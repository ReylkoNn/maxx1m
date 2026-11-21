"""
Comprehensive desktop security regression tests for Package I:
1. Live TLS 1.3 SPKI Pinning over HTTPS (`requests`) and WSS (`websockets`):
   proves that a rogue/compelled CA certificate (even when trusted by the CA bundle!)
   is rejected DURING the TLS handshake BEFORE a single byte of HTTP headers,
   passwords, or WebSocket Bearer tokens is transmitted!
2. Pure-stdlib ASN.1 DER SubjectPublicKeyInfo parser equivalence with `cryptography.x509`
   across RSA-2048, ECDSA P-256, and Ed25519 X.509 certificates.
3. Anti-downgrade authenticated `tls_pins.enc` storage defeating `local_state.json` tampering.
4. Cryptographic Traffic Padding (`\x00MXP1`) hiding message lengths in fixed buckets
   across both 1-on-1 (`CryptoManager`) and Group v2 (`GroupCrypto`) messages, with
   fail-closed tail verification and backward compatibility with unpadded legacy messages.
5. E2EE Encrypted Group Names (`SERVER_GROUP_NAME_PLACEHOLDER == "[E2EE]"` on server,
   real UTF-8 title sealed inside padded SenderKey bundles) + client `history_store`
   `PRAGMA secure_delete=ON` forensic zeroing on disk.
"""

import asyncio
import base64
from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import socket
import ssl
import threading
import uuid

import nacl.exceptions
from nacl.encoding import Base64Encoder
from nacl.public import Box
import nacl.utils
import pytest
import requests
import websockets

from app import secure_storage
from app.crypto_box import CryptoManager, PADDING_MAGIC, pad_traffic_bytes, unpad_traffic_bytes
from app.group_crypto import SERVER_GROUP_NAME_PLACEHOLDER, group_crypto
from app.history_store import EncryptedHistory
from app.secure_storage import SecureStorage
from app.state import state
from app.tls_pinning import (
    _extract_spki_der_asn1,
    build_pinned_ssl_context,
    compute_spki_pin,
    install_urllib3_spki_enforcement,
    normalize_spki_pin,
    resolve_spki_pins_for_host,
)


def _generate_ca_and_leaf_certs(tmp_path: Path):
    """Generate a trusted Root CA + (1) Legitimate Server cert + (2) Rogue MITM cert signed by SAME Root CA."""
    cryptography = pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = tmp_path / "ca.pem"
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    def _issue_leaf(priv_key, label: str):
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        san = x509.SubjectAlternativeName(
            [
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(ca_name)
            .public_key(priv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(san, critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        cert_path = tmp_path / f"{label}.pem"
        key_path = tmp_path / f"{label}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            priv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        spki_crypto = priv_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cert_path, key_path, der, spki_crypto

    legit = _issue_leaf(ec.generate_private_key(ec.SECP256R1()), "legit")
    rogue = _issue_leaf(rsa.generate_private_key(public_exponent=65537, key_size=2048), "rogue")
    ed_leaf = _issue_leaf(ed25519.Ed25519PrivateKey.generate(), "ed25519_leaf")
    return ca_pem, legit, rogue, ed_leaf


def _start_recording_tls_server(cert_path: Path, key_path: Path, response_bytes: bytes):
    """Run a single-connection TLS server that records any decrypted application bytes sent by the client."""
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]

    captured = bytearray()
    done = threading.Event()

    def _serve():
        try:
            listener.settimeout(5.0)
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(2.0)
                try:
                    with srv_ctx.wrap_socket(conn, server_side=True) as tls_conn:
                        tls_conn.settimeout(0.5)
                        try:
                            while True:
                                chunk = tls_conn.recv(16384)
                                if not chunk:
                                    break
                                captured.extend(chunk)
                                hdr_end = captured.find(b"\r\n\r\n")
                                if hdr_end != -1:
                                    # Wait for Content-Length body if present
                                    hdr_text = bytes(captured[:hdr_end]).decode("iso-8859-1", errors="ignore")
                                    expected_body = 0
                                    for line in hdr_text.split("\r\n"):
                                        if line.lower().startswith("content-length:"):
                                            expected_body = int(line.split(":", 1)[1].strip())
                                    if len(captured) >= hdr_end + 4 + expected_body:
                                        tls_conn.sendall(response_bytes)
                                        break
                        except (socket.timeout, ssl.SSLError, ConnectionError, OSError):
                            pass
                except (ssl.SSLError, ConnectionError, OSError):
                    pass
        finally:
            try:
                listener.close()
            except OSError:
                pass
            done.set()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return port, captured, done


def test_asn1_spki_extractor_matches_cryptography_across_ecdsa_rsa_and_ed25519(tmp_path: Path):
    _, legit_ec, rogue_rsa, ed_leaf = _generate_ca_and_leaf_certs(tmp_path)
    for _cert_p, _key_p, cert_der, expected_spki_der in (legit_ec, rogue_rsa, ed_leaf):
        assert _extract_spki_der_asn1(cert_der) == expected_spki_der
        pin = compute_spki_pin(cert_der)
        assert pin.startswith("sha256/")
        assert normalize_spki_pin(pin) == pin
        # Hex representation normalizes to the exact same sha256/<b64> pin!
        raw_digest = base64.b64decode(pin[7:])
        assert normalize_spki_pin(raw_digest.hex()) == pin


def test_live_tls_spki_pinning_blocks_rogue_ca_before_sending_http_or_ws_credentials(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    monkeypatch.setattr(secure_storage, "CONFIG_FILE", tmp_path / "local_state.json")
    monkeypatch.setattr(state, "username", None)

    ca_pem, legit, rogue, _ = _generate_ca_and_leaf_certs(tmp_path)
    legit_cert, legit_key, legit_der, _ = legit
    rogue_cert, rogue_key, _, _ = rogue
    legit_pin = compute_spki_pin(legit_der)

    monkeypatch.setenv("MAX1M_TLS_SPKI_PINS", f"localhost={legit_pin}")
    install_urllib3_spki_enforcement()

    # 1. ROGUE CA MITM ON HTTPS (`requests.post`):
    #    Even though `verify=str(ca_pem)` trusts the CA that signed `rogue_cert`,
    #    SPKI pinning MUST abort BEFORE `SUPER_SECRET_PASSWORD` or `SECRET_BEARER_JWT` is sent!
    http_ok_reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
    port_rogue, captured_rogue_http, done_rogue = _start_recording_tls_server(
        rogue_cert, rogue_key, http_ok_reply
    )
    with pytest.raises(requests.exceptions.SSLError):
        requests.post(
            f"https://localhost:{port_rogue}/auth/login",
            headers={"Authorization": "Bearer SECRET_BEARER_JWT"},
            json={"password": "SUPER_SECRET_PASSWORD"},
            verify=str(ca_pem),
            timeout=3.0,
        )
    done_rogue.wait(timeout=3.0)
    assert bytes(captured_rogue_http) == b""

    # 2. LEGITIMATE SERVER ON HTTPS (`requests.post`): succeeds cleanly!
    port_legit, captured_legit_http, done_legit = _start_recording_tls_server(
        legit_cert, legit_key, http_ok_reply
    )
    resp = requests.post(
        f"https://localhost:{port_legit}/auth/login",
        json={"ping": "ok"},
        verify=str(ca_pem),
        timeout=3.0,
    )
    done_legit.wait(timeout=3.0)
    assert resp.status_code == 200
    assert b"POST /auth/login" in bytes(captured_legit_http)

    # 3. ROGUE CA MITM ON WSS (`websockets.connect` with `build_pinned_ssl_context`):
    #    WebSocket Upgrade + `Authorization: Bearer SECRET_WS_TOKEN` MUST NEVER hit the wire!
    port_ws_rogue, captured_rogue_ws, done_ws_rogue = _start_recording_tls_server(
        rogue_cert, rogue_key, b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
    )
    base_ws_ctx = ssl.create_default_context(cafile=str(ca_pem))
    pinned_ws_ctx = build_pinned_ssl_context(
        f"wss://localhost:{port_ws_rogue}/messages/ws/dev1", base_context=base_ws_ctx
    )
    assert pinned_ws_ctx is not None

    async def _attempt_rogue_ws():
        import inspect

        header_kw = (
            "additional_headers"
            if "additional_headers" in inspect.signature(websockets.connect).parameters
            else "extra_headers"
        )
        async with websockets.connect(
            f"wss://localhost:{port_ws_rogue}/messages/ws/dev1",
            ssl=pinned_ws_ctx,
            open_timeout=3.0,
            **{header_kw: {"Authorization": "Bearer SECRET_WS_TOKEN"}},
        ):
            pass

    with pytest.raises(ssl.SSLCertVerificationError):
        asyncio.run(_attempt_rogue_ws())
    done_ws_rogue.wait(timeout=3.0)
    assert bytes(captured_rogue_ws) == b""


def test_anti_downgrade_tls_pins_enc_defeats_local_state_tampering(tmp_path: Path, monkeypatch):
    keyring_mem: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    monkeypatch.setattr(secure_storage, "CONFIG_FILE", tmp_path / "local_state.json")
    monkeypatch.setattr(
        secure_storage.keyring, "get_password", lambda s, k: keyring_mem.get((s, k))
    )
    monkeypatch.setattr(
        secure_storage.keyring, "set_password", lambda s, k, v: keyring_mem.__setitem__((s, k), v)
    )
    monkeypatch.delenv("MAX1M_TLS_SPKI_PINS", raising=False)
    monkeypatch.setattr(state, "username", "alice_sec")

    real_pin = "sha256/" + base64.b64encode(b"\x11" * 32).decode("ascii")
    attacker_pin = "sha256/" + base64.b64encode(b"\x99" * 32).decode("ascii")

    SecureStorage.save_tls_pins("alice_sec", {"node.example.org": [real_pin]})

    # Simulate local unencrypted file tampering: attacker overwrites local_state.json with their own pin or {}
    SecureStorage.save_local_state({"tls_spki_pins": {"node.example.org": [attacker_pin]}})

    # Authenticated tls_pins.enc MUST win and reject attacker_pin!
    resolved = resolve_spki_pins_for_host("node.example.org")
    assert resolved == {real_pin}

    # Corrupting tls_pins.enc MUST fail closed with SSLCertVerificationError!
    pins_path = SecureStorage._get_tls_pins_file("alice_sec")
    corrupted = bytearray(pins_path.read_bytes())
    corrupted[-1] ^= 0xFF
    pins_path.write_bytes(bytes(corrupted))
    with pytest.raises(ssl.SSLCertVerificationError):
        resolve_spki_pins_for_host("node.example.org")


def test_traffic_padding_hides_lengths_and_preserves_legacy_compatibility():
    alice = CryptoManager()
    alice.generate_new_keypair()
    bob = CryptoManager()
    bob.generate_new_keypair()

    alice_pub = alice.get_public_key_b64()
    bob_pub = bob.get_public_key_b64()

    # 1. Personal E2EE messages of wildly different short lengths produce IDENTICAL ciphertext size!
    samples = [
        "да",
        '{"type":"typing"}',
        '{"type":"text","text":"Встречаемся в 19:30 у северного выхода без телефонов","msg_id":"1234"}',
    ]
    blobs = [alice.encrypt_message(s, bob_pub)["encrypted_blob"] for s in samples]
    raw_sizes = {len(base64.b64decode(b)) for b in blobs}
    assert raw_sizes == {512 + 40}  # 512-byte bucket + 24-byte nonce + 16-byte Poly1305 MAC!
    for s, b in zip(samples, blobs):
        assert bob.decrypt_message(b, alice_pub) == s

    # 2. Tampered non-zero byte in padding tail fails closed!
    bad_padded = bytearray(pad_traffic_bytes(b"hello"))
    assert bad_padded[:5] == PADDING_MAGIC
    bad_padded[-1] = 0x01
    with pytest.raises(ValueError):
        unpad_traffic_bytes(bytes(bad_padded))

    # 3. Legacy unpadded Curve25519 Box ciphertext still decrypts seamlessly!
    raw_box = Box(
        alice.private_key.to_curve25519_private_key(),
        bob.public_key.to_curve25519_public_key(),
    )
    legacy_ct_b64 = Base64Encoder.encode(raw_box.encrypt(b'{"type":"text","text":"legacy"}')).decode("ascii")
    assert bob.decrypt_message(legacy_ct_b64, alice_pub) == '{"type":"text","text":"legacy"}'

    # 4. Group v2 messages ALSO pad to identical fixed buckets!
    g_sk_send = group_crypto.generate_sender_key(group_id="grp-pad", epoch=1)
    enc_sk, sig_sk = group_crypto.encrypt_sender_key_for_member(
        g_sk_send,
        bob_pub,
        group_id="grp-pad",
        sender_device_id="dev-a",
        recipient_device_id="dev-b",
        group_name="Редакция Свободы Слова",
        crypto_mgr=alice,
    )
    assert SERVER_GROUP_NAME_PLACEHOLDER == "[E2EE]"
    g_sk_recv = group_crypto.decrypt_sender_key(
        enc_sk,
        sig_sk,
        alice_pub,
        expected_group_id="grp-pad",
        expected_sender_device_id="dev-a",
        expected_recipient_device_id="dev-b",
        crypto_mgr=bob,
    )
    assert g_sk_recv is not None
    assert g_sk_recv["group_name"] == "Редакция Свободы Слова"

    gpkt_short = group_crypto.encrypt_group_message(
        "ок", g_sk_send, group_id="grp-pad", sender_device_id="dev-a", crypto_mgr=alice
    )
    gpkt_med = group_crypto.encrypt_group_message(
        "Длинное сообщение в защищённой группе на несколько предложений без утечки длины!",
        g_sk_send,
        group_id="grp-pad",
        sender_device_id="dev-a",
        crypto_mgr=alice,
    )
    assert len(base64.b64decode(gpkt_short["blob"])) == len(base64.b64decode(gpkt_med["blob"])) == 512 + 40
    assert (
        group_crypto.decrypt_group_message(
            gpkt_short, g_sk_recv, expected_group_id="grp-pad", expected_sender_device_id="dev-a", sender_public_key_b64=alice_pub
        )
        == "ок"
    )
    assert (
        group_crypto.decrypt_group_message(
            gpkt_med, g_sk_recv, expected_group_id="grp-pad", expected_sender_device_id="dev-a", sender_public_key_b64=alice_pub
        )
        == "Длинное сообщение в защищённой группе на несколько предложений без утечки длины!"
    )


def test_client_encrypted_history_sqlite_enables_secure_delete(tmp_path: Path):
    db_file = tmp_path / "chat.sqlite3"
    key = nacl.utils.random(32)
    hist = EncryptedHistory.create(db_file, key, "alice", "bob")
    with hist._connection(write=False) as conn:
        assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
        assert conn.execute("PRAGMA temp_store").fetchone()[0] == 2
