"""
Production Asynchronous X3DH + Signal Double Ratchet Engine & Transactional Store.

Cryptographic primitives (pure libsodium via PyNaCl + RFC 5869 HKDF-SHA256):
- Identity keys: Ed25519 (`SigningKey` / `VerifyKey`) mapped birationally to X25519
  for X3DH Diffie-Hellman agreement, and used directly for Ed25519 prekey & envelope signatures.
- X3DH: 4-DH (with One-Time PreKey) or 3-DH (Signed PreKey fallback) over X25519 with
  domain-separated 0xFF*32 prefix and HKDF-SHA256 (`info=b"Max1m-X3DH-v1"`).
- Double Ratchet:
  - Root chain KDF: HKDF-SHA256 (`info=b"Max1m-DR-Root-v1"`)
  - Message chain KDF: HMAC-SHA256 (`0x01` -> message key, `0x02` -> next chain key)
  - AEAD: XChaCha20-Poly1305-IETF (`crypto_aead_xchacha20poly1305_ietf`) with canonical
    Associated Data binding sender/receiver Ed25519 identities, device IDs, and DR header,
    plus cryptographic Traffic Padding (`pad_traffic_bytes`) inside AEAD!
- Persistence:
  - Encrypted SQLite database (`ratchet_v1.sqlite3`) per profile with `PRAGMA secure_delete=ON`,
    `PRAGMA temp_store=MEMORY`, `PRAGMA synchronous=FULL`, encrypted under `_get_or_create_local_key`
    (protected by `local_vault` Argon2id when enabled).
"""

from contextlib import contextmanager
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid
from typing import Dict, List, Optional, Tuple

import nacl.bindings
import nacl.exceptions
from nacl.public import PrivateKey as X25519PrivateKey
import nacl.secret
from nacl.signing import SigningKey, VerifyKey
import nacl.utils

from app.crypto_box import pad_traffic_bytes, unpad_traffic_bytes

DR_WIRE_MAGIC = b"M1DR01"  # 6 bytes -> exact 8-char Base64 prefix "TTFEUjAx" (valid canonical Base64!)
DR_WIRE_PREFIX = "TTFEUjAx"
X3DH_CURVE25519_PREFIX = b"curve_25519:"
X3DH_INFO = b"Max1m-X3DH-v1"
DR_ROOT_INFO = b"Max1m-DR-Root-v1"
DR_AEAD_NONCE_DERIVE_INFO = b"Max1m-DR-AEAD-KeyNonce-v1"

MAX_SKIP = 256
MAX_SKIPPED_CACHE = 512
SKIPPED_KEY_TTL_SECONDS = 14 * 86400
DEFAULT_OPK_BATCH = 50
OPK_REPLENISH_THRESHOLD = 20
MAX_RETAINED_SIGNED_PREKEYS = 3


class RatchetError(ValueError):
    """Raised when X3DH or Double Ratchet verification/decryption fails closed."""


class ReplayAlreadyProcessed(Exception):
    """Indicates an exact, already-authenticated server delivery retry (safe to ACK)."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(val: str, expected_len: Optional[int] = None) -> bytes:
    if not isinstance(val, str):
        raise RatchetError("Expected base64 string")
    try:
        raw = base64.b64decode(val.encode("ascii"), validate=True)
    except Exception as exc:
        raise RatchetError("Invalid base64 encoding") from exc
    if _b64e(raw) != val:
        raise RatchetError("Non-canonical base64 encoding")
    if expected_len is not None and len(raw) != expected_len:
        raise RatchetError("Unexpected decoded byte length")
    return raw


def _zeroize(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(prev)
        counter += 1
    return bytes(okm[:length])


def _x25519_dh(priv_32: bytes, pub_32: bytes) -> bytearray:
    if len(priv_32) != 32 or len(pub_32) != 32:
        raise RatchetError("Invalid X25519 key length")
    try:
        shared = nacl.bindings.crypto_scalarmult(priv_32, pub_32)
    except Exception as exc:
        raise RatchetError("Rejected invalid/low-order X25519 point") from exc
    if shared == b"\x00" * 32:
        raise RatchetError("All-zero X25519 shared secret")
    return bytearray(shared)


def sign_prekey(signing_key: SigningKey, spk_pub_32: bytes) -> str:
    if len(spk_pub_32) != 32:
        raise ValueError("Invalid signed prekey length")
    sig = signing_key.sign(X3DH_CURVE25519_PREFIX + spk_pub_32).signature
    return _b64e(sig)


def verify_signed_prekey(identity_ed25519_b64: str, spk_pub_b64: str, signature_b64: str) -> bool:
    try:
        id_raw = _b64d(identity_ed25519_b64, 32)
        spk_raw = _b64d(spk_pub_b64, 32)
        sig_raw = _b64d(signature_b64, 64)
        vk = VerifyKey(id_raw)
    except Exception:
        return False
    for msg in (X3DH_CURVE25519_PREFIX + spk_raw, spk_raw):
        try:
            vk.verify(msg, sig_raw)
            return True
        except nacl.exceptions.BadSignatureError:
            continue
    return False


def attachment_commitment(file_id: str, secret_key: str, msg_id: str) -> str:
    payload = f"Max1m-DR-Attach-v1:{file_id}:{secret_key}:{msg_id}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ============================================================================
# X3DH KEY AGREEMENT (Signal X3DH Specification)
# ============================================================================

def x3dh_initiate(
    our_ed25519_signing_key: SigningKey,
    peer_verified_ed25519_b64: str,
    claimed_bundle: dict,
) -> Tuple[bytes, dict]:
    """
    Initiator (Alice) side of X3DH.
    Verifies `claimed_bundle["identity_key"] == peer_verified_ed25519_b64` AND
    verifies the Ed25519 signature on `signed_prekey` BEFORE any DH computation.
    Returns `(shared_secret_32, x3dh_header_dict)`.
    """
    if not isinstance(claimed_bundle, dict):
        raise RatchetError("Invalid prekey bundle")
    bundle_ik = claimed_bundle.get("identity_key")
    spk_b64 = claimed_bundle.get("signed_prekey")
    sig_b64 = claimed_bundle.get("signature")
    spk_version = claimed_bundle.get("version")
    if (
        bundle_ik != peer_verified_ed25519_b64
        or isinstance(spk_version, bool)
        or not isinstance(spk_version, int)
        or spk_version < 1
    ):
        raise RatchetError("Bundle identity key or version mismatch")
    if not verify_signed_prekey(peer_verified_ed25519_b64, spk_b64, sig_b64):
        raise RatchetError("Signed prekey failed Ed25519 signature verification")

    peer_ik_ed = VerifyKey(_b64d(peer_verified_ed25519_b64, 32))
    peer_ik_x = bytes(peer_ik_ed.to_curve25519_public_key())
    peer_spk_x = _b64d(spk_b64, 32)

    our_ik_x_priv = bytearray(bytes(our_ed25519_signing_key.to_curve25519_private_key()))
    ek_obj = X25519PrivateKey.generate()
    ek_priv = bytearray(bytes(ek_obj))
    ek_pub = bytes(ek_obj.public_key)

    opk_entry = claimed_bundle.get("one_time_key")
    opk_id: Optional[str] = None
    opk_pub: Optional[bytes] = None
    if opk_entry is not None:
        if not isinstance(opk_entry, dict) or not isinstance(opk_entry.get("key_id"), str):
            raise RatchetError("Malformed one_time_key in bundle")
        opk_id = opk_entry["key_id"]
        opk_pub = _b64d(opk_entry["public_key"], 32)

    dh1 = dh2 = dh3 = dh4 = bytearray()
    ikm = bytearray()
    try:
        dh1 = _x25519_dh(bytes(our_ik_x_priv), peer_spk_x)
        dh2 = _x25519_dh(bytes(ek_priv), peer_ik_x)
        dh3 = _x25519_dh(bytes(ek_priv), peer_spk_x)
        ikm.extend(b"\xff" * 32)
        ikm.extend(dh1)
        ikm.extend(dh2)
        ikm.extend(dh3)
        if opk_pub is not None:
            dh4 = _x25519_dh(bytes(ek_priv), opk_pub)
            ikm.extend(dh4)
        shared_secret = hkdf_sha256(bytes(ikm), b"\x00" * 32, X3DH_INFO, 32)
    finally:
        for b in (our_ik_x_priv, ek_priv, dh1, dh2, dh3, dh4, ikm):
            _zeroize(b)

    session_id = hashlib.sha256(
        b"Max1m-X3DH-SID:" + ek_pub + peer_spk_x + (opk_id.encode("utf-8") if opk_id else b"")
    ).hexdigest()[:32]

    x3dh_header = {
        "session_id": session_id,
        "ek_pub": _b64e(ek_pub),
        "spk_version": spk_version,
        "spk_pub": spk_b64,
        "opk_id": opk_id,
    }
    return shared_secret, x3dh_header


def x3dh_respond(
    our_ed25519_signing_key: SigningKey,
    our_spk_priv_32: bytes,
    our_opk_priv_32: Optional[bytes],
    peer_verified_ed25519_b64: str,
    x3dh_header: dict,
) -> bytes:
    """Responder (Bob) side of X3DH."""
    peer_ik_ed = VerifyKey(_b64d(peer_verified_ed25519_b64, 32))
    peer_ik_x = bytes(peer_ik_ed.to_curve25519_public_key())
    ek_pub = _b64d(x3dh_header.get("ek_pub", ""), 32)

    our_ik_x_priv = bytearray(bytes(our_ed25519_signing_key.to_curve25519_private_key()))
    dh1 = dh2 = dh3 = dh4 = bytearray()
    ikm = bytearray()
    try:
        dh1 = _x25519_dh(our_spk_priv_32, peer_ik_x)
        dh2 = _x25519_dh(bytes(our_ik_x_priv), ek_pub)
        dh3 = _x25519_dh(our_spk_priv_32, ek_pub)
        ikm.extend(b"\xff" * 32)
        ikm.extend(dh1)
        ikm.extend(dh2)
        ikm.extend(dh3)
        if our_opk_priv_32 is not None:
            dh4 = _x25519_dh(our_opk_priv_32, ek_pub)
            ikm.extend(dh4)
        return hkdf_sha256(bytes(ikm), b"\x00" * 32, X3DH_INFO, 32)
    finally:
        for b in (our_ik_x_priv, dh1, dh2, dh3, dh4, ikm):
            _zeroize(b)


# ============================================================================
# SIGNAL DOUBLE RATCHET SESSION
# ============================================================================

def _kdf_rk(rk_32: bytes, dh_out_32: bytes) -> Tuple[bytes, bytes]:
    derived = hkdf_sha256(dh_out_32, rk_32, DR_ROOT_INFO, 64)
    return derived[:32], derived[32:64]


def _kdf_ck(ck_32: bytes) -> Tuple[bytes, bytes]:
    next_ck = hmac.new(ck_32, b"\x02", hashlib.sha256).digest()
    msg_key = hmac.new(ck_32, b"\x01", hashlib.sha256).digest()
    return next_ck, msg_key


def _derive_aead_key_and_nonce(msg_key_32: bytes) -> Tuple[bytes, bytes]:
    km = hkdf_sha256(msg_key_32, b"\x00" * 32, DR_AEAD_NONCE_DERIVE_INFO, 56)
    return km[:32], km[32:56]


def _build_aad(
    *,
    sender_ik: str,
    receiver_ik: str,
    sender_device_id: str,
    receiver_device_id: str,
    dr_header: dict,
) -> bytes:
    canon_hdr = {
        "dh": dr_header["dh"],
        "pn": int(dr_header["pn"]),
        "n": int(dr_header["n"]),
    }
    if dr_header.get("x3dh") is not None:
        canon_hdr["x3dh"] = dr_header["x3dh"]
    return json.dumps(
        {
            "v": 1,
            "sender_ik": sender_ik,
            "receiver_ik": receiver_ik,
            "sender_dev": sender_device_id,
            "receiver_dev": receiver_device_id,
            "hdr": canon_hdr,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class DoubleRatchetSession:
    """In-memory Signal Double Ratchet state (always cloned before mutation for transactional safety)."""

    def __init__(self, state_dict: dict):
        self.state = json.loads(json.dumps(state_dict))

    @classmethod
    def init_initiator(cls, shared_secret: bytes, bob_spk_pub_b64: str, x3dh_header: dict) -> "DoubleRatchetSession":
        bob_spk_raw = _b64d(bob_spk_pub_b64, 32)
        dh_obj = X25519PrivateKey.generate()
        dh_priv = bytes(dh_obj)
        dh_pub = bytes(dh_obj.public_key)
        dh_out = _x25519_dh(dh_priv, bob_spk_raw)
        try:
            rk, ck_s = _kdf_rk(shared_secret, bytes(dh_out))
        finally:
            _zeroize(dh_out)
        return cls(
            {
                "v": 1,
                "session_id": x3dh_header["session_id"],
                "dh_priv": _b64e(dh_priv),
                "dh_pub": _b64e(dh_pub),
                "dh_remote": bob_spk_pub_b64,
                "rk": _b64e(rk),
                "ck_s": _b64e(ck_s),
                "ck_r": None,
                "ns": 0,
                "nr": 0,
                "pn": 0,
                "skipped_mk": {},
                "pending_x3dh": x3dh_header,
            }
        )

    @classmethod
    def init_responder(
        cls,
        shared_secret: bytes,
        our_spk_priv_32: bytes,
        our_spk_pub_b64: str,
        session_id: str,
    ) -> "DoubleRatchetSession":
        return cls(
            {
                "v": 1,
                "session_id": session_id,
                "dh_priv": _b64e(our_spk_priv_32),
                "dh_pub": our_spk_pub_b64,
                "dh_remote": None,
                "rk": _b64e(shared_secret),
                "ck_s": None,
                "ck_r": None,
                "ns": 0,
                "nr": 0,
                "pn": 0,
                "skipped_mk": {},
                "pending_x3dh": None,
            }
        )

    def to_dict(self) -> dict:
        return json.loads(json.dumps(self.state))

    def encrypt(
        self,
        plaintext: str,
        *,
        sender_ik: str,
        receiver_ik: str,
        sender_device_id: str,
        receiver_device_id: str,
        msg_kind: str = "text",
        attachment_commit: Optional[str] = None,
    ) -> str:
        if not isinstance(plaintext, str):
            raise RatchetError("Plaintext must be str")
        st = self.to_dict()
        if st["ck_s"] is None:
            # Should only happen if responder sends before receiving (never occurs in normal init)
            raise RatchetError("Sending chain not initialized")

        ck_s = _b64d(st["ck_s"], 32)
        next_ck_s, mk = _kdf_ck(ck_s)
        msg_num = int(st["ns"])
        st["ck_s"] = _b64e(next_ck_s)
        st["ns"] = msg_num + 1

        dr_header: dict = {
            "dh": st["dh_pub"],
            "pn": int(st["pn"]),
            "n": msg_num,
        }
        if st.get("pending_x3dh") is not None:
            dr_header["x3dh"] = st["pending_x3dh"]

        aad = _build_aad(
            sender_ik=sender_ik,
            receiver_ik=receiver_ik,
            sender_device_id=sender_device_id,
            receiver_device_id=receiver_device_id,
            dr_header=dr_header,
        )
        aead_key, aead_nonce = _derive_aead_key_and_nonce(mk)
        mk_buf = bytearray(mk)
        _zeroize(mk_buf)

        padded = pad_traffic_bytes(plaintext.encode("utf-8"))
        ct_bytes = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            padded, aad, aead_nonce, aead_key
        )

        outer = {
            "dr_v": 1,
            "session_id": st["session_id"],
            "recipient_ik": receiver_ik,
            "recipient_device_id": receiver_device_id,
            "msg_kind": msg_kind,
            "header": dr_header,
            "ciphertext": _b64e(ct_bytes),
        }
        if attachment_commit:
            outer["attachment_commit"] = attachment_commit

        # Commit state mutation
        self.state = st
        raw_outer = json.dumps(outer, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return _b64e(DR_WIRE_MAGIC + raw_outer)

    def _prune_skipped(self, skipped: dict) -> None:
        now = int(time.time())
        expired = [k for k, v in skipped.items() if now - int(v.get("ts", now)) > SKIPPED_KEY_TTL_SECONDS]
        for k in expired:
            skipped.pop(k, None)
        while len(skipped) > MAX_SKIPPED_CACHE:
            oldest_k = min(skipped.keys(), key=lambda k: int(skipped[k].get("ts", 0)))
            skipped.pop(oldest_k, None)

    def _skip_message_keys(self, st: dict, until_n: int) -> None:
        if st["ck_r"] is None:
            return
        cur_nr = int(st["nr"])
        if until_n - cur_nr > MAX_SKIP:
            raise RatchetError("Exceeded MAX_SKIP out-of-order message window")
        ck_r = _b64d(st["ck_r"], 32)
        dh_rem = st["dh_remote"]
        skipped = st["skipped_mk"]
        now = int(time.time())
        while cur_nr < until_n:
            ck_r, mk = _kdf_ck(ck_r)
            skipped[f"{dh_rem}:{cur_nr}"] = {"mk": _b64e(mk), "ts": now}
            cur_nr += 1
        st["ck_r"] = _b64e(ck_r)
        st["nr"] = cur_nr
        self._prune_skipped(skipped)

    def _dh_ratchet(self, st: dict, header_dh_b64: str) -> None:
        peer_dh_raw = _b64d(header_dh_b64, 32)
        st["pn"] = int(st["ns"])
        st["ns"] = 0
        st["nr"] = 0
        st["dh_remote"] = header_dh_b64

        rk = _b64d(st["rk"], 32)
        our_priv = _b64d(st["dh_priv"], 32)
        dh_recv = _x25519_dh(our_priv, peer_dh_raw)
        try:
            rk, ck_r = _kdf_rk(rk, bytes(dh_recv))
        finally:
            _zeroize(dh_recv)

        new_dh = X25519PrivateKey.generate()
        new_priv = bytes(new_dh)
        new_pub = bytes(new_dh.public_key)
        dh_send = _x25519_dh(new_priv, peer_dh_raw)
        try:
            rk, ck_s = _kdf_rk(rk, bytes(dh_send))
        finally:
            _zeroize(dh_send)

        st["dh_priv"] = _b64e(new_priv)
        st["dh_pub"] = _b64e(new_pub)
        st["rk"] = _b64e(rk)
        st["ck_r"] = _b64e(ck_r)
        st["ck_s"] = _b64e(ck_s)

    def decrypt(
        self,
        outer: dict,
        *,
        sender_ik: str,
        receiver_ik: str,
        sender_device_id: str,
        receiver_device_id: str,
    ) -> str:
        """Stage ratchet advancement on a deep copy; commit ONLY if Poly1305 MAC succeeds."""
        st = self.to_dict()
        dr_header = outer.get("header")
        if not isinstance(dr_header, dict):
            raise RatchetError("Missing DR header")
        header_dh = dr_header.get("dh")
        pn = dr_header.get("pn")
        n = dr_header.get("n")
        if (
            not isinstance(header_dh, str)
            or isinstance(pn, bool)
            or not isinstance(pn, int)
            or isinstance(n, bool)
            or not isinstance(n, int)
            or pn < 0
            or n < 0
            or pn > 10_000_000
            or n > 10_000_000
        ):
            raise RatchetError("Malformed DR header counters")
        _b64d(header_dh, 32)
        ct_bytes = _b64d(outer.get("ciphertext", ""))

        aad = _build_aad(
            sender_ik=sender_ik,
            receiver_ik=receiver_ik,
            sender_device_id=sender_device_id,
            receiver_device_id=receiver_device_id,
            dr_header=dr_header,
        )

        skip_key_id = f"{header_dh}:{n}"
        skipped_entry = st["skipped_mk"].pop(skip_key_id, None)
        if skipped_entry is not None:
            mk = _b64d(skipped_entry["mk"], 32)
        else:
            if header_dh != st["dh_remote"]:
                self._skip_message_keys(st, pn)
                self._dh_ratchet(st, header_dh)
            if n < int(st["nr"]):
                raise RatchetError("Duplicate or replayed message number")
            self._skip_message_keys(st, n)
            ck_r = _b64d(st["ck_r"], 32)
            next_ck_r, mk = _kdf_ck(ck_r)
            st["ck_r"] = _b64e(next_ck_r)
            st["nr"] = n + 1

        aead_key, aead_nonce = _derive_aead_key_and_nonce(mk)
        mk_buf = bytearray(mk)
        _zeroize(mk_buf)

        try:
            padded_pt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                ct_bytes, aad, aead_nonce, aead_key
            )
            pt_bytes = unpad_traffic_bytes(padded_pt)
            plaintext = pt_bytes.decode("utf-8")
        except Exception as exc:
            raise RatchetError("Double Ratchet AEAD authentication failed") from exc

        # Peer has replied or we have received -> clear pending_x3dh if peer rotated DH
        if st.get("pending_x3dh") is not None:
            st["pending_x3dh"] = None

        self.state = st
        return plaintext


def sign_dr_blob(signing_key: SigningKey, wire_blob_b64: str) -> str:
    raw = _b64d(wire_blob_b64)
    sig = signing_key.sign(raw).signature
    return _b64e(sig)


def is_double_ratchet_blob(blob: object) -> bool:
    return isinstance(blob, str) and blob.startswith(DR_WIRE_PREFIX)


def parse_double_ratchet_outer(blob: str) -> dict:
    if not is_double_ratchet_blob(blob) or len(blob) > 1024 * 1024:
        raise RatchetError("Not a Double Ratchet envelope")
    raw_all = _b64d(blob)
    if not raw_all.startswith(DR_WIRE_MAGIC):
        raise RatchetError("Invalid Double Ratchet wire magic")
    raw = raw_all[len(DR_WIRE_MAGIC) :]
    try:
        outer = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RatchetError("Invalid Double Ratchet outer JSON") from exc
    if (
        not isinstance(outer, dict)
        or outer.get("dr_v") != 1
        or not isinstance(outer.get("session_id"), str)
        or not isinstance(outer.get("recipient_ik"), str)
        or not isinstance(outer.get("recipient_device_id"), str)
        or not isinstance(outer.get("msg_kind"), str)
        or not isinstance(outer.get("header"), dict)
        or not isinstance(outer.get("ciphertext"), str)
    ):
        raise RatchetError("Malformed Double Ratchet outer fields")
    return outer


# ============================================================================
# TRANSACTIONAL ENCRYPTED RATCHET STORE (SQLite + SecretBox + secure_delete=ON)
# ============================================================================

class RatchetStore:
    """
    Per-profile transactional encrypted SQLite store for:
    - Local X3DH Signed PreKeys (current + up to 2 rotated versions)
    - Local X3DH One-Time PreKeys (deleted immediately upon first authenticated X3DH receive)
    - Active & responder Double Ratchet sessions per `(peer_device_id, peer_ik)`
    - Crash-safe `seen_incoming` `(delivery_id -> sha256(wire_blob))` idempotency table
    """

    def __init__(self, username: str):
        from app.secure_storage import SecureStorage, _restrict_file_permissions

        self.username = username
        user_dir = SecureStorage._get_user_dir(username)
        self.db_path: Path = user_dir / "ratchet_v1.sqlite3"
        self._key = SecureStorage._get_or_create_local_key(username)
        self._box = nacl.secret.SecretBox(self._key)
        created = not self.db_path.exists()
        with self._tx() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS prekey_state ("
                "id INTEGER PRIMARY KEY CHECK(id=1), blob BLOB NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS peer_sessions ("
                "peer_key TEXT PRIMARY KEY, blob BLOB NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS seen_incoming ("
                "delivery_id TEXT PRIMARY KEY, blob BLOB NOT NULL)"
            )
        if created:
            _restrict_file_permissions(self.db_path)

    @contextmanager
    def _tx(self):
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        try:
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def _enc(self, scope_tag: str, obj: dict) -> bytes:
        raw = json.dumps(
            {"owner": self.username, "tag": scope_tag, "data": obj},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return bytes(self._box.encrypt(pad_traffic_bytes(raw)))

    def _dec(self, scope_tag: str, blob: bytes) -> dict:
        pt = unpad_traffic_bytes(self._box.decrypt(bytes(blob)))
        env = json.loads(pt.decode("utf-8"))
        if not isinstance(env, dict) or env.get("owner") != self.username or env.get("tag") != scope_tag:
            raise RatchetError("Encrypted ratchet store scope mismatch")
        data = env.get("data")
        if not isinstance(data, dict):
            raise RatchetError("Corrupt ratchet store record")
        return data

    def _load_prekey_state_tx(self, conn) -> dict:
        row = conn.execute("SELECT blob FROM prekey_state WHERE id=1").fetchone()
        if not row:
            return {"current_version": 0, "signed_prekeys": {}, "one_time_prekeys": {}}
        return self._dec("prekey_state", row[0])

    def _save_prekey_state_tx(self, conn, st: dict) -> None:
        blob = self._enc("prekey_state", st)
        conn.execute(
            "INSERT INTO prekey_state (id, blob) VALUES (1, ?) "
            "ON CONFLICT(id) DO UPDATE SET blob=excluded.blob",
            (blob,),
        )

    def prepare_publish_bundle(
        self,
        signing_key: SigningKey,
        *,
        needed_opks: int = DEFAULT_OPK_BATCH,
        rotate_signed_prekey: bool = False,
    ) -> dict:
        """Generate (or reuse current) signed prekey + `needed_opks` fresh OPKs and persist private keys first."""
        needed_opks = max(0, min(100, int(needed_opks)))
        with self._tx() as conn:
            st = self._load_prekey_state_tx(conn)
            spks: dict = st.setdefault("signed_prekeys", {})
            opks: dict = st.setdefault("one_time_prekeys", {})
            cur_ver = int(st.get("current_version", 0) or 0)

            if cur_ver < 1 or str(cur_ver) not in spks or rotate_signed_prekey:
                cur_ver += 1
                spk_obj = X25519PrivateKey.generate()
                spk_priv = _b64e(bytes(spk_obj))
                spk_pub_raw = bytes(spk_obj.public_key)
                spk_pub = _b64e(spk_pub_raw)
                sig_b64 = sign_prekey(signing_key, spk_pub_raw)
                spks[str(cur_ver)] = {
                    "version": cur_ver,
                    "priv": spk_priv,
                    "pub": spk_pub,
                    "sig": sig_b64,
                    "created_at": int(time.time()),
                }
                while len(spks) > MAX_RETAINED_SIGNED_PREKEYS:
                    oldest_v = min(spks.keys(), key=lambda k: int(k))
                    if oldest_v == str(cur_ver):
                        break
                    spks.pop(oldest_v, None)
                st["current_version"] = cur_ver

            cur_spk = spks[str(cur_ver)]
            batch_public = []
            for _ in range(needed_opks):
                kid = str(uuid.uuid4())
                opk_obj = X25519PrivateKey.generate()
                opk_priv = _b64e(bytes(opk_obj))
                opk_pub = _b64e(bytes(opk_obj.public_key))
                opks[kid] = {"priv": opk_priv, "pub": opk_pub}
                batch_public.append({"key_id": kid, "public_key": opk_pub})

            self._save_prekey_state_tx(conn, st)
            return {
                "version": cur_ver,
                "signed_prekey": cur_spk["pub"],
                "signature": cur_spk["sig"],
                "one_time_keys": batch_public,
                "verify_signature": True,
            }

    @staticmethod
    def _peer_slot_key(peer_device_id: str, peer_ik_b64: str) -> str:
        digest = hashlib.sha256(f"{peer_device_id}|{peer_ik_b64}".encode("utf-8")).hexdigest()
        return f"peer_{digest}"

    def has_active_session(self, peer_device_id: str, peer_ik_b64: str) -> bool:
        pkey = self._peer_slot_key(peer_device_id, peer_ik_b64)
        with self._tx() as conn:
            row = conn.execute("SELECT blob FROM peer_sessions WHERE peer_key=?", (pkey,)).fetchone()
            if not row:
                return False
            rec = self._dec(pkey, row[0])
            return isinstance(rec.get("active"), dict) and rec["active"].get("ck_s") is not None

    def init_initiator_session_from_bundle(
        self,
        *,
        our_signing_key: SigningKey,
        peer_device_id: str,
        peer_verified_ik_b64: str,
        claimed_bundle: dict,
    ) -> str:
        shared_secret, x3dh_hdr = x3dh_initiate(our_signing_key, peer_verified_ik_b64, claimed_bundle)
        sess = DoubleRatchetSession.init_initiator(shared_secret, claimed_bundle["signed_prekey"], x3dh_hdr)
        pkey = self._peer_slot_key(peer_device_id, peer_verified_ik_b64)
        with self._tx() as conn:
            row = conn.execute("SELECT blob FROM peer_sessions WHERE peer_key=?", (pkey,)).fetchone()
            rec = self._dec(pkey, row[0]) if row else {"sessions": {}, "active_id": None}
            sid = sess.state["session_id"]
            rec["sessions"][sid] = sess.to_dict()
            rec["active_id"] = sid
            rec["active"] = sess.to_dict()
            conn.execute(
                "INSERT INTO peer_sessions (peer_key, blob) VALUES (?, ?) "
                "ON CONFLICT(peer_key) DO UPDATE SET blob=excluded.blob",
                (pkey, self._enc(pkey, rec)),
            )
        return sess.state["session_id"]

    def encrypt_for_peer(
        self,
        *,
        our_ik_b64: str,
        our_device_id: str,
        peer_device_id: str,
        peer_verified_ik_b64: str,
        plaintext: str,
        msg_kind: str = "text",
        attachment_commit: Optional[str] = None,
    ) -> str:
        pkey = self._peer_slot_key(peer_device_id, peer_verified_ik_b64)
        with self._tx() as conn:
            row = conn.execute("SELECT blob FROM peer_sessions WHERE peer_key=?", (pkey,)).fetchone()
            if not row:
                raise RatchetError("No active Double Ratchet session for peer")
            rec = self._dec(pkey, row[0])
            active_id = rec.get("active_id")
            sessions = rec.get("sessions") or {}
            sess_dict = sessions.get(active_id) or rec.get("active")
            if not isinstance(sess_dict, dict):
                raise RatchetError("Missing active Double Ratchet state")
            sess = DoubleRatchetSession(sess_dict)
            wire_blob = sess.encrypt(
                plaintext,
                sender_ik=our_ik_b64,
                receiver_ik=peer_verified_ik_b64,
                sender_device_id=our_device_id,
                receiver_device_id=peer_device_id,
                msg_kind=msg_kind,
                attachment_commit=attachment_commit,
            )
            new_dict = sess.to_dict()
            sessions[new_dict["session_id"]] = new_dict
            rec["sessions"] = sessions
            rec["active_id"] = new_dict["session_id"]
            rec["active"] = new_dict
            conn.execute(
                "UPDATE peer_sessions SET blob=? WHERE peer_key=?",
                (self._enc(pkey, rec), pkey),
            )
            return wire_blob

    def decrypt_from_peer(
        self,
        *,
        our_signing_key: SigningKey,
        our_ik_b64: str,
        our_device_id: str,
        peer_device_id: str,
        peer_verified_ik_b64: str,
        wire_blob: str,
        server_delivery_id: Optional[str] = None,
    ) -> str:
        outer = parse_double_ratchet_outer(wire_blob)
        if outer["recipient_ik"] != our_ik_b64 or outer["recipient_device_id"] != our_device_id:
            raise RatchetError("Double Ratchet envelope addressed to different device/key")

        wire_digest = hashlib.sha256(wire_blob.encode("utf-8")).hexdigest()
        pkey = self._peer_slot_key(peer_device_id, peer_verified_ik_b64)

        with self._tx() as conn:
            if isinstance(server_delivery_id, str) and server_delivery_id:
                seen_row = conn.execute(
                    "SELECT blob FROM seen_incoming WHERE delivery_id=?",
                    (server_delivery_id,),
                ).fetchone()
                if seen_row:
                    seen_rec = self._dec(f"seen:{server_delivery_id}", seen_row[0])
                    if hmac.compare_digest(seen_rec.get("digest", ""), wire_digest) and (
                        seen_rec.get("sender_dev") == peer_device_id
                    ):
                        if seen_rec.get("persisted") is True:
                            raise ReplayAlreadyProcessed()
                        staged = seen_rec.get("staged_pt")
                        if isinstance(staged, str):
                            return staged
                    raise RatchetError("Conflicting ciphertext on duplicate server delivery ID")

            row = conn.execute("SELECT blob FROM peer_sessions WHERE peer_key=?", (pkey,)).fetchone()
            rec = self._dec(pkey, row[0]) if row else {"sessions": {}, "active_id": None}
            sessions: dict = rec.setdefault("sessions", {})

            sid = outer["session_id"]
            dr_header = outer["header"]
            x3dh_hdr = dr_header.get("x3dh")
            consumed_opk_id: Optional[str] = None
            pk_state: Optional[dict] = None

            if sid not in sessions:
                if not isinstance(x3dh_hdr, dict) or x3dh_hdr.get("session_id") != sid:
                    raise RatchetError("Unknown Double Ratchet session without valid X3DH init header")
                pk_state = self._load_prekey_state_tx(conn)
                spk_ver = str(x3dh_hdr.get("spk_version", ""))
                spk_entry = (pk_state.get("signed_prekeys") or {}).get(spk_ver)
                if not isinstance(spk_entry, dict) or spk_entry.get("pub") != x3dh_hdr.get("spk_pub"):
                    raise RatchetError("Referenced Signed PreKey not found or mismatched")
                spk_priv_32 = _b64d(spk_entry["priv"], 32)

                opk_priv_32: Optional[bytes] = None
                req_opk_id = x3dh_hdr.get("opk_id")
                if req_opk_id is not None:
                    if not isinstance(req_opk_id, str):
                        raise RatchetError("Invalid opk_id")
                    opk_entry = (pk_state.get("one_time_prekeys") or {}).get(req_opk_id)
                    if not isinstance(opk_entry, dict):
                        raise RatchetError("One-time prekey missing or already consumed")
                    opk_priv_32 = _b64d(opk_entry["priv"], 32)
                    consumed_opk_id = req_opk_id

                shared_secret = x3dh_respond(
                    our_signing_key,
                    spk_priv_32,
                    opk_priv_32,
                    peer_verified_ik_b64,
                    x3dh_hdr,
                )
                sess = DoubleRatchetSession.init_responder(shared_secret, spk_priv_32, spk_entry["pub"], sid)
            else:
                sess = DoubleRatchetSession(sessions[sid])

            plaintext = sess.decrypt(
                outer,
                sender_ik=peer_verified_ik_b64,
                receiver_ik=our_ik_b64,
                sender_device_id=peer_device_id,
                receiver_device_id=our_device_id,
            )

            # Commit OPK destruction ONLY AFTER authentic AEAD decryption succeeds!
            if consumed_opk_id is not None and pk_state is not None:
                pk_state["one_time_prekeys"].pop(consumed_opk_id, None)
                self._save_prekey_state_tx(conn, pk_state)

            updated_dict = sess.to_dict()
            sessions[sid] = updated_dict
            # Keep at most 4 recent sessions per peer device (handles offline simultaneous-init glare)
            while len(sessions) > 4:
                oldest_sid = next(iter(s for s in sessions if s != sid))
                sessions.pop(oldest_sid, None)

            rec["active_id"] = sid
            rec["active"] = updated_dict
            conn.execute(
                "INSERT INTO peer_sessions (peer_key, blob) VALUES (?, ?) "
                "ON CONFLICT(peer_key) DO UPDATE SET blob=excluded.blob",
                (pkey, self._enc(pkey, rec)),
            )

            if isinstance(server_delivery_id, str) and server_delivery_id:
                seen_blob = self._enc(
                    f"seen:{server_delivery_id}",
                    {
                        "digest": wire_digest,
                        "sender_dev": peer_device_id,
                        "persisted": False,
                        "staged_pt": plaintext,
                        "ts": int(time.time()),
                    },
                )
                conn.execute(
                    "INSERT INTO seen_incoming (delivery_id, blob) VALUES (?, ?)",
                    (server_delivery_id, seen_blob),
                )

            return plaintext

    def mark_delivery_persisted(self, server_delivery_id: str) -> None:
        """Scrub staged plaintext from `seen_incoming` once `SecureStorage.save_message` succeeds."""
        if not isinstance(server_delivery_id, str) or not server_delivery_id:
            return
        with self._tx() as conn:
            row = conn.execute(
                "SELECT blob FROM seen_incoming WHERE delivery_id=?",
                (server_delivery_id,),
            ).fetchone()
            if not row:
                return
            rec = self._dec(f"seen:{server_delivery_id}", row[0])
            if rec.get("persisted") is True and "staged_pt" not in rec:
                return
            cleaned = {
                "digest": rec["digest"],
                "sender_dev": rec["sender_dev"],
                "persisted": True,
                "ts": int(time.time()),
            }
            conn.execute(
                "UPDATE seen_incoming SET blob=? WHERE delivery_id=?",
                (self._enc(f"seen:{server_delivery_id}", cleaned), server_delivery_id),
            )


def encrypt_personal_envelope(
    *,
    owner_username: str,
    owner_device_id: str,
    crypto_mgr,
    recipient_device_id: str,
    recipient_pub_b64: str,
    plaintext: str,
    msg_kind: str = "text",
    attachment_commit: Optional[str] = None,
) -> Tuple[dict, bool]:
    """
    Encrypt a personal 1-on-1 envelope using an active X3DH + Double Ratchet session
    when available, returning `(envelope_dict, used_double_ratchet)`.
    Falls back cleanly to signed NaCl Box if the peer device has no established DR session yet.
    """
    if (
        isinstance(owner_username, str)
        and owner_username
        and isinstance(owner_device_id, str)
        and owner_device_id
        and getattr(crypto_mgr, "private_key", None) is not None
        and msg_kind in {"text", "image", "voice", "file", "edit_msg", "pin_msg", "delete_msg", "read_ack", "typing"}
    ):
        try:
            store = RatchetStore(owner_username)
            if store.has_active_session(recipient_device_id, recipient_pub_b64):
                wire_blob = store.encrypt_for_peer(
                    our_ik_b64=crypto_mgr.get_public_key_b64(),
                    our_device_id=owner_device_id,
                    peer_device_id=recipient_device_id,
                    peer_verified_ik_b64=recipient_pub_b64,
                    plaintext=plaintext,
                    msg_kind=msg_kind,
                    attachment_commit=attachment_commit,
                )
                sig = sign_dr_blob(crypto_mgr.private_key, wire_blob)
                return {"encrypted_blob": wire_blob, "signature": sig}, True
        except Exception:
            pass

    return crypto_mgr.encrypt_message(plaintext, recipient_pub_b64), False


