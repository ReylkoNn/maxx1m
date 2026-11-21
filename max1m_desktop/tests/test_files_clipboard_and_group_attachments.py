"""
Tests for Package V:
1. Strict filename sanitization (`sanitize_attachment_filename`), pipe/traversal/Windows-device
   neutralization, and executable extension warnings.
2. Document (`type: "file"`, `[FILE_META]|...`) fail-closed verification in `outbox_policy.py`
   for both X3DH + Double Ratchet (`attachment_commitment`) and NaCl Box envelopes.
3. Group v2 E2EE attachment upload + multi-device grant (`UploadAndGrantGroupAttachmentWorker`)
   + `SenderKey` encrypted `[FILE_META]` / `[VOICE_META]` round-trip with TTL.
4. Incoming `msg_type == "file"` bounds and sanitization in `MainScreen._handle_decrypted_payload`.
"""

import ast
import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.double_ratchet as dr_mod
import app.secure_storage as ss_mod
from app.contact_keys import fingerprint_public_key
from app.crypto_box import CryptoManager
from app.double_ratchet import RatchetStore, attachment_commitment, encrypt_personal_envelope
from app.group_crypto import GroupCrypto
from app.media_identity import (
    build_file_meta,
    format_file_size,
    is_dangerous_executable_extension,
    parse_file_meta,
    sanitize_attachment_filename,
)
from app.outbox_policy import OutboxRecipientError, verify_queued_recipient
from app.workers import UploadAndGrantGroupAttachmentWorker


def test_filename_sanitization_and_executable_detection():
    assert sanitize_attachment_filename("../../etc/passwd") == "passwd"
    assert sanitize_attachment_filename(r"C:\Users\Admin\Desktop\Договор №12.pdf") == "Договор №12.pdf"
    assert sanitize_attachment_filename("CON.txt") == "_CON.txt"
    assert sanitize_attachment_filename("lpt1") == "_lpt1"
    # Pipe delimiter injection inside filename is neutralized so [FILE_META]| fields cannot shift
    injected = sanitize_attachment_filename("report|injected_key|999.xlsx")
    assert "|" not in injected and injected.endswith(".xlsx")
    assert sanitize_attachment_filename("...\x00\x1f   ") == "document.bin"

    assert is_dangerous_executable_extension("invoice.pdf.exe") is True
    assert is_dangerous_executable_extension("deploy.ps1") is True
    assert is_dangerous_executable_extension("Отчёт_Q4.xlsx") is False
    assert format_file_size(1536) == "1.5 КБ"


def test_document_outbox_policy_double_ratchet_and_box_verification(tmp_path, monkeypatch):
    base = tmp_path / ".max1m"
    base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ss_mod, "BASE_DIR", base)
    keys = {}
    monkeypatch.setattr(ss_mod.keyring, "get_password", lambda s, k: keys.get(f"{s}:{k}"))
    monkeypatch.setattr(ss_mod.keyring, "set_password", lambda s, k, v: keys.__setitem__(f"{s}:{k}", v))

    alice_cm = CryptoManager()
    alice_cm.generate_new_keypair()
    bob_cm = CryptoManager()
    bob_cm.generate_new_keypair()
    bob_pub = bob_cm.get_public_key_b64()

    bob_bundle = RatchetStore("bob").prepare_publish_bundle(bob_cm.private_key, needed_opks=2)
    RatchetStore("alice").init_initiator_session_from_bundle(
        our_signing_key=alice_cm.private_key,
        peer_device_id="bob-dev",
        peer_verified_ik_b64=bob_pub,
        claimed_bundle={
            "device_id": "bob-dev",
            "identity_key": bob_pub,
            "signed_prekey": bob_bundle["signed_prekey"],
            "signature": bob_bundle["signature"],
            "version": bob_bundle["version"],
            "one_time_key": bob_bundle["one_time_keys"][0],
        },
    )

    state = SimpleNamespace(
        username="alice",
        device_id="alice-dev",
        server_url="https://node.local",
        allies={
            "bob": {
                "devices": [
                    {
                        "device_id": "bob-dev",
                        "public_key": bob_pub,
                        "verified_fingerprint": fingerprint_public_key(bob_pub),
                        "verified_scope": {
                            "username": "alice",
                            "device_id": "alice-dev",
                            "server_url": "https://node.local",
                        },
                    }
                ]
            }
        },
    )

    fid = str(uuid.uuid4())
    fkey = alice_cm.generate_file_key()
    mid = "msg_doc_1"
    fname = "Смета_2026.xlsx"
    fsize = 48120
    cap = "Финальная версия"
    meta_text = build_file_meta(fid, fkey, fname, fsize, cap)

    doc_msg = {
        "type": "file",
        "file_id": fid,
        "secret_key": fkey,
        "filename": fname,
        "size_bytes": fsize,
        "caption": cap,
        "msg_id": mid,
    }

    # 1. Double Ratchet document envelope passes `verify_queued_recipient`
    dr_env, used_dr = encrypt_personal_envelope(
        owner_username="alice",
        owner_device_id="alice-dev",
        crypto_mgr=alice_cm,
        recipient_device_id="bob-dev",
        recipient_pub_b64=bob_pub,
        plaintext=json.dumps(doc_msg, ensure_ascii=False),
        msg_kind="file",
        attachment_commit=attachment_commitment(fid, fkey, mid),
    )
    assert used_dr is True
    record_dr = {
        "receiver_device_id": "bob-dev",
        **dr_env,
        "_local_history": {"ally_username": "bob", "text": meta_text, "msg_id": mid},
    }
    ctx, extracted = verify_queued_recipient(state, alice_cm, record_dr, attachment_file_id=fid, return_attachment_key=True)
    assert ctx.username == "bob" and extracted == fkey

    # Tampering local history secret_key fails attachment commitment check
    other_key = alice_cm.generate_file_key()
    bad_record = {
        "receiver_device_id": "bob-dev",
        **dr_env,
        "_local_history": {
            "ally_username": "bob",
            "text": build_file_meta(fid, other_key, fname, fsize, cap),
            "msg_id": mid,
        },
    }
    with pytest.raises(OutboxRecipientError):
        verify_queued_recipient(state, alice_cm, bad_record, attachment_file_id=fid, return_attachment_key=True)

    # 2. Legacy NaCl Box document envelope also passes `verify_queued_recipient`
    box_env = alice_cm.encrypt_message(json.dumps(doc_msg, ensure_ascii=False), bob_pub)
    record_box = {
        "receiver_device_id": "bob-dev",
        **box_env,
        "_local_history": {"ally_username": "bob", "text": meta_text, "msg_id": mid},
    }
    _, extracted_box = verify_queued_recipient(state, alice_cm, record_box, attachment_file_id=fid, return_attachment_key=True)
    assert extracted_box == fkey


def test_group_v2_e2ee_attachment_worker_and_sender_key_roundtrip(monkeypatch):
    import app.workers as w_mod

    alice_cm = CryptoManager()
    alice_cm.generate_new_keypair()
    gcm = GroupCrypto()

    raw_pdf = b"%PDF-1.7\nSecret company contract payload\n%%EOF"
    fid = str(uuid.uuid4())
    fkey = alice_cm.generate_file_key()
    enc_blob = alice_cm.encrypt_file(raw_pdf, fkey)

    uploaded = []
    granted = []
    monkeypatch.setattr(
        w_mod.api,
        "upload_file_reliable",
        lambda srv, tok, f_id, blob: (uploaded.append((f_id, len(blob))) or True, {"file_id": f_id}),
    )
    monkeypatch.setattr(
        w_mod.api,
        "grant_file_access",
        lambda srv, tok, f_id, dev_id: (granted.append((f_id, dev_id)) or True, {"ok": True}),
    )

    dev_b = str(uuid.uuid4())
    dev_c = str(uuid.uuid4())
    results = []
    worker = UploadAndGrantGroupAttachmentWorker(
        "https://node.local", "jwt-tok", fid, enc_blob, [dev_b, dev_c, dev_b]
    )
    worker.finished.connect(lambda ok, info: results.append((ok, info)))
    worker.run()

    assert results == [(True, {"file_id": fid, "granted": 2})]
    assert uploaded == [(fid, len(enc_blob))]
    assert granted == [(fid, dev_b), (fid, dev_c)]
    assert worker.token == "" and worker.encrypted_blob == b""

    # Encrypt `[FILE_META]` over Group v2 SenderKey with TTL and verify recipient decrypts both
    sender_sk = gcm.generate_sender_key(epoch=2)
    recv_sk = json.loads(json.dumps(sender_sk))
    meta_str = build_file_meta(fid, fkey, "Контракт_2026.pdf", len(raw_pdf), "Подписать сегодня")

    import app.group_crypto as gc_mod
    monkeypatch.setattr(gc_mod, "default_crypto", alice_cm)

    enc_grp = gcm.encrypt_group_message(
        meta_str,
        sender_sk,
        group_id="grp-docs",
        sender_device_id="alice-dev",
        crypto_mgr=alice_cm,
        ttl_seconds=3600,
    )
    dec_env = gcm.decrypt_group_message_envelope(
        enc_grp,
        recv_sk,
        expected_group_id="grp-docs",
        expected_sender_device_id="alice-dev",
        sender_public_key_b64=alice_cm.get_public_key_b64(),
    )
    assert dec_env is not None and dec_env["ttl_seconds"] == 3600
    parsed = parse_file_meta(dec_env["text"])
    assert parsed is not None
    assert parsed["filename"] == "Контракт_2026.pdf"
    assert alice_cm.decrypt_file(enc_blob, parsed["secret_key"]) == raw_pdf


def test_incoming_file_payload_validation_in_main_screen():
    source = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "MainScreen")
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "_handle_decrypted_payload")

    saved = []
    from app.media_identity import valid_file_id, valid_file_key

    env = {
        "json": json,
        "valid_file_id": valid_file_id,
        "valid_file_key": valid_file_key,
        "state": SimpleNamespace(username="bob", current_chat_username=None),
        "storage": SimpleNamespace(
            save_message=lambda *a, **kw: (saved.append((a, kw)) or True),
        ),
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), str(source), "exec"), env)
    handle = env["_handle_decrypted_payload"]
    screen = SimpleNamespace(
        window=lambda: SimpleNamespace(isActiveWindow=lambda: False),
        _get_ally_card=lambda _u: None,
        _get_ally_item=lambda _u: None,
    )

    cm = CryptoManager()
    fkey = cm.generate_file_key()
    fid = str(uuid.uuid4())

    # Negative size rejected before storage
    bad_msg = json.dumps({"type": "file", "file_id": fid, "secret_key": fkey, "filename": "a.pdf", "size_bytes": -5, "msg_id": "m1"})
    assert handle(screen, "alice", bad_msg, "sig1") is False
    assert not saved

    # Traversal filename is sanitized before persistence!
    good_msg = json.dumps({
        "type": "file",
        "file_id": fid,
        "secret_key": fkey,
        "filename": "../../evil/ТЗ_проекта.pdf",
        "size_bytes": 2048,
        "caption": "См. п. 3",
        "msg_id": "m2",
    })
    assert handle(screen, "alice", good_msg, "sig2") is True
    assert len(saved) == 1
    persisted_text = saved[0][0][2]
    parsed = parse_file_meta(persisted_text)
    assert parsed is not None and parsed["filename"] == "ТЗ_проекта.pdf"
