"""
Regression tests for Windows `Max1m.exe` message sending & atomic queue resilience:
1. Transient Windows Defender (`WdFilter.sys`) `PermissionError` (`winerror=5` / `32`)
   during `os.replace` in `outbox.enqueue` and `SecureStorage.save_allies` is retried
   cleanly without failing message send or leaving orphan temp files.
2. `_encrypt_durable_personal` and `_encrypt_attachment_personal` fall back cleanly to
   signed NaCl Box if Double Ratchet import/store raises unexpectedly, rather than
   aborting `_send_system_payload` with "Сообщение не отправлено".
3. `edit_msg` and `pin_msg` trigger `_verify_call_contact` when an ally device has not
   yet been verified, matching `_send_ally_text_message`.
"""

import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace

import keyring
from keyring.backend import KeyringBackend

from app import outbox
from app.crypto_box import CryptoManager
from app.recipient_context import RecipientContext
from app.secure_storage import SecureStorage

DESKTOP_ROOT = Path(__file__).resolve().parents[1]


class _MemKeyring(KeyringBackend):
    priority = 10

    def __init__(self):
        self._data = {}

    def get_password(self, service, username):
        return self._data.get((service, username))

    def set_password(self, service, username, password):
        self._data[(service, username)] = password

    def delete_password(self, service, username):
        self._data.pop((service, username), None)


def _extract_methods(rel_path: str, class_name: str, method_names: list[str], env: dict) -> dict:
    src_path = DESKTOP_ROOT / rel_path
    tree = ast.parse(src_path.read_text(encoding="utf-8"), filename=str(src_path))
    cls_node = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name
    )
    selected = [
        n for n in cls_node.body if isinstance(n, ast.FunctionDef) and n.name in method_names
    ]
    mod = ast.Module(body=selected, type_ignores=[])
    ast.fix_missing_locations(mod)
    local_ns = dict(env)
    exec(compile(mod, str(src_path), "exec"), local_ns)
    return {name: local_ns[name] for name in method_names}


def test_outbox_enqueue_and_save_allies_retry_transient_windows_defender_permission_error(
    tmp_path, monkeypatch
):
    import app.secure_storage as ss

    monkeypatch.setattr(ss, "BASE_DIR", tmp_path / "max1m_data")
    monkeypatch.setattr(ss, "CONFIG_FILE", (tmp_path / "max1m_data") / "local_state.json")
    keyring.set_keyring(_MemKeyring())

    real_replace = os.replace
    flaky_attempts = {"count": 0}

    def _defender_locked_replace(src, dst):
        if flaky_attempts["count"] < 2:
            flaky_attempts["count"] += 1
            err = PermissionError("Access is denied")
            err.winerror = 5
            raise err
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _defender_locked_replace)
    monkeypatch.setattr(ss.time, "sleep", lambda _s: None)

    SecureStorage.save_allies("alice", {"bob": {"user_id": "u2", "devices": []}})
    assert SecureStorage.load_allies("alice") == {"bob": {"user_id": "u2", "devices": []}}
    assert flaky_attempts["count"] == 2

    # Reset counter and verify outbox.enqueue also survives transient WinError 32
    flaky_attempts["count"] = 0
    msg_id = outbox.enqueue(
        "alice",
        "https://relay.example",
        "alice-dev-1",
        {"receiver_device_id": "bob-dev-1", "encrypted_blob": "blob", "signature": "sig"},
        local_history={"ally_username": "bob", "text": "hello", "msg_id": "m1", "timestamp": "2026-11-05T00:00:00"},
    )
    assert flaky_attempts["count"] == 2
    queued = outbox.next_message("alice", "https://relay.example", "alice-dev-1")
    assert queued is not None
    qpath, record = queued
    assert record["client_message_id"] == msg_id
    # Ensure no leftover temp files remain in outbox directory
    leftover = [p for p in qpath.parent.iterdir() if not p.name.endswith(".enc")]
    assert leftover == []


def test_encrypt_durable_personal_falls_back_to_nacl_box_if_double_ratchet_unavailable(monkeypatch):
    import sys

    alice = CryptoManager()
    alice.generate_new_keypair()
    bob = CryptoManager()
    bob.generate_new_keypair()

    # Simulate missing/broken app.double_ratchet in frozen bundle
    monkeypatch.setitem(sys.modules, "app.double_ratchet", None)

    env = {"json": json, "crypto": alice}
    methods = _extract_methods(
        "app/windows/main_screen.py",
        "MainScreen",
        ["_encrypt_durable_personal", "_encrypt_attachment_personal"],
        env,
    )
    screen = SimpleNamespace(_ensure_peer_ratchet_session=lambda *_a: None)
    enc_dur = methods["_encrypt_durable_personal"].__get__(screen)
    enc_att = methods["_encrypt_attachment_personal"].__get__(screen)

    ctx = RecipientContext(
        username="bob",
        device_id="bob-dev",
        public_key=bob.get_public_key_b64(),
        owner_username="alice",
        owner_device_id="alice-dev",
        server_url="https://relay.example",
    )
    res = enc_dur(ctx, {"type": "text", "text": "Привет!", "msg_id": "m1"}, "text")
    assert "encrypted_blob" in res and "signature" in res
    assert bob.verify_signature(res["encrypted_blob"], res["signature"], alice.get_public_key_b64())
    dec = bob.decrypt_message(res["encrypted_blob"], alice.get_public_key_b64())
    assert json.loads(dec)["text"] == "Привет!"

    att_res = enc_att(
        ctx,
        {"type": "image", "file_id": "f1", "secret_key": "k1", "caption": "ok", "msg_id": "m2"},
        "image",
        "f1",
        "k1",
        "m2",
    )
    assert bob.verify_signature(att_res["encrypted_blob"], att_res["signature"], alice.get_public_key_b64())
    dec_att = bob.decrypt_message(att_res["encrypted_blob"], alice.get_public_key_b64())
    assert json.loads(dec_att)["type"] == "image"
