"""Regression tests for Package #5 desktop features:
- Smart _delete_message behavior:
  1) Deleting an incoming peer message (is_mine=False) NEVER sends delete_msg to the peer.
  2) Deleting an unsent attachment in attachment_outbox cancels .job+.blob, dispatches server
     reservation cancellation, never resurrects the message, and never sends un-ACKable delete_msg.
  3) Deleting an unsent outbox message with _send_attempted=False cancels the outbox record locally
     without sending delete_msg; whereas _send_attempted=True cancels the outbox record AND queues
     a durable delete_msg.
  4) Both legacy JSON history and migrated SQLite row-store preserve (deleted, was_mine).
- Explicit _cancel_pending_attachment_outbox menu flow.
- Read-only profile diagnostics (diagnose_profile.py) without secret leakage or side effects.
"""
import ast
import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import keyring
from keyring.backend import KeyringBackend
import pytest

import diagnose_profile as diag_mod
from app import attachment_outbox, outbox, secure_storage
from app.contact_keys import fingerprint_public_key
from app.crypto_box import CryptoManager
from app.history_activation import migrate_chat
from app.recipient_context import RecipientContext, verification_scope
from app.secure_storage import SecureStorage

DESKTOP_ROOT = Path(__file__).resolve().parents[1]


class _MemKeyring(KeyringBackend):
    priority = 10

    def __init__(self):
        self.data = {}

    def get_password(self, service, username):
        return self.data.get((service, username))

    def set_password(self, service, username, password):
        self.data[(service, username)] = password

    def delete_password(self, service, username):
        self.data.pop((service, username), None)


def _extract_methods(rel_path: str, class_name: str, method_names: list[str], env: dict) -> dict:
    src = (DESKTOP_ROOT / rel_path).read_text(encoding="utf-8")
    tree = ast.parse(src)
    wanted = set(method_names)
    nodes = [
        node
        for cls in tree.body
        if isinstance(cls, ast.ClassDef) and cls.name == class_name
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    assert {n.name for n in nodes} == wanted
    mod = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    ns = dict(env)
    exec(compile(mod, str(DESKTOP_ROOT / rel_path), "exec"), ns)
    return {name: ns[name] for name in method_names}


def test_delete_message_with_meta_in_legacy_and_migrated_row_store(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    keyring.set_keyring(_MemKeyring())

    SecureStorage.save_message("alice", "bob", "from bob", is_mine=False, msg_id="in-1")
    SecureStorage.save_message("alice", "bob", "from alice", is_mine=True, msg_id="out-1")

    assert SecureStorage.delete_message_with_meta("alice", "bob", "in-1") == (True, False)
    assert SecureStorage.delete_message_with_meta("alice", "bob", "in-1") == (False, False)
    assert SecureStorage.delete_message_with_meta("alice", "bob", "out-1") == (True, True)

    # Test migrated SQLite row-store as well
    SecureStorage.save_message("alice", "carol", "peer msg", is_mine=False, msg_id="in-2")
    SecureStorage.save_message("alice", "carol", "my msg", is_mine=True, msg_id="out-2")
    assert migrate_chat("alice", "carol") is True

    assert SecureStorage.delete_message_with_meta("alice", "carol", "in-2") == (True, False)
    assert SecureStorage.delete_message_with_meta("alice", "carol", "out-2") == (True, True)
    assert SecureStorage.delete_message_with_meta("alice", "carol", "missing") == (False, False)


def test_smart_delete_prevents_incoming_poisoning_and_unsent_resurrection(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    keyring.set_keyring(_MemKeyring())

    alice = CryptoManager()
    alice.generate_new_keypair()
    bob = CryptoManager()
    bob.generate_new_keypair()
    bob_pub = bob.get_public_key_b64()
    ctx = RecipientContext("bob", "bob-dev", bob_pub, "alice", "alice-dev", "https://relay.example")

    state = SimpleNamespace(
        username="alice",
        device_id="alice-dev",
        server_url="https://relay.example",
        token="tok-alice",
        current_chat_type="ally",
        current_group_id=None,
        current_chat_username="bob",
        current_chat_device_id="bob-dev",
        allies={
            "bob": {
                "user_id": "u-bob",
                "devices": [
                    {
                        "device_id": "bob-dev",
                        "device_name": "Bob PC",
                        "public_key": bob_pub,
                        "fingerprint": fingerprint_public_key(bob_pub),
                        "verified_fingerprint": fingerprint_public_key(bob_pub),
                        "verified_scope": verification_scope(ctx),
                    }
                ],
            }
        },
    )

    cancelled_reservations = []
    sent_delete_payloads = []

    class _CancelWorkerStub:
        def __init__(self, server_url, token, file_id):
            self.file_id = file_id
            self.finished = SimpleNamespace(connect=lambda *_a: None)

        def start(self):
            cancelled_reservations.append(self.file_id)

    env = {
        "state": state,
        "storage": SecureStorage,
        "outbox": outbox,
        "attachment_outbox": attachment_outbox,
        "CancelUploadReservationWorker": _CancelWorkerStub,
        "voice_cache": SimpleNamespace(delete_group=lambda _s: None),
        "message_scope": lambda *a: ":".join(str(x) for x in a),
        "QMessageBox": SimpleNamespace(
            Yes=1,
            No=2,
            question=lambda *_a, **_kw: 1,
            warning=lambda *_a: None,
            information=lambda *_a: None,
        ),
        "Qt": SimpleNamespace(QueuedConnection=0),
    }
    methods = _extract_methods(
        "app/windows/main_screen.py",
        "MainScreen",
        [
            "_dispatch_cancel_upload_reservations",
            "_delete_message",
            "_cancel_pending_attachment_outbox",
        ],
        env,
    )

    screen = SimpleNamespace(
        _net_workers=[],
        _outbox_worker=None,
        _attachment_worker=None,
        _outbox_management_active=False,
        _outbox_skipped=set(),
        _attachment_skipped=set(),
        _attachment_retry_after={},
        _attachment_warning_shown=True,
        _render_history_page=lambda: None,
        _send_system_payload=lambda user, payload: sent_delete_payloads.append((user, payload)),
    )
    for name, fn in methods.items():
        setattr(screen, name, fn.__get__(screen))

    # Case 1: Deleting peer's INCOMING message (is_mine=False) MUST NOT send delete_msg!
    SecureStorage.save_message("alice", "bob", "hello from bob", is_mine=False, msg_id="peer-msg-1")
    screen._delete_message("peer-msg-1")
    assert SecureStorage.load_messages_strict("alice", "bob") == []
    assert sent_delete_payloads == []

    # Case 2: Deleting an UNSENT attachment in attachment_outbox cancels .job/.blob,
    # dispatches server reservation cancel, and MUST NOT send delete_msg!
    att_file_id = str(uuid.uuid4())
    att_msg_id = str(uuid.uuid4())
    att_hist = {"ally_username": "bob", "text": f"[IMAGE_META]|{att_file_id}|key|", "msg_id": att_msg_id}
    SecureStorage.save_message("alice", "bob", att_hist["text"], is_mine=True, msg_id=att_msg_id)
    env_att = alice.encrypt_message(
        json.dumps({"type": "image", "file_id": att_file_id, "secret_key": "k", "msg_id": att_msg_id}),
        bob_pub,
    )
    attachment_outbox.enqueue(
        ctx,
        b"encrypted-attachment-bytes",
        att_file_id,
        str(uuid.uuid4()),
        {"receiver_device_id": "bob-dev", **env_att},
        att_hist,
    )
    assert len(attachment_outbox.pending_job_paths("alice", "https://relay.example", "alice-dev")) == 1

    screen._delete_message(att_msg_id)
    assert attachment_outbox.pending_job_paths("alice", "https://relay.example", "alice-dev") == []
    assert cancelled_reservations == [att_file_id]
    assert SecureStorage.load_messages_strict("alice", "bob") == []
    assert sent_delete_payloads == []

    # Case 3: Deleting an UNSENT text message in outbox with _send_attempted=False
    # removes it from outbox without sending delete_msg or resurrecting!
    unattempted_msg_id = "msg-unattempted"
    hist_unattempted = {"ally_username": "bob", "text": "draft secret", "msg_id": unattempted_msg_id}
    SecureStorage.save_message("alice", "bob", "draft secret", is_mine=True, msg_id=unattempted_msg_id)
    env_txt1 = alice.encrypt_message(
        json.dumps({"type": "text", "text": "draft secret", "msg_id": unattempted_msg_id}), bob_pub
    )
    outbox.enqueue(
        "alice",
        "https://relay.example",
        "alice-dev",
        {"receiver_device_id": "bob-dev", **env_txt1},
        local_history=hist_unattempted,
    )
    screen._delete_message(unattempted_msg_id)
    assert outbox.pending_paths("alice", "https://relay.example", "alice-dev") == []
    assert SecureStorage.load_messages_strict("alice", "bob") == []
    assert sent_delete_payloads == []

    # Case 4: Deleting an outbox message where _send_attempted=True removes it from outbox
    # AND sends durable delete_msg (since the server might have accepted the lost attempt)!
    attempted_msg_id = "msg-attempted"
    hist_attempted = {"ally_username": "bob", "text": "maybe sent", "msg_id": attempted_msg_id}
    SecureStorage.save_message("alice", "bob", "maybe sent", is_mine=True, msg_id=attempted_msg_id)
    env_txt2 = alice.encrypt_message(
        json.dumps({"type": "text", "text": "maybe sent", "msg_id": attempted_msg_id}), bob_pub
    )
    outbox.enqueue(
        "alice",
        "https://relay.example",
        "alice-dev",
        {"receiver_device_id": "bob-dev", **env_txt2},
        local_history=hist_attempted,
    )
    qpath = outbox.pending_paths("alice", "https://relay.example", "alice-dev")[0]
    outbox.mark_send_attempted(qpath, "alice", "https://relay.example", "alice-dev")

    screen._delete_message(attempted_msg_id)
    assert outbox.pending_paths("alice", "https://relay.example", "alice-dev") == []
    assert sent_delete_payloads == [("bob", {"type": "delete_msg", "msg_id": attempted_msg_id})]

    # Case 5: Explicit _cancel_pending_attachment_outbox cancels all queued attachment jobs
    # while preserving chat history!
    att2_fid = str(uuid.uuid4())
    att2_mid = str(uuid.uuid4())
    att2_hist = {"ally_username": "bob", "text": f"[IMAGE_META]|{att2_fid}|key|", "msg_id": att2_mid}
    SecureStorage.save_message("alice", "bob", att2_hist["text"], is_mine=True, msg_id=att2_mid)
    attachment_outbox.enqueue(
        ctx,
        b"blob-two",
        att2_fid,
        str(uuid.uuid4()),
        {"receiver_device_id": "bob-dev", **env_att},
        att2_hist,
    )
    cancelled_reservations.clear()
    screen._cancel_pending_attachment_outbox()
    assert attachment_outbox.pending_job_paths("alice", "https://relay.example", "alice-dev") == []
    assert cancelled_reservations == [att2_fid]
    # History message remains intact after queue-only cancel
    assert len(SecureStorage.load_messages_strict("alice", "bob")) == 1


def test_diagnose_profile_read_only_and_detects_corruption_without_leaking_secrets(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    mem_kr = _MemKeyring()
    keyring.set_keyring(mem_kr)

    # 1. Non-existent profile: strictly read-only (does NOT create dirs or keyring entries!)
    empty_report = diag_mod.diagnose_profile("ghost_user", base_dir=tmp_path)
    assert empty_report["profile_exists"] is False
    assert empty_report["keyring_status"] == "missing"
    assert empty_report["healthy"] is True
    assert not (tmp_path / "profiles" / "ghost_user").exists()
    assert mem_kr.data == {}

    # 2. Populated healthy profile: verify counts and zero secret leakage in CLI JSON output
    priv_crypto = CryptoManager()
    priv_crypto.generate_new_keypair()
    SecureStorage.save_private_key("alice", priv_crypto.get_private_key_b64())
    SecureStorage.save_profile_device("alice", "https://secret-relay.internal", "dev-secret-99", "Laptop")
    SecureStorage.save_allies("alice", {"secret_contact_bob": {"user_id": "u1", "devices": []}})
    SecureStorage.save_groups_index("alice", {"grp-secret-1": {"name": "TopSecretGroup", "created_by_device_id": "d"}})
    SecureStorage.save_message("alice", "secret_contact_bob", "ultra_secret_plaintext", is_mine=True, msg_id="m1")

    rc = diag_mod.main(["--profile", "alice", "--base-dir", str(tmp_path), "--confirm-read-only"])
    out = capsys.readouterr().out
    assert rc == 0
    parsed = json.loads(out)
    assert parsed["healthy"] is True
    assert parsed["keyring_status"] == "present"
    assert parsed["device_private_key_status"] == "present"
    assert parsed["device_identity_status"] == "ok"
    assert parsed["allies_enc_status"] == "ok"
    assert parsed["groups_enc_status"] == "ok"
    assert parsed["legacy_message_files"] == 1
    for secret_marker in ("secret_contact_bob", "TopSecretGroup", "ultra_secret_plaintext", "secret-relay.internal", "dev-secret-99"):
        assert secret_marker not in out

    # 3. Orphan attachment blob is detected (healthy=False, exit code 2) without deleting it
    orphan_blob = tmp_path / "profiles" / "alice" / "outbox" / "scope1" / "attachments" / f"{uuid.uuid4()}.blob"
    orphan_blob.parent.mkdir(parents=True, exist_ok=True)
    orphan_blob.write_bytes(b"orphan-ciphertext")
    rc_corrupt = diag_mod.main(["--profile", "alice", "--base-dir", str(tmp_path), "--confirm-read-only"])
    out_corrupt = json.loads(capsys.readouterr().out)
    assert rc_corrupt == 2
    assert out_corrupt["healthy"] is False
    assert out_corrupt["orphan_attachment_blobs"] == 1
    assert orphan_blob.exists()
