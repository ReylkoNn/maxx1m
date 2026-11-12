"""
Tests for Package VII:
1. Encrypted SQLite `edit_message` ownership invariants (cannot edit peer's own message,
   cannot edit another group member's message, cannot edit deleted/media rows, and
   preserves `original_identity` so idempotent network retries never conflict).
2. `edit_msg` and `pin_msg` outbox policy verification over Double Ratchet and NaCl Box,
   plus `get_pinned_message` / `set_pinned_message` encrypted persistence.
3. Private System Notifications (`should_mask_notifications` + `AppWindow.show_notification`)
   masking sender & text when Argon2id LocalVault or `private_notifications` is active.
4. `mss` screen capture dependency declared in `max1m_desktop/requirements.txt`.
"""

import ast
import json
from pathlib import Path
from types import SimpleNamespace

import app.local_vault as lv_mod
import app.secure_storage as ss_mod
from app.contact_keys import fingerprint_public_key
from app.crypto_box import CryptoManager
from app.double_ratchet import RatchetStore, encrypt_personal_envelope
from app.local_vault import enable_local_vault, lock_vault
from app.outbox_policy import verify_queued_recipient
from app.secure_storage import SecureStorage


def _setup_isolated_storage(tmp_path, monkeypatch):
    base = tmp_path / ".max1m"
    base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ss_mod, "BASE_DIR", base)
    monkeypatch.setattr(ss_mod, "CONFIG_FILE", base / "local_state.json")
    keys = {}
    monkeypatch.setattr(ss_mod.keyring, "get_password", lambda s, k: keys.get(f"{s}:{k}"))
    monkeypatch.setattr(ss_mod.keyring, "set_password", lambda s, k, v: keys.__setitem__(f"{s}:{k}", v))
    monkeypatch.setattr(ss_mod.keyring, "delete_password", lambda s, k: keys.pop(f"{s}:{k}", None))
    return base, keys


def test_encrypted_edit_message_ownership_group_sender_isolation_and_retry_safety(tmp_path, monkeypatch):
    _setup_isolated_storage(tmp_path, monkeypatch)

    assert SecureStorage.save_message("alice", "bob", "Черновик сметы", True, msg_id="m_mine")
    assert SecureStorage.save_message("alice", "bob", "Ответ Боба", False, msg_id="m_bob")
    assert SecureStorage.save_message("alice", "bob", "[IMAGE_META]|id|key|cap", True, msg_id="m_img")

    # Peer cannot edit Alice's own message (`only_incoming=True` fails)
    assert SecureStorage.edit_message("alice", "bob", "m_mine", "Подмена!", only_incoming=True) is False
    # Alice cannot edit Bob's incoming message (`only_mine=True` fails)
    assert SecureStorage.edit_message("alice", "bob", "m_bob", "Подмена!", only_mine=True) is False
    # Media attachment row cannot be turned into edited text
    assert SecureStorage.edit_message("alice", "bob", "m_img", "Текст", only_mine=True) is False

    # Legitimate local edit of own message succeeds and marks `edited=True`
    assert SecureStorage.edit_message("alice", "bob", "m_mine", "Финальная смета: 120 000 ₽", only_mine=True) is True
    # Idempotent redelivery/retry of original unedited text does NOT raise Conflicting message id!
    assert SecureStorage.save_message("alice", "bob", "Черновик сметы", True, msg_id="m_mine") is False

    msgs = {m["msg_id"]: m for m in SecureStorage.load_messages("alice", "bob")}
    assert msgs["m_mine"]["text"] == "Финальная смета: 120 000 ₽"
    assert msgs["m_mine"]["edited"] is True

    # Group v2 sender isolation: @mallory cannot edit @bob's group message!
    assert SecureStorage.save_message(
        "alice", "group_g1", "Релиз в 18:00", False, msg_id="gm_1", sender_name="@bob"
    )
    assert (
        SecureStorage.edit_message(
            "alice", "group_g1", "gm_1", "Отмена релиза!", only_incoming=True, expected_sender_name="@mallory"
        )
        is False
    )
    assert (
        SecureStorage.edit_message(
            "alice", "group_g1", "gm_1", "Релиз в 19:00", only_incoming=True, expected_sender_name="@bob"
        )
        is True
    )
    gmsgs = {m["msg_id"]: m for m in SecureStorage.load_messages("alice", "group_g1")}
    assert gmsgs["gm_1"]["text"] == "Релиз в 19:00" and gmsgs["gm_1"]["edited"] is True


def test_edit_and_pin_outbox_policy_and_encrypted_pinned_persistence(tmp_path, monkeypatch):
    _setup_isolated_storage(tmp_path, monkeypatch)

    # Encrypted pinned message round-trip + unpin
    assert SecureStorage.get_pinned_message("alice", "group_g1") is None
    assert SecureStorage.set_pinned_message(
        "alice", "group_g1", {"msg_id": "gm_1", "preview": "Регламент созвонов в 10:00"}
    )
    pinned = SecureStorage.get_pinned_message("alice", "group_g1")
    assert pinned == {"msg_id": "gm_1", "preview": "Регламент созвонов в 10:00"}
    assert SecureStorage.set_pinned_message("alice", "group_g1", None)
    assert SecureStorage.get_pinned_message("alice", "group_g1") is None

    # Double Ratchet + Box verification for `edit_msg` and `pin_msg`
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

    for kind, body in (
        ("edit_msg", {"type": "edit_msg", "msg_id": "m1", "new_text": "Обновлённый текст"}),
        ("pin_msg", {"type": "pin_msg", "msg_id": "m1", "preview": "Важное объявление"}),
    ):
        dr_env, used_dr = encrypt_personal_envelope(
            owner_username="alice",
            owner_device_id="alice-dev",
            crypto_mgr=alice_cm,
            recipient_device_id="bob-dev",
            recipient_pub_b64=bob_pub,
            plaintext=json.dumps(body, ensure_ascii=False),
            msg_kind=kind,
        )
        assert used_dr is True
        ctx = verify_queued_recipient(state, alice_cm, {"receiver_device_id": "bob-dev", **dr_env})
        assert ctx.username == "bob"

        box_env = alice_cm.encrypt_message(json.dumps(body, ensure_ascii=False), bob_pub)
        ctx_box = verify_queued_recipient(state, alice_cm, {"receiver_device_id": "bob-dev", **box_env})
        assert ctx_box.username == "bob"


def test_private_notifications_mask_sender_and_content_and_mss_in_requirements(tmp_path, monkeypatch):
    _setup_isolated_storage(tmp_path, monkeypatch)

    # Without vault and with private_notifications=False -> unmasked
    SecureStorage._get_or_create_local_key("ivan")
    assert SecureStorage.should_mask_notifications("ivan") is False

    # Explicit private_notifications=True -> masked!
    SecureStorage.set_private_notifications("ivan", True)
    assert SecureStorage.should_mask_notifications("ivan") is True
    SecureStorage.set_private_notifications("ivan", False)
    assert SecureStorage.should_mask_notifications("ivan") is False

    # Enabling Argon2id LocalVault automatically masks notifications when locked!
    cm = CryptoManager()
    cm.generate_new_keypair()
    from nacl.encoding import Base64Encoder
    SecureStorage.save_private_key("ivan", cm.private_key.encode(encoder=Base64Encoder).decode("ascii"))
    enable_local_vault("ivan", "MasterPass!2026", auto_lock_seconds=300)
    lock_vault("ivan")
    assert SecureStorage.should_mask_notifications("ivan") is True

    # Verify AppWindow.show_notification masks both title and body
    app_src = Path(__file__).resolve().parents[1] / "app/windows/app_window.py"
    tree = ast.parse(app_src.read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AppWindow")
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "show_notification")

    shown = []
    env = {
        "storage": SecureStorage,
        "state": SimpleNamespace(username="ivan"),
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), str(app_src), "exec"), env)
    win = SimpleNamespace(
        in_app_toast=SimpleNamespace(show_notification=lambda t, m, is_group=False: shown.append((t, m, is_group)))
    )
    env["show_notification"](win, "@director", "Пароль от банка: 9911", is_group=False)
    assert shown == [("Max1m", "🔒 Новое зашифрованное сообщение", False)]

    # Verify `mss` is declared in max1m_desktop/requirements.txt
    req_txt = (Path(__file__).resolve().parents[1] / "requirements.txt").read_text(encoding="utf-8")
    assert "mss==" in req_txt
