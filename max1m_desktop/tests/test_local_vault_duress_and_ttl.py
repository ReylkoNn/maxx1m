import ast
import base64
import json
from pathlib import Path
import sqlite3
import time
from types import SimpleNamespace

import keyring
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from nacl.pwhash import argon2id
import pytest

from app import local_vault, secure_storage
from app.crypto_box import CryptoManager
from app.group_crypto import GroupCrypto
from app.history_store import EncryptedHistory
from app.local_vault import (
    VaultAuthenticationError,
    VaultLockedError,
    disable_local_vault,
    enable_local_vault,
    execute_panic_wipe,
    is_vault_enabled,
    is_vault_unlocked,
    lock_all_vaults,
    lock_vault,
    secure_wipe_file,
    unlock_vault,
)
from app.secure_storage import SERVICE_NAME, SecureStorage

FAST_OPS = int(argon2id.OPSLIMIT_INTERACTIVE)
FAST_MEM = int(argon2id.MEMLIMIT_INTERACTIVE)


class _DictKeyring(KeyringBackend):
    priority = 10

    def __init__(self):
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.store:
            raise PasswordDeleteError(username)
        del self.store[(service, username)]


@pytest.fixture
def isolated_vault_env(tmp_path, monkeypatch):
    kr = _DictKeyring()
    keyring.set_keyring(kr)
    base_dir = tmp_path / ".max1m"
    monkeypatch.setattr(secure_storage, "BASE_DIR", base_dir)
    monkeypatch.setattr(secure_storage, "CONFIG_FILE", base_dir / "local_state.json")
    lock_all_vaults()
    yield base_dir, kr
    lock_all_vaults()


def _make_keypair() -> tuple[CryptoManager, str, str]:
    cm = CryptoManager()
    cm.generate_new_keypair()
    return cm, cm.get_private_key_b64(), cm.get_public_key_b64()


def test_argon2id_vault_purges_os_keyring_zeroizes_ram_and_enforces_fail_closed(isolated_vault_env):
    base_dir, kr = isolated_vault_env
    _, priv_b64, _pub_b64 = _make_keypair()

    SecureStorage.save_private_key("alice", priv_b64)
    assert SecureStorage.save_message("alice", "bob", "Секретный план", is_mine=True, msg_id="m1")

    # Before enabling vault, keys reside in OS keyring
    assert kr.get_password(SERVICE_NAME, "alice_privkey") == priv_b64
    assert kr.get_password(SERVICE_NAME, "alice_local_storage_key") is not None

    enable_local_vault(
        "alice",
        "CorrectHorseBatteryStaple!99",
        auto_lock_seconds=300,
        opslimit=FAST_OPS,
        memlimit=FAST_MEM,
    )

    assert is_vault_enabled("alice")
    assert is_vault_unlocked("alice")
    # OS keyring MUST be completely empty for alice!
    assert kr.get_password(SERVICE_NAME, "alice_privkey") is None
    assert kr.get_password(SERVICE_NAME, "alice_local_storage_key") is None

    # Grab reference to active RAM slot before locking to verify byte-level zeroization
    slot_ref = local_vault._UNLOCKED_VAULTS["alice"]
    assert any(b != 0 for b in slot_ref.local_key)
    assert any(b != 0 for b in slot_ref.private_key_utf8)

    lock_vault("alice")
    assert not is_vault_unlocked("alice")
    assert all(b == 0 for b in slot_ref.local_key)
    assert all(b == 0 for b in slot_ref.private_key_utf8)

    # While locked, accessing keys or history MUST fail closed without falling back to keyring
    with pytest.raises(VaultLockedError):
        SecureStorage.get_private_key("alice")
    with pytest.raises(VaultLockedError):
        SecureStorage.load_messages_strict("alice", "bob")

    # Wrong password rejected
    with pytest.raises(VaultAuthenticationError):
        unlock_vault("alice", "WrongMasterPassword123")
    assert not is_vault_unlocked("alice")

    # Correct password unlocks RAM slot and restores decrypted access
    assert unlock_vault("alice", "CorrectHorseBatteryStaple!99") == "unlocked"
    assert SecureStorage.get_private_key("alice") == priv_b64
    msgs = SecureStorage.load_messages_strict("alice", "bob")
    assert len(msgs) == 1 and msgs[0]["text"] == "Секретный план"

    # Disabling vault restores keys to OS keyring and shreds vault.enc
    assert disable_local_vault("alice", "CorrectHorseBatteryStaple!99") == "disabled"
    assert not is_vault_enabled("alice")
    assert kr.get_password(SERVICE_NAME, "alice_privkey") == priv_b64
    assert SecureStorage.load_messages_strict("alice", "bob")[0]["text"] == "Секретный план"


def test_duress_pin_forensic_indistinguishability_and_instant_panic_wipe(isolated_vault_env):
    base_dir, kr = isolated_vault_env
    for uname in ("user_plain", "user_duress"):
        _, priv_b64, _ = _make_keypair()
        SecureStorage.save_private_key(uname, priv_b64)
        SecureStorage.save_message(uname, "ally", f"Секрет {uname}", is_mine=True, msg_id=f"id_{uname}")

    enable_local_vault(
        "user_plain",
        "MasterPassword_Alpha1!",
        duress_password=None,
        opslimit=FAST_OPS,
        memlimit=FAST_MEM,
    )
    enable_local_vault(
        "user_duress",
        "MasterPassword_Beta2!",
        duress_password="DuressCode_911!",
        opslimit=FAST_OPS,
        memlimit=FAST_MEM,
    )

    env_plain = json.loads((base_dir / "profiles" / "user_plain" / "vault.enc").read_text("utf-8"))
    env_duress = json.loads((base_dir / "profiles" / "user_duress" / "vault.enc").read_text("utf-8"))

    # Forensic indistinguishability: identical schema & identical duress_slot ciphertext byte size
    assert set(env_plain.keys()) == set(env_duress.keys())
    raw_duress_a = base64.b64decode(env_plain["duress_slot"])
    raw_duress_b = base64.b64decode(env_duress["duress_slot"])
    assert len(raw_duress_a) == len(raw_duress_b)
    assert len(base64.b64decode(env_plain["duress_salt"])) == argon2id.SALTBYTES
    assert len(base64.b64decode(env_duress["duress_salt"])) == argon2id.SALTBYTES

    # Create voice_cache & local_state.json for user_duress to verify complete destruction
    vcache = base_dir / "voice_cache"
    vcache.mkdir(parents=True, exist_ok=True)
    (vcache / "cached_clip.bin").write_bytes(b"VOICE_SECRET_BYTES" * 32)
    SecureStorage.save_local_state(
        {"username": "user_duress", "server_url": "https://node.local", "device_id": "d1", "device_name": "PC"}
    )

    lock_vault("user_duress")
    outcome = unlock_vault("user_duress", "DuressCode_911!")
    assert outcome == "duress_wiped"
    assert not (base_dir / "profiles" / "user_duress").exists()
    assert not vcache.exists()
    assert not (base_dir / "local_state.json").exists()
    assert kr.get_password(SERVICE_NAME, "user_duress_privkey") is None
    # Neighboring profile on the same machine remains intact when single-user duress triggers
    assert (base_dir / "profiles" / "user_plain" / "vault.enc").exists()


def test_secure_wipe_file_overwrites_single_link_and_preserves_hardlink_sibling(tmp_path):
    # Case 1: st_nlink > 1 -> unlinks target without corrupting sibling hardlink
    shared = tmp_path / "shared_blob.bin"
    sibling = tmp_path / "sibling_blob.bin"
    secret = b"HARDLINK_SHARED_PAYLOAD_777" * 50
    shared.write_bytes(secret)
    import os
    os.link(shared, sibling)
    secure_wipe_file(shared)
    assert not shared.exists()
    assert sibling.read_bytes() == secret

    # Case 2: single-link file -> capture pre-unlink bytes via monkeypatched os.unlink
    single = tmp_path / "single_secret.bin"
    marker = b"FORENSIC_CANARY_PLAINTEXT_8899" * 64
    single.write_bytes(marker)

    observed_before_unlink = []
    real_unlink = os.unlink

    def _spy_unlink(p):
        observed_before_unlink.append(Path(p).read_bytes())
        return real_unlink(p)

    local_vault.os.unlink = _spy_unlink
    try:
        secure_wipe_file(single)
    finally:
        local_vault.os.unlink = real_unlink

    assert not single.exists()
    assert len(observed_before_unlink) == 1
    assert b"FORENSIC_CANARY_PLAINTEXT_8899" not in observed_before_unlink[0]
    assert observed_before_unlink[0] == b"\x00" * len(marker)


def test_disappearing_messages_ttl_group_personal_and_sqlite_forensic_purge(isolated_vault_env, tmp_path):
    # 1. GroupCrypto TTL envelope roundtrip & fail-closed validation
    gc = GroupCrypto()
    sender_cm, _, sender_pub = _make_keypair()
    sk_send = gc.generate_sender_key(group_id="grp-ttl", epoch=1)
    sk_recv = dict(sk_send, skipped_keys={})

    enc = gc.encrypt_group_message(
        "Исчезающее сообщение в группе",
        sk_send,
        group_id="grp-ttl",
        sender_device_id="dev-sender",
        crypto_mgr=sender_cm,
        ttl_seconds=60,
    )
    env = gc.decrypt_group_message_envelope(
        enc,
        sk_recv,
        expected_group_id="grp-ttl",
        expected_sender_device_id="dev-sender",
        sender_public_key_b64=sender_pub,
    )
    assert env == {"text": "Исчезающее сообщение в группе", "ttl_seconds": 60}

    for bad_ttl in (True, False, 0, 4, -10, 31 * 86400, "60"):
        with pytest.raises(ValueError):
            gc.encrypt_group_message("bad", sk_send, group_id="grp-ttl", ttl_seconds=bad_ttl)  # type: ignore[arg-type]

    # 2. EncryptedHistory SQLite physical scrubbing (`PRAGMA secure_delete=ON`)
    db_path = tmp_path / "ttl_chat.sqlite"
    key32 = b"\x42" * 32
    canary = "EPHEMERAL_FORENSIC_CANARY_990011"
    now = int(time.time())
    store = EncryptedHistory.create(db_path, key32, "alice", "bob")
    assert store.append(
        {
            "msg_id": "exp-1",
            "text": canary,
            "is_mine": True,
            "is_read": True,
            "timestamp": "2026-11-05T12:00:00",
            "expires_at": now + 30,
        }
    )
    assert store.append(
        {
            "msg_id": "keep-1",
            "text": "Постоянное сообщение",
            "is_mine": False,
            "is_read": True,
            "timestamp": "2026-11-05T12:01:00",
        }
    )
    assert len(store.page().messages) == 2
    # Purge after expiration
    purged_ids = store.purge_expired(now_ts=now + 31)
    assert purged_ids == ["exp-1"]
    remaining = store.page().messages
    assert [m["msg_id"] for m in remaining] == ["keep-1"]

    # Force WAL truncate checkpoint and verify zero remnants in raw SQLite file
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
    raw_rows = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    conn.close()
    assert raw_rows == 1
    assert canary.encode("utf-8") not in db_path.read_bytes()

    # 3. Legacy `.enc` SecureStorage TTL filtering & purge_expired_messages
    _, priv_b64, _ = _make_keypair()
    SecureStorage.save_private_key("alice", priv_b64)
    SecureStorage.set_chat_ttl("alice", "bob", 60)
    assert SecureStorage.get_chat_ttl("alice", "bob") == 60

    past_exp = int(time.time()) - 5
    future_exp = int(time.time()) + 3600
    SecureStorage.save_message("alice", "bob", "Уже истекло", is_mine=True, msg_id="old_ttl", expires_at=past_exp)
    SecureStorage.save_message("alice", "bob", "Ещё живо", is_mine=True, msg_id="live_ttl", expires_at=future_exp)

    # Expired message is immediately hidden on load even before background purge runs!
    visible = SecureStorage.load_messages_strict("alice", "bob")
    assert [m["msg_id"] for m in visible] == ["live_ttl"]

    # Background purge physically removes expired entries from encrypted storage
    assert SecureStorage.purge_expired_messages("alice") == {"bob": ["old_ttl"]}
    assert SecureStorage.purge_expired_messages("alice") == {}


def test_inactivity_auto_lock_watchdog_locks_session_and_vault(isolated_vault_env, monkeypatch):
    _, priv_b64, _ = _make_keypair()
    SecureStorage.save_private_key("alice", priv_b64)
    enable_local_vault("alice", "VaultPass_AutoLock_1!", auto_lock_seconds=60, opslimit=FAST_OPS, memlimit=FAST_MEM)
    SecureStorage.set_auto_lock_seconds("alice", 60)
    assert is_vault_unlocked("alice")

    app_path = Path(__file__).resolve().parents[1] / "app/windows/app_window.py"
    tree = ast.parse(app_path.read_text(encoding="utf-8"))
    nodes = [
        n
        for cls in tree.body
        if isinstance(cls, ast.ClassDef) and cls.name == "AppWindow"
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name in {"_on_security_maintenance_tick", "_zeroize_local_vaults"}
    ]
    fake_state = SimpleNamespace(username="alice", token="jwt-live")
    env = {"state": fake_state, "storage": SecureStorage}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(app_path), "exec"), env)

    logged_out = []
    statuses = []

    class DummyWin:
        _on_security_maintenance_tick = env["_on_security_maintenance_tick"]
        _zeroize_local_vaults = env["_zeroize_local_vaults"]

        def logout_session(self):
            fake_state.token = ""
            logged_out.append(True)
            return True

        def _set_status(self, msg, is_err):
            statuses.append((msg, is_err))

    win = DummyWin()

    # Idle = 10s (< 60s): session stays unlocked
    monkeypatch.setattr(local_vault, "idle_seconds", lambda: 10.0)
    win._on_security_maintenance_tick()
    assert not logged_out and is_vault_unlocked("alice")

    # Idle = 65s (>= 60s): session auto-locks and RAM vault slot is zeroized!
    monkeypatch.setattr(local_vault, "idle_seconds", lambda: 65.0)
    win._on_security_maintenance_tick()
    assert logged_out == [True]
    assert not is_vault_unlocked("alice")
    assert statuses and "неактивности" in statuses[0][0]
