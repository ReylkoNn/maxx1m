import ast
import json
from pathlib import Path
from types import SimpleNamespace

import keyring
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
import pytest

from app import identity_setup, secure_storage
from app.crypto_box import CryptoManager
from app.secure_storage import SecureStorage
from app.state import state


DESKTOP_ROOT = Path(__file__).resolve().parents[1]


def _extract_app_window_methods(names: list[str], env: dict):
    path = DESKTOP_ROOT / "app/windows/app_window.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    nodes = [
        node
        for cls in tree.body
        if isinstance(cls, ast.ClassDef) and cls.name == "AppWindow"
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    assert len(nodes) == len(names)
    compiled = compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), "exec")
    exec(compiled, env)
    return {name: env[name] for name in names}


class _MemKeyring(KeyringBackend):
    priority = 10

    def __init__(self):
        self.data = {}

    def get_password(self, service, username):
        return self.data.get((service, username))

    def set_password(self, service, username, password):
        self.data[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.data:
            raise PasswordDeleteError(username)
        del self.data[(service, username)]


@pytest.fixture
def isolated_storage(tmp_path, monkeypatch):
    kr = _MemKeyring()
    keyring.set_keyring(kr)
    base = tmp_path / ".max1m"
    monkeypatch.setattr(secure_storage, "BASE_DIR", base)
    monkeypatch.setattr(secure_storage, "CONFIG_FILE", base / "local_state.json")
    old = (
        state.server_url,
        state.username,
        state.device_name,
        state.device_id,
        state.token,
        dict(state.allies),
        dict(state.groups),
    )
    yield base, kr
    (
        state.server_url,
        state.username,
        state.device_name,
        state.device_id,
        state.token,
        allies_copy,
        groups_copy,
    ) = old
    state.allies = allies_copy
    state.groups = groups_copy


def test_encrypted_allies_authenticates_blocks_downgrade_and_cross_profile_swap(isolated_storage):
    contacts = {
        "bob": {
            "user_id": "u-bob",
            "devices": [{"device_id": "bob-d1", "public_key": "pk-bob", "fingerprint": "FP:BOB"}],
            "verified_scopes": {"scope1": ["FP:BOB"]},
        }
    }
    SecureStorage.save_allies("alice", contacts)

    enc_path = SecureStorage._get_encrypted_allies_file("alice")
    legacy_path = SecureStorage._get_allies_file("alice")
    assert enc_path.is_file()
    assert not legacy_path.exists()
    assert b"bob" not in enc_path.read_bytes()
    assert b"FP:BOB" not in enc_path.read_bytes()
    assert SecureStorage.load_allies("alice") == contacts

    # Writing an unauthenticated allies.json alongside allies.enc MUST be ignored (no downgrade).
    legacy_path.write_text(json.dumps({"mallory": {"devices": []}}), encoding="utf-8")
    assert SecureStorage.load_allies("alice") == contacts

    # Copying alice's allies.enc to bob's profile fails closed (domain/key separation).
    bob_key = SecureStorage._get_or_create_local_key("bob")
    bob_enc = SecureStorage._get_encrypted_allies_file("bob")
    bob_enc.write_bytes(enc_path.read_bytes())
    with pytest.raises(ValueError, match="Invalid contact store"):
        SecureStorage.load_allies("bob")

    # Even encrypting an owner="alice" record under bob's own SecretBox key fails owner check!
    import nacl.secret
    bob_box = nacl.secret.SecretBox(bob_key)
    forged = bob_box.encrypt(json.dumps({"version": 1, "owner": "alice", "allies": contacts}).encode())
    bob_enc.write_bytes(forged)
    with pytest.raises(ValueError, match="Invalid contact store"):
        SecureStorage.load_allies("bob")

    # Corrupting allies.enc blocks both load_allies and save_allies without overwriting.
    raw = bytearray(enc_path.read_bytes())
    raw[-1] ^= 0xFF
    enc_path.write_bytes(bytes(raw))
    with pytest.raises(ValueError, match="Invalid contact store"):
        SecureStorage.load_allies("alice")
    with pytest.raises(ValueError, match="Invalid contact store"):
        SecureStorage.save_allies("alice", {})

    # Missing keyring key while allies.enc exists fails closed instead of generating a new key.
    keyring.delete_password("Max1m_Secure_Messenger", "alice_local_storage_key")
    with pytest.raises(ValueError, match="key is missing"):
        SecureStorage._get_or_create_local_key("alice")


def test_legacy_allies_json_reads_and_upgrades_to_encrypted_without_deleting_backup(isolated_storage):
    legacy_path = SecureStorage._get_allies_file("alice")
    legacy_contacts = {"charlie": {"devices": [{"device_id": "d1"}]}}
    legacy_path.write_text(json.dumps(legacy_contacts), encoding="utf-8")

    assert SecureStorage.load_allies("alice") == legacy_contacts

    updated = {**legacy_contacts, "dave": {"devices": [{"device_id": "d2"}]}}
    SecureStorage.save_allies("alice", updated)

    assert SecureStorage._get_encrypted_allies_file("alice").is_file()
    # Non-destructive: legacy backup file remains untouched on disk, while reads use allies.enc.
    assert json.loads(legacy_path.read_text(encoding="utf-8")) == legacy_contacts
    assert SecureStorage.load_allies("alice") == updated


def test_multiaccount_switch_preserves_device_id_and_blocks_server_mismatch(isolated_storage):
    alice_crypto = CryptoManager()
    alice_crypto.generate_new_keypair()
    bob_crypto = CryptoManager()
    bob_crypto.generate_new_keypair()

    SecureStorage.save_private_key("alice", alice_crypto.get_private_key_b64())
    SecureStorage.save_profile_device(
        "alice", "https://relay-one.example", "alice-dev-1", "Alice Laptop", alice_crypto.get_public_key_b64()
    )
    SecureStorage.save_private_key("bob", bob_crypto.get_private_key_b64())
    SecureStorage.save_profile_device(
        "bob", "https://relay-one.example", "bob-dev-1", "Bob Laptop", bob_crypto.get_public_key_b64()
    )

    # Simulate Bob having been the most recent user in global state & local_state.json
    SecureStorage.save_local_state({
        "server_url": "https://relay-one.example",
        "username": "bob",
        "device_name": "Bob Laptop",
        "device_id": "bob-dev-1",
    })
    state.server_url = "https://relay-one.example"
    state.username = "bob"
    state.device_id = "bob-dev-1"
    state.device_name = "Bob Laptop"

    started_workers = []
    statuses = []

    class _DummyLoginWorker:
        def __init__(self, server_url, payload):
            self.server_url = server_url
            self.payload = payload
            self.finished = SimpleNamespace(connect=lambda *_a: None)

        def start(self):
            started_workers.append((self.server_url, dict(self.payload), self.auth_context))

    active_crypto = CryptoManager()
    env = {
        "state": state,
        "storage": SecureStorage,
        "crypto": active_crypto,
        "identity_setup": identity_setup,
        "LoginWorker": _DummyLoginWorker,
    }
    methods = _extract_app_window_methods(["_start_login"], env)

    win = SimpleNamespace(
        submit_button=SimpleNamespace(setEnabled=lambda _v: None),
        stack=SimpleNamespace(setCurrentWidget=lambda _w: None),
        loading_screen=SimpleNamespace(set_status=lambda *_a: None),
        _update_auth_animation_state=lambda: None,
        _set_status=lambda msg, err: statuses.append((msg, err)),
        _on_login_finished=lambda *_a: None,
    )

    # 1. Wrong server URL for Alice's bound profile -> blocked BEFORE network call!
    methods["_start_login"](win, "https://evil-relay.example", "alice", "Pass123!", "Alice Laptop")
    assert started_workers == []
    assert statuses and statuses[-1][1] is True
    assert "другому серверу" in statuses[-1][0]

    # 2. Matching server URL for Alice -> reuses alice-dev-1 cleanly even though state had Bob!
    methods["_start_login"](win, "https://relay-one.example/", "alice", "Pass123!", "Alice Laptop")
    assert len(started_workers) == 1
    srv, payload, auth_ctx = started_workers[0]
    assert payload == {
        "username": "alice",
        "password": "Pass123!",
        "device_id": "alice-dev-1",
    }
    assert auth_ctx[4] == "alice-dev-1"
    assert active_crypto.get_public_key_b64() == alice_crypto.get_public_key_b64()


def test_logout_session_clears_sensitive_memory_and_keeps_profile_device_bound(isolated_storage):
    alice_crypto = CryptoManager()
    alice_crypto.generate_new_keypair()
    SecureStorage.save_private_key("alice", alice_crypto.get_private_key_b64())

    state.server_url = "https://relay.example"
    state.username = "alice"
    state.device_name = "Alice PC"
    state.device_id = "alice-dev-77"
    state.token = "secret-jwt-token"
    state.allies = {"bob": {"devices": []}}
    state.groups = {"grp-1": {"name": "Team"}}

    events = []
    env = {
        "state": state,
        "storage": SecureStorage,
        "crypto": alice_crypto,
        "rtc": SimpleNamespace(end_call=lambda: events.append("rtc_end_call")),
        "QMessageBox": SimpleNamespace(warning=lambda *_a: events.append("warn")),
    }
    methods = _extract_app_window_methods(["logout_session"], env)

    pwd_cleared = []
    win = SimpleNamespace(
        worker=None,
        sync_worker=None,
        _ack_worker=None,
        groups_fetch_worker=None,
        _sync_timer=SimpleNamespace(stop=lambda: events.append("sync_timer_stop")),
        ws_worker=SimpleNamespace(
            stop=lambda: events.append("ws_stop"),
            wait=lambda _ms: events.append("ws_wait"),
        ),
        main_screen=SimpleNamespace(
            _net_workers=[],
            find_worker=None,
            _outbox_worker=None,
            settings_screen=None,
            _media_queue=SimpleNamespace(active=False),
            _history_worker=None,
            _is_recording=False,
            _voice_thread=None,
            _voice_playback=None,
            _in_call=False,
            reset_session_view=lambda: events.append("reset_view"),
        ),
        password_block={"input": SimpleNamespace(clear=lambda: pwd_cleared.append(True))},
        stack=SimpleNamespace(setCurrentWidget=lambda _w: events.append("show_auth")),
        auth_screen=object(),
        _set_mode=lambda m: events.append(("mode", m)),
        _update_auth_animation_state=lambda: None,
        _set_status=lambda msg, err: events.append(("status", msg, err)),
    )

    assert methods["logout_session"](win) is True
    assert state.token == ""
    assert state.allies == {}
    assert state.groups == {}
    assert alice_crypto.private_key is None
    assert alice_crypto.public_key is None
    assert pwd_cleared == [True]
    assert "ws_stop" in events and "reset_view" in events and "show_auth" in events

    # Profile device binding was backfilled into device_identity.enc before clearing memory!
    saved_dev = SecureStorage.load_profile_device("alice")
    assert saved_dev["device_id"] == "alice-dev-77"
    assert saved_dev["server_url"] == "https://relay.example"
