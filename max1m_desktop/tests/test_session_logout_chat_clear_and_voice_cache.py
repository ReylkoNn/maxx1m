"""Regression tests for Package #6 desktop features:
- APIClient.logout, LogoutSessionWorker token scrubbing, AppWindow.logout_session
  server-revocation worker dispatch, and SettingsScreen.request_logout_other_sessions
- MainScreen._clear_chat hygiene: cancels pending outbox + attachment_outbox + server
  upload reservations for that contact ONLY (no resurrection!), purges voice_cache
  entries and in-memory BoundedBytesCache image entries for that contact ONLY
  (leaving other contacts untouched), across both legacy JSON and migrated row-store
- Bounded VoiceCache LRU eviction (preserving legacy/unreadable entries) and
  SettingsScreen voice cache UI clear
"""
import ast
import base64
import json
import os
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import keyring
from keyring.backend import KeyringBackend
import pytest

from app import attachment_outbox, outbox, secure_storage, voice_cache as vc_mod
from app.bounded_cache import BoundedBytesCache
from app.client_api import APIClient
from app.contact_keys import fingerprint_public_key
from app.crypto_box import CryptoManager
from app.history_activation import migrate_chat
from app.recipient_context import RecipientContext, verification_scope
from app.secure_storage import SecureStorage
from app.voice_cache import VoiceCache, asset_scope, message_scope
from app.workers import LogoutSessionWorker

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


class _FakeResponse:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._raw = json.dumps(body).encode("utf-8")

    def iter_content(self, _sz=4096):
        yield self._raw

    def close(self):
        pass


def test_api_logout_worker_scrubbing_and_window_dispatch(monkeypatch):
    client = APIClient()
    calls = []

    def fake_post(url, json=None, headers=None, timeout=None, stream=None, allow_redirects=None):
        calls.append((url, json, headers, allow_redirects))
        return _FakeResponse(200, {"status": "ok", "invalidated_devices_count": 2})

    monkeypatch.setattr("app.client_api.requests.post", fake_post)
    assert client.logout("https://relay", "tok", include_other_devices=True, only_other_devices=True)[0] is False
    ok, data = client.logout("https://relay/", "tok-secret", only_other_devices=True)
    assert ok is True
    assert data == {"status": "ok", "invalidated_devices_count": 2}
    assert calls == [
        (
            "https://relay/auth/logout",
            {"include_other_devices": False, "only_other_devices": True},
            {"Authorization": "Bearer tok-secret"},
            False,
        )
    ]

    # LogoutSessionWorker scrubs self.token after run()
    monkeypatch.setattr("app.workers.api", client)
    worker = LogoutSessionWorker("https://relay", "tok-secret", only_other_devices=True)
    emitted = []
    worker.finished.connect(lambda ok_flag, payload: emitted.append((ok_flag, payload)))
    worker.run()
    assert emitted == [(True, {"status": "ok", "invalidated_devices_count": 2})]
    assert worker.token == ""

    # AppWindow.logout_session dispatches LogoutSessionWorker with captured token before wiping state.token
    dispatched = []

    class _LogoutStub:
        def __init__(self, srv, tok):
            self.srv = srv
            self.tok = tok
            self.finished = SimpleNamespace(connect=lambda *_a: None)

        def start(self):
            dispatched.append((self.srv, self.tok))

    st = SimpleNamespace(
        username="alice",
        server_url="https://relay.example",
        device_id="alice-dev",
        device_name="Alice PC",
        token="jwt-to-revoke",
        current_chat_username="bob",
        current_chat_device_id="bob-dev",
        current_group_id=None,
        current_chat_type="ally",
        allies={"bob": {}},
        groups={},
    )
    cr = CryptoManager()
    cr.generate_new_keypair()
    methods = _extract_methods(
        "app/windows/app_window.py",
        "AppWindow",
        ["logout_session"],
        {
            "state": st,
            "storage": SimpleNamespace(save_profile_device=None),
            "crypto": cr,
            "rtc": SimpleNamespace(end_call=lambda: None),
            "LogoutSessionWorker": _LogoutStub,
            "QMessageBox": SimpleNamespace(warning=lambda *_a: None),
        },
    )
    win = SimpleNamespace(
        worker=None,
        main_screen=None,
        sync_worker=None,
        _ack_worker=None,
        groups_fetch_worker=None,
        _sync_timer=None,
        ws_worker=None,
        _logout_workers=[],
    )
    assert methods["logout_session"](win) is True
    assert st.token == ""
    assert dispatched == [("https://relay.example", "jwt-to-revoke")]


def test_clear_chat_cancels_queues_and_purges_caches_for_target_contact_only(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    kr = _MemKeyring()
    keyring.set_keyring(kr)

    alice = CryptoManager()
    alice.generate_new_keypair()
    bob = CryptoManager()
    bob.generate_new_keypair()
    carol = CryptoManager()
    carol.generate_new_keypair()
    bob_pub = bob.get_public_key_b64()
    carol_pub = carol.get_public_key_b64()

    ctx_bob = RecipientContext("bob", "bob-dev", bob_pub, "alice", "alice-dev", "https://relay.example")
    ctx_carol = RecipientContext("carol", "carol-dev", carol_pub, "alice", "alice-dev", "https://relay.example")

    # Populate messages for both bob (migrated SQLite row-store!) and carol (legacy JSON)
    SecureStorage.save_message("alice", "bob", "bob voice", is_mine=False, msg_id="bob-m1")
    assert migrate_chat("alice", "bob") is True
    SecureStorage.save_message("alice", "carol", "carol voice", is_mine=False, msg_id="carol-m1")

    assert SecureStorage.list_message_ids("alice", "bob") == ["bob-m1"]
    assert SecureStorage.list_message_ids("alice", "carol") == ["carol-m1"]

    # Populate voice cache for both bob and carol
    vcache = VoiceCache(tmp_path / "vcache")
    bob_vscope = message_scope("alice", "https://relay.example", "bob", "bob-m1")
    carol_vscope = message_scope("alice", "https://relay.example", "carol", "carol-m1")
    asset = asset_scope("fid-1", "skey-1")
    assert vcache.save(bob_vscope, asset, b"RIFF-bob")
    assert vcache.save(carol_vscope, asset, b"RIFF-carol")

    # Populate image cache for both bob and carol
    icache = BoundedBytesCache(1024 * 1024)
    bob_ikey = ("alice", "alice-dev", "https://relay.example", "bob", "img-1", "k1")
    carol_ikey = ("alice", "alice-dev", "https://relay.example", "carol", "img-2", "k2")
    icache[bob_ikey] = b"bob-pixels"
    icache[carol_ikey] = b"carol-pixels"

    # Enqueue outbox + attachment_outbox for BOTH bob and carol
    bob_fid = str(uuid.uuid4())
    carol_fid = str(uuid.uuid4())
    bob_env = alice.encrypt_message(json.dumps({"type": "text", "text": "q-bob", "msg_id": "bob-q1"}), bob_pub)
    carol_env = alice.encrypt_message(json.dumps({"type": "text", "text": "q-carol", "msg_id": "carol-q1"}), carol_pub)
    outbox.enqueue(
        "alice", "https://relay.example", "alice-dev",
        {"receiver_device_id": "bob-dev", **bob_env},
        local_history={"ally_username": "bob", "text": "q-bob", "msg_id": "bob-q1"},
    )
    outbox.enqueue(
        "alice", "https://relay.example", "alice-dev",
        {"receiver_device_id": "carol-dev", **carol_env},
        local_history={"ally_username": "carol", "text": "q-carol", "msg_id": "carol-q1"},
    )
    attachment_outbox.enqueue(
        ctx_bob, b"bob-blob", bob_fid, str(uuid.uuid4()),
        {"receiver_device_id": "bob-dev", **bob_env},
        {"ally_username": "bob", "text": f"[IMAGE_META]|{bob_fid}|k|", "msg_id": "bob-att1"},
    )
    attachment_outbox.enqueue(
        ctx_carol, b"carol-blob", carol_fid, str(uuid.uuid4()),
        {"receiver_device_id": "carol-dev", **carol_env},
        {"ally_username": "carol", "text": f"[IMAGE_META]|{carol_fid}|k|", "msg_id": "carol-att1"},
    )

    st = SimpleNamespace(
        username="alice",
        server_url="https://relay.example",
        device_id="alice-dev",
        token="tok",
        current_chat_type="ally",
        current_group_id=None,
        current_chat_username="bob",
        allies={
            "bob": {"devices": [{"device_id": "bob-dev"}]},
            "carol": {"devices": [{"device_id": "carol-dev"}]},
        },
    )
    cancelled_reservations = []
    methods = _extract_methods(
        "app/windows/main_screen.py",
        "MainScreen",
        ["_clear_chat"],
        {
            "state": st,
            "storage": SecureStorage,
            "outbox": outbox,
            "attachment_outbox": attachment_outbox,
            "voice_cache": vcache,
            "message_scope": message_scope,
            "QMessageBox": SimpleNamespace(warning=lambda *_a: None),
        },
    )
    screen = SimpleNamespace(
        _outbox_worker=None,
        _net_workers=[],
        _outbox_skipped=set(),
        _attachment_skipped=set(),
        _attachment_retry_after={},
        _image_cache=icache,
        _history_offset=3,
        _history_query="q",
        _render_history_page=lambda: None,
        _get_ally_card=lambda _u: None,
        _dispatch_cancel_upload_reservations=lambda fids: cancelled_reservations.extend(fids),
    )

    methods["_clear_chat"](screen)

    # Bob's history, queues, voice cache, and image cache are completely purged!
    assert SecureStorage.load_messages_strict("alice", "bob") == []
    assert cancelled_reservations == [bob_fid]
    assert vcache.load(bob_vscope, asset) is None
    assert bob_ikey not in icache

    # Carol's history, queues, voice cache, and image cache are 100% preserved!
    assert len(SecureStorage.load_messages_strict("alice", "carol")) == 1
    assert len(outbox.pending_paths("alice", "https://relay.example", "alice-dev")) == 1
    assert [p.stem for p in attachment_outbox.pending_job_paths("alice", "https://relay.example", "alice-dev")] == [carol_fid]
    assert vcache.load(carol_vscope, asset) == b"RIFF-carol"
    assert icache[carol_ikey] == b"carol-pixels"


def test_bounded_voice_cache_lru_preserves_legacy_and_settings_ui_clear(tmp_path, monkeypatch):
    kr = _MemKeyring()
    keyring.set_keyring(kr)

    cache_dir = tmp_path / "bounded_voice"
    cache_dir.mkdir()
    cache = VoiceCache(cache_dir, max_entries=2)

    g1 = message_scope("alice", "https://s", "bob", "m1")
    g2 = message_scope("alice", "https://s", "bob", "m2")
    g3 = message_scope("alice", "https://s", "bob", "m3")
    a = asset_scope("f", "k")

    assert cache.save(g1, a, b"wav-1")
    # Place a legacy unscoped file and a corrupt v2 file AFTER key initialization:
    # eviction MUST NOT delete either of them!
    legacy_file = cache_dir / "legacy_unscoped.bin"
    legacy_file.write_bytes(b"legacy-offline-entry")
    corrupt_v2 = cache_dir / f"v2_{'0' * 64}_{'1' * 64}.bin"
    corrupt_v2.write_bytes(b"unreadable-or-old-key-entry")

    p1 = cache_dir / f"v2_{g1}_{a}.bin"
    os.utime(p1, (1000, 1000))

    assert cache.save(g2, a, b"wav-2")
    p2 = cache_dir / f"v2_{g2}_{a}.bin"
    os.utime(p2, (2000, 2000))

    # Touch g1 via load() so g1 becomes newer than g2!
    assert cache.load(g1, a) == b"wav-1"

    # Saving g3 exceeds max_entries=2 -> evicts g2 (oldest readable v2), keeping g1, g3, legacy, and corrupt_v2!
    assert cache.save(g3, a, b"wav-3")
    assert cache.load(g1, a) == b"wav-1"
    assert cache.load(g2, a) is None
    assert cache.load(g3, a) == b"wav-3"
    assert legacy_file.exists()
    assert corrupt_v2.exists()

    # SettingsScreen clear_voice_cache UI flow clears all *.bin on explicit confirmation
    methods = _extract_methods(
        "app/windows/settings_screen.py",
        "SettingsScreen",
        ["refresh_voice_cache_info", "_on_clear_voice_cache_clicked"],
        {
            "voice_cache": cache,
            "QMessageBox": SimpleNamespace(
                Yes=1,
                No=2,
                question=lambda *_a, **_kw: 1,
                warning=lambda *_a: None,
            ),
        },
    )
    lbl_texts = []
    settings_stub = SimpleNamespace(
        _voice_cache_size_value=SimpleNamespace(setText=lambda t: lbl_texts.append(t)),
    )
    settings_stub.refresh_voice_cache_info = methods["refresh_voice_cache_info"].__get__(settings_stub)
    assert methods["_on_clear_voice_cache_clicked"](settings_stub) is True
    assert list(cache_dir.glob("*.bin")) == []
    assert lbl_texts[-1] == "0.0 МБ"
