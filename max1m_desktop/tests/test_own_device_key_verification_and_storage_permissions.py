"""Regression tests for Package #8 desktop features:
- Zero-trust own-device public-key pinning & local SHA-256 fingerprint recomputation in APIClient / SettingsScreen
- Universal Bearer-token cleartext remote HTTP blocking across all APIClient methods and WebSocketWorker
- POSIX 0o700/0o600 storage permissions, fail-closed load_local_state + crash-safe startup, and call_envelope depth/NaN limits
"""
import ast
import json
import os
import stat
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import attachment_outbox, call_envelope, identity_setup, outbox, secure_storage, workers
from app.client_api import APIClient
from app.contact_keys import fingerprint_public_key, safe_local_fingerprint
from app.crypto_box import CryptoManager


def _extract_methods(rel_path: str, class_name: str, names: list[str], env: dict):
    path = Path(__file__).resolve().parents[1] / rel_path
    tree = ast.parse(path.read_text(encoding="utf-8"))
    nodes = [
        n
        for cls in tree.body
        if isinstance(cls, ast.ClassDef) and cls.name == class_name
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name in names
    ]
    assert len(nodes) == len(names)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), "exec"), env)
    return {name: env[name] for name in names}


def test_own_devices_verifies_current_public_key_and_recomputes_local_fingerprints(monkeypatch):
    my_crypto = CryptoManager()
    my_crypto.generate_new_keypair()
    my_pub = my_crypto.get_public_key_b64()
    my_real_fp = fingerprint_public_key(my_pub)

    rogue_crypto = CryptoManager()
    rogue_crypto.generate_new_keypair()
    rogue_pub = rogue_crypto.get_public_key_b64()
    rogue_real_fp = fingerprint_public_key(rogue_pub)
    forged_fp = "0000:1111:2222:3333:4444:5555:6666:7777"
    assert forged_fp not in (my_real_fp, rogue_real_fp)

    client = APIClient()

    def _resp(payload):
        raw = json.dumps(payload).encode("utf-8")
        return SimpleNamespace(
            status_code=200,
            iter_content=lambda _n: [raw],
            close=lambda: None,
        )

    # 1. Compromised server substituting current device's public_key is rejected when expected_public_key is pinned
    substituted_payload = [
        {
            "id": "dev-me",
            "device_name": "My Desktop",
            "public_key": rogue_pub,
            "fingerprint": rogue_real_fp,
            "is_current": True,
            "is_revoked": False,
        }
    ]
    monkeypatch.setattr("app.client_api.requests.get", lambda *a, **kw: _resp(substituted_payload))
    ok_sub, _ = client.list_own_devices(
        "https://relay.example.test",
        "tok",
        expected_device_id="dev-me",
        expected_public_key=my_pub,
    )
    assert ok_sub is False

    # 2. Rogue secondary device claiming a forged fingerprint is overwritten with true SHA-256(public_key) + flagged
    spoofed_fp_payload = [
        {
            "id": "dev-me",
            "device_name": "My Desktop",
            "public_key": my_pub,
            "fingerprint": my_real_fp,
            "is_current": True,
            "is_revoked": False,
        },
        {
            "id": "dev-rogue",
            "device_name": "My Phone",
            "public_key": rogue_pub,
            "fingerprint": forged_fp,
            "is_current": False,
            "is_revoked": False,
        },
    ]
    monkeypatch.setattr("app.client_api.requests.get", lambda *a, **kw: _resp(spoofed_fp_payload))
    ok_list, cleaned = client.list_own_devices(
        "https://relay.example.test",
        "tok",
        expected_device_id="dev-me",
        expected_public_key=my_pub,
    )
    assert ok_list is True
    assert cleaned[0]["fingerprint"] == my_real_fp
    assert not cleaned[0].get("server_fingerprint_mismatch")
    assert cleaned[1]["fingerprint"] == rogue_real_fp
    assert cleaned[1]["fingerprint"] != forged_fp
    assert cleaned[1].get("server_fingerprint_mismatch") is True

    # 3. SettingsScreen renders locally computed fingerprint + mismatch warning and triggers lockdown on HTTP 401
    class _Lbl:
        def __init__(self, text=""):
            self.text = text
            self.tooltip = ""

        def setText(self, t):
            self.text = t

        def setObjectName(self, _n):
            pass

        def setWordWrap(self, _w):
            pass

        def setToolTip(self, t):
            self.tooltip = t

        def setTextInteractionFlags(self, _f):
            pass

    class _Btn:
        def __init__(self, text=""):
            self.text = text
            self.clicked = SimpleNamespace(connect=lambda fn: setattr(self, "_fn", fn))

        def setObjectName(self, _n):
            pass

        def setFocusPolicy(self, _p):
            pass

        def setEnabled(self, _v):
            pass

    class _Frame:
        def __init__(self):
            self.widgets = []

        def setObjectName(self, _n):
            pass

        def deleteLater(self):
            pass

    class _RowLayout:
        def __init__(self, frame):
            self.frame = frame

        def setContentsMargins(self, *_a):
            pass

        def setSpacing(self, _s):
            pass

        def addWidget(self, w, *_a):
            self.frame.widgets.append(w)

    class _ListLayout:
        def __init__(self):
            self.items = []

        def count(self):
            return len(self.items)

        def takeAt(self, idx):
            frame = self.items.pop(idx)
            return SimpleNamespace(widget=lambda: frame)

        def addWidget(self, w):
            self.items.append(w)

    prompts = []
    invalidations = []
    spawned_workers = []

    class _FakeListWorker:
        def __init__(self, server_url, token, expected_device_id=None, expected_public_key=None):
            self.server_url = server_url
            self.token = token
            self.expected_device_id = expected_device_id
            self.expected_public_key = expected_public_key
            self.finished = SimpleNamespace(connect=lambda *_a: None)
            spawned_workers.append(self)

        def isRunning(self):
            return False

        def start(self):
            pass

        def wait(self):
            pass

    st = SimpleNamespace(
        username="alice",
        server_url="https://relay.example.test",
        device_id="dev-me",
        token="tok",
    )
    env = {
        "state": st,
        "crypto": my_crypto,
        "safe_local_fingerprint": safe_local_fingerprint,
        "QFrame": _Frame,
        "QHBoxLayout": _RowLayout,
        "QLabel": _Lbl,
        "QPushButton": _Btn,
        "Qt": SimpleNamespace(NoFocus=0, TextSelectableByMouse=1, QueuedConnection=1),
        "QMessageBox": SimpleNamespace(
            Yes=1,
            No=2,
            question=lambda _s, _title, body, *_a: prompts.append(body) or 2,
        ),
        "ListOwnDevicesWorker": _FakeListWorker,
        "RevokeDeviceWorker": workers.RevokeDeviceWorker,
    }
    SettingsCls = type(
        "SettingsCls",
        (),
        _extract_methods(
            "app/windows/settings_screen.py",
            "SettingsScreen",
            [
                "_current_account_context",
                "_clear_devices_rows",
                "_render_own_devices",
                "request_devices_refresh",
                "_on_own_devices_loaded",
                "_confirm_and_revoke_device",
            ],
            env,
        ),
    )
    s_view = SettingsCls()
    s_view._net_workers = []
    s_view._devices_account_context = None
    s_view._own_devices = []
    s_view._devices_list_layout = _ListLayout()
    s_view._devices_status_label = _Lbl()
    s_view.refresh_devices_btn = _Btn()
    s_view.window = lambda: SimpleNamespace(
        _handle_remote_session_invalidated=lambda reason: invalidations.append(reason)
    )

    assert s_view.request_devices_refresh() is True
    assert spawned_workers[0].expected_public_key == my_pub

    # Render even if raw server payload had forged_fp directly
    s_view._render_own_devices(spoofed_fp_payload)
    rogue_row_lbl = s_view._devices_list_layout.items[1].widgets[0]
    assert rogue_real_fp[:24] in rogue_row_lbl.text
    assert forged_fp[:12] not in rogue_row_lbl.text
    assert "подменён отпечаток сервера" in rogue_row_lbl.text

    # Confirm dialog also shows locally computed rogue_real_fp, never forged_fp
    s_view._confirm_and_revoke_device(spoofed_fp_payload[1])
    assert prompts and rogue_real_fp in prompts[0] and forged_fp not in prompts[0]

    # HTTP 401 on _on_own_devices_loaded triggers remote session invalidation on parent window
    w401 = spawned_workers[0]
    w401.account_context = ("alice", "https://relay.example.test", "dev-me", "tok")
    s_view._on_own_devices_loaded(False, "HTTP 401: не удалось получить список устройств", w401)
    assert len(invalidations) == 1


def test_all_bearer_endpoints_and_websocket_block_remote_cleartext_http(monkeypatch):
    monkeypatch.delenv("MAX1M_ALLOW_INSECURE_HTTP", raising=False)
    monkeypatch.setattr(
        "app.client_api.requests.get",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("unexpected GET over HTTP")),
    )
    monkeypatch.setattr(
        "app.client_api.requests.post",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("unexpected POST over HTTP")),
    )
    monkeypatch.setattr(
        "app.client_api.requests.delete",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("unexpected DELETE over HTTP")),
    )

    client = APIClient()
    insecure = "http://remote-relay.example.net:8000"
    fid = str(uuid.uuid4())

    assert client.find_user(insecure, "tok", "bob")[0] is False
    assert client.list_own_devices(insecure, "tok")[0] is False
    assert client.revoke_own_device(insecure, "tok", "dev-2")[0] is False
    assert client.cancel_upload_reservation(insecure, "tok", fid)[0] is False
    assert client.send_message(insecure, "tok", {"encrypted_blob": "a", "signature": "b"})[0] is False
    assert client.send_reliable_message(insecure, "tok", {"client_message_id": fid})[0] is False
    assert client.upload_file(insecure, "tok", b"cipher")[0] is False
    assert client.upload_file_reliable(insecure, "tok", fid, b"cipher")[0] is False
    assert client.download_file(insecure, "tok", fid)[0] is False
    assert client.grant_file_access(insecure, "tok", fid, "dev-2")[0] is False

    with pytest.raises(ValueError):
        workers.WebSocketWorker(insecure, "tok", "dev-1")


def test_posix_permissions_fail_closed_local_state_and_call_envelope_depth(tmp_path, monkeypatch):
    base_dir = tmp_path / "max1m_home"
    cfg_file = base_dir / "local_state.json"
    monkeypatch.setattr(secure_storage, "BASE_DIR", base_dir)
    monkeypatch.setattr(secure_storage, "CONFIG_FILE", cfg_file)

    keyring_mem: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(
        secure_storage.keyring,
        "get_password",
        lambda svc, key: keyring_mem.get((svc, key)),
    )
    monkeypatch.setattr(
        secure_storage.keyring,
        "set_password",
        lambda svc, key, val: keyring_mem.__setitem__((svc, key), val),
    )

    store = secure_storage.SecureStorage
    store.save_local_state({"username": "alice", "server_url": "https://node.test", "device_id": "dev-a"})
    store.save_allies("alice", {})
    msg_file = store._get_messages_file("alice", "bob")
    store.save_message("alice", "bob", "m1", "hi", True)

    msg_id = str(uuid.uuid4())
    outbox.enqueue(
        "alice",
        "https://node.test",
        "dev-a",
        {
            "client_message_id": msg_id,
            "receiver_device_id": "dev-b",
            "encrypted_blob": "blob",
            "signature": "sig",
        },
        message_id=msg_id,
    )
    att_dir = attachment_outbox._dir("alice", "https://node.test", "dev-a")
    call_id = str(uuid.uuid4())
    assert call_envelope.remember_offer("alice", "https://node.test", "dev-a", "dev-b", call_id, now=1700000000) is True

    if os.name != "nt":
        for d in (
            base_dir,
            base_dir / "profiles",
            base_dir / "profiles" / "alice",
            msg_file.parent,
            att_dir.parent,
            att_dir,
        ):
            mode = stat.S_IMODE(d.stat().st_mode)
            assert mode == 0o700, f"expected 0o700 for {d}, got {oct(mode)}"

        assert stat.S_IMODE(cfg_file.stat().st_mode) == 0o600
        replay_files = list(att_dir.parent.parent.glob("*-call-replay.enc"))
        assert len(replay_files) == 1
        assert stat.S_IMODE(replay_files[0].stat().st_mode) == 0o600

    # Fail-closed load_local_state on corrupted / non-dict JSON blocks prepare_new_identity overwrite,
    # while AppWindow._load_local_state_on_startup handles it gracefully without crashing.
    cfg_file.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        store.load_local_state()

    fresh_crypto = CryptoManager()
    with pytest.raises(ValueError):
        identity_setup.prepare_new_identity("charlie", "https://node.test", "register", fresh_crypto)

    startup_statuses = []
    startup_env = {
        "storage": store,
        "state": SimpleNamespace(),
        "DEFAULT_SERVER_URL": "http://127.0.0.1:8000",
    }
    startup_fn = _extract_methods(
        "app/windows/app_window.py",
        "AppWindow",
        ["_load_local_state_on_startup"],
        startup_env,
    )["_load_local_state_on_startup"]
    win_stub = SimpleNamespace(_set_status=lambda msg, err: startup_statuses.append((msg, err)))
    startup_fn(win_stub)
    assert len(startup_statuses) == 1 and startup_statuses[0][1] is True

    # call_envelope.open_envelope rejects overly deep nested JSON and NaN in encrypted signaling content
    alice_c = CryptoManager()
    alice_c.generate_new_keypair()
    bob_c = CryptoManager()
    bob_c.generate_new_keypair()
    now = int(time.time())

    deep_content: list | str = "leaf"
    for _ in range(25):
        deep_content = [deep_content]
    deep_env = call_envelope.seal(
        alice_c,
        "webrtc_signal",
        "dev-alice",
        "dev-bob",
        str(uuid.uuid4()),
        bob_c.get_public_key_b64(),
        content={"sdp": deep_content},
        now=now,
    )
    deep_env["from_device_id"] = "dev-alice"
    with pytest.raises(ValueError):
        call_envelope.open_envelope(bob_c, deep_env, "dev-bob", alice_c.get_public_key_b64(), now=now)
