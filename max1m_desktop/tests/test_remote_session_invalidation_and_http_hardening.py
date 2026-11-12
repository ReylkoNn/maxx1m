"""Regression tests for Package #7 desktop features:
- Automatic remote session invalidation lockdown (WS 1008 / 401/403 -> auth_check -> HTTP 401/403 -> lock & wipe RAM)
- Cleartext remote HTTP server_url guard (validate_server_url, APIClient auth methods, AppWindow._submit)
- Redirect blocking, bounded JSON parsing, path-traversal ID validation, and post-run token scrubbing across workers
"""
import ast
import asyncio
import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import websockets

from app import workers
from app.client_api import APIClient, validate_server_url
from app.delivery import process_delivery_page


def _extract_app_window_methods(names: list[str], env: dict):
    path = Path(__file__).resolve().parents[1] / "app/windows/app_window.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    nodes = [
        n
        for cls in tree.body
        if isinstance(cls, ast.ClassDef) and cls.name == "AppWindow"
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name in names
    ]
    assert len(nodes) == len(names)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), "exec"), env)
    return {name: env[name] for name in names}


def test_websocket_worker_emits_auth_check_on_1008_and_403_and_scrubs_token(monkeypatch):
    # Invalid device_id rejected before constructing ws_url
    with pytest.raises(ValueError):
        workers.WebSocketWorker("https://example.test", "secret.jwt", "../escape")

    # 1. Close code 1008 emits ("disconnected", "auth_check") and backs off >= 5s
    ws_worker = workers.WebSocketWorker("https://example.test", "secret.jwt", "dev-ok-1")
    statuses = []
    sleeps = []
    ws_worker.connection_status.connect(lambda s: statuses.append(s))

    class Closed1008Conn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def recv(self):
            close_frame = websockets.frames.Close(1008, "policy")
            raise websockets.exceptions.ConnectionClosedError(close_frame, None)

    async def fake_sleep(delay):
        sleeps.append(delay)
        ws_worker._is_running = False

    monkeypatch.setattr(workers.websockets, "connect", lambda *a, **kw: Closed1008Conn())
    monkeypatch.setattr(workers.asyncio, "sleep", fake_sleep)
    asyncio.run(ws_worker._connect_loop())

    assert "disconnected" in statuses
    assert "auth_check" in statuses
    assert sleeps and sleeps[0] >= 5.0

    # 2. HTTP 403 handshake failure also emits "auth_check"
    ws_worker2 = workers.WebSocketWorker("https://example.test", "secret2.jwt", "dev-ok-2")
    statuses2 = []
    ws_worker2.connection_status.connect(lambda s: statuses2.append(s))

    class Handshake403Error(Exception):
        status_code = 403

    def reject_403(*a, **kw):
        raise Handshake403Error("HTTP 403")

    async def stop_sleep(_delay):
        ws_worker2._is_running = False

    monkeypatch.setattr(workers.websockets, "connect", reject_403)
    monkeypatch.setattr(workers.asyncio, "sleep", stop_sleep)
    asyncio.run(ws_worker2._connect_loop())
    assert "auth_check" in statuses2

    # 3. stop() scrubs _token immediately
    ws_worker3 = workers.WebSocketWorker("https://example.test", "live-secret-jwt", "dev-ok-3")
    ws_worker3.stop()
    assert ws_worker3._token == ""


def test_app_window_auth_check_and_401_immediately_locks_session_and_wipes_ram():
    state = SimpleNamespace(
        username="alice",
        server_url="https://relay.example.test",
        device_id="dev-alice",
        device_name="Alice Laptop",
        token="active-jwt-token",
        current_chat_username="bob",
        current_chat_device_id="dev-bob",
        current_group_id=None,
        current_chat_type="ally",
        allies={"bob": {"devices": []}},
        groups={"g1": {"name": "Team"}},
    )
    crypto_stub = SimpleNamespace(
        private_key="SENSITIVE_PRIV_KEY",
        public_key="PUB_KEY",
        get_public_key_b64=lambda: "PUB_B64",
    )
    rtc_ended = []
    rtc_stub = SimpleNamespace(end_call=lambda: rtc_ended.append(True))
    saved_profiles = []
    storage_stub = SimpleNamespace(
        save_profile_device=lambda *args: saved_profiles.append(args),
    )

    env = {
        "state": state,
        "crypto": crypto_stub,
        "rtc": rtc_stub,
        "storage": storage_stub,
        "process_delivery_page": process_delivery_page,
        "Qt": SimpleNamespace(QueuedConnection=0),
        "QTimer": SimpleNamespace(singleShot=lambda _d, _fn: None),
    }
    names = [
        "_on_ws_connection_status",
        "_on_sync_connection_status",
        "_on_sync_finished",
        "_on_delivery_ack_finished",
        "_handle_remote_session_invalidated",
    ]
    WinCls = type("WinCls", (), _extract_app_window_methods(names, env))
    win = WinCls()

    sync_starts = []
    win._start_message_sync = lambda: sync_starts.append(True)
    win.sync_worker = None
    win._ack_worker = None
    win._sync_cursor = "cur-10"
    win._sync_restart_requested = False

    ws_stopped = []
    ws_mock = SimpleNamespace(
        account_context=("alice", "https://relay.example.test", "dev-alice", "active-jwt-token"),
        stop=lambda: ws_stopped.append("stop"),
        wait=lambda _ms=0: ws_stopped.append("wait"),
    )
    win.ws_worker = ws_mock

    conn_ui_updates = []
    view_resets = []
    history_cancelled = []
    media_resets = []
    win.main_screen = SimpleNamespace(
        update_connection_status=lambda s: conn_ui_updates.append(s),
        reset_session_view=lambda: view_resets.append(True),
        _history_worker=SimpleNamespace(cancel=lambda: history_cancelled.append(True)),
        _history_pending=("old",),
        _media_queue=SimpleNamespace(reset=lambda: media_resets.append(True)),
        _is_recording=False,
        _voice_thread=None,
        _voice_playback=None,
        _in_call=False,
    )
    timer_stops = []
    win._sync_timer = SimpleNamespace(stop=lambda: timer_stops.append(True))
    pw_cleared = []
    win.password_block = {"input": SimpleNamespace(clear=lambda: pw_cleared.append(True))}
    modes = []
    win._set_mode = lambda m: modes.append(m)
    win.auth_screen = object()
    shown_screens = []
    win.stack = SimpleNamespace(setCurrentWidget=lambda w: shown_screens.append(w))
    statuses = []
    win._set_status = lambda msg, err: statuses.append((msg, err))

    # Step 1: WS emits "auth_check" -> triggers immediate _start_message_sync without polluting UI status label
    win._on_ws_connection_status("auth_check", ws_mock)
    assert sync_starts == [True]
    assert conn_ui_updates == []

    # If sync_worker is currently in flight when "auth_check" arrives, _sync_restart_requested is armed
    in_flight_sync = SimpleNamespace(
        account_context=("alice", "https://relay.example.test", "dev-alice", "active-jwt-token"),
        wait=lambda: None,
    )
    win.sync_worker = in_flight_sync
    win._on_ws_connection_status("auth_check", ws_mock)
    assert win._sync_restart_requested is True

    # Transient 503 does NOT invalidate local session
    win._on_sync_finished(False, "HTTP 503: sync failed", in_flight_sync)
    assert state.token == "active-jwt-token"
    assert crypto_stub.private_key == "SENSITIVE_PRIV_KEY"

    # Step 2: Authoritative HTTP 401 from SyncMessagesWorker immediately locks session & wipes secrets
    sync_401 = SimpleNamespace(
        account_context=("alice", "https://relay.example.test", "dev-alice", "active-jwt-token"),
        wait=lambda: None,
    )
    win.sync_worker = sync_401
    win._on_sync_finished(False, "HTTP 401: sync failed", sync_401)

    assert state.token == ""
    assert crypto_stub.private_key is None
    assert crypto_stub.public_key is None
    assert state.allies == {}
    assert state.groups == {}
    assert ws_stopped == ["stop", "wait"]
    assert win.ws_worker is None
    assert timer_stops == [True]
    assert history_cancelled == [True]
    assert media_resets == [True]
    assert view_resets == [True]
    assert rtc_ended == [True]
    assert pw_cleared == [True]
    assert modes == ["login"]
    assert shown_screens == [win.auth_screen]
    assert statuses and statuses[-1][1] is True


def test_cleartext_remote_http_blocked_while_https_and_loopback_allowed(monkeypatch):
    monkeypatch.delenv("MAX1M_ALLOW_INSECURE_HTTP", raising=False)

    assert validate_server_url("https://relay.example.org")[0] is True
    assert validate_server_url("https://relay.example.org:8443")[0] is True
    assert validate_server_url("http://127.0.0.1:8000")[0] is True
    assert validate_server_url("http://localhost:8000")[0] is True
    assert validate_server_url("http://[::1]:8000")[0] is True

    # Remote plaintext HTTP rejected
    ok_http, err_http = validate_server_url("http://relay.example.org:8000")
    assert ok_http is False and "HTTPS" in err_http.upper()

    # Embedded userinfo, query strings, fragments, non-HTTP schemes rejected
    assert validate_server_url("https://user:secret@relay.example.org")[0] is False
    assert validate_server_url("https://relay.example.org?token=leak")[0] is False
    assert validate_server_url("https://relay.example.org#frag")[0] is False
    assert validate_server_url("ftp://relay.example.org")[0] is False

    # APIClient refuses to send credentials/tokens over remote plaintext HTTP
    client = APIClient()
    monkeypatch.setattr(
        "app.client_api.requests.post",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("network must not be called for insecure HTTP")),
    )
    assert client.login("http://remote-node.example.com", {"username": "alice", "password": "Password123"})[0] is False
    assert client.register("http://remote-node.example.com", {"username": "alice"})[0] is False
    assert client.logout("http://remote-node.example.com", "jwt-tok")[0] is False
    assert client.change_password("http://remote-node.example.com", "jwt-tok", "OldPass123", "NewPass456")[0] is False

    # AppWindow._submit blocks remote HTTP before key generation or worker creation
    statuses = []
    env = {
        "re": __import__("re"),
        "validate_server_url": validate_server_url,
        "state": SimpleNamespace(device_id=None, username="", server_url=""),
    }
    submit_fn = _extract_app_window_methods(["_submit"], env)["_submit"]
    form = SimpleNamespace(
        server_block={"input": SimpleNamespace(text=lambda: "http://unencrypted-relay.example.org")},
        username_block={"input": SimpleNamespace(text=lambda: "alice")},
        password_block={"input": SimpleNamespace(text=lambda: "StrongPass123!")},
        device_block={"input": SimpleNamespace(text=lambda: "Desktop")},
        invite_block={"input": SimpleNamespace(text=lambda: "INV-123")},
        mode="login",
        submit_button=SimpleNamespace(setEnabled=lambda _v: (_ for _ in ()).throw(AssertionError("must reject earlier"))),
        _set_status=lambda text, err: statuses.append((text, err)),
    )
    submit_fn(form)
    assert len(statuses) == 1 and statuses[0][1] is True


def test_workers_block_redirects_traversal_oversized_responses_and_scrub_tokens(monkeypatch):
    client = APIClient()
    fid = str(uuid.uuid4())

    # 1. grant_file_access rejects malformed recipient_device_id before network
    monkeypatch.setattr(
        "app.client_api.requests.post",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("unexpected network call")),
    )
    assert client.grant_file_access("https://node.test", "tok", fid, "../bad/device")[0] is False

    # 2. Group path workers reject traversal group_id before network and scrub token
    for bad_cls in (
        workers.FetchGroupSenderKeysWorker,
        workers.LeaveGroupWorker,
        workers.DeleteGroupWorker,
    ):
        monkeypatch.setattr(
            workers.requests,
            "get",
            lambda *a, **kw: (_ for _ in ()).throw(AssertionError("unexpected GET")),
        )
        monkeypatch.setattr(
            workers.requests,
            "post",
            lambda *a, **kw: (_ for _ in ()).throw(AssertionError("unexpected POST")),
        )
        monkeypatch.setattr(
            workers.requests,
            "delete",
            lambda *a, **kw: (_ for _ in ()).throw(AssertionError("unexpected DELETE")),
        )
        w = bad_cls("https://node.test", "secret-jwt", "../../auth/logout")
        out = []
        w.finished.connect(lambda ok, data, gid: out.append((ok, data, gid)))
        w.run()
        assert out and out[0][0] is False
        assert w.token == ""

    # 3. APIClient.upload_file enforces allow_redirects=False, stream=True, closes response, bounds JSON
    upload_calls = []
    closed = []

    def fake_upload_post(url, **kw):
        upload_calls.append((url, kw))
        return SimpleNamespace(
            status_code=200,
            iter_content=lambda _n: [json.dumps({"file_id": fid}).encode("utf-8")],
            close=lambda: closed.append(True),
        )

    monkeypatch.setattr("app.client_api.requests.post", fake_upload_post)
    u_worker = workers.UploadFileWorker("https://node.test", "upload-jwt", b"CIPHERTEXT")
    u_res = []
    u_worker.finished.connect(lambda ok, data: u_res.append((ok, data)))
    u_worker.run()
    assert upload_calls[0][1]["allow_redirects"] is False
    assert upload_calls[0][1]["stream"] is True
    assert closed == [True]
    assert u_res == [(True, {"file_id": fid})]
    assert u_worker.token == ""

    # 4. Group workers enforce allow_redirects=False, stream=True, never echo raw error text, scrub token
    group_calls = []

    def fake_group_post(url, **kw):
        group_calls.append((url, kw))
        return SimpleNamespace(
            status_code=500,
            text="SENSITIVE_STACKTRACE_" * 1000,
            iter_content=lambda _n: [b"giant"],
            close=lambda: closed.append("group"),
        )

    monkeypatch.setattr(workers.requests, "post", fake_group_post)
    cg = workers.CreateGroupWorker("https://node.test", "grp-jwt", {"name": "g"})
    cg_res = []
    cg.finished.connect(lambda ok, data: cg_res.append((ok, data)))
    cg.run()
    assert group_calls[0][1]["allow_redirects"] is False
    assert group_calls[0][1]["stream"] is True
    assert cg_res == [(False, "HTTP 500")]
    assert "SENSITIVE_STACKTRACE_" not in cg_res[0][1]
    assert cg.token == ""
