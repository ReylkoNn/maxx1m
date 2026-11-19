import ast
from pathlib import Path
from types import SimpleNamespace

from app.recipient_context import RecipientContext, choose_online_device


def _presence_handler(state, *, is_verified, timer=None):
    path = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(path.read_text())
    node = next(
        n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == "MainScreen"
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == "_on_contact_presence_received"
    )
    env = {
        "state": state,
        "RecipientContext": RecipientContext,
        "choose_online_device": choose_online_device,
        "recipient_is_verified": is_verified,
        "QTimer": timer or SimpleNamespace(singleShot=lambda *_: None),
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(path), "exec"), env)
    return env["_on_contact_presence_received"]


class PresenceWorker:
    def __init__(self, account, username, requested_device_id):
        self.account_context = account
        self.requested_username = username
        self.requested_device_id = requested_device_id
        self.waited = False

    def wait(self):
        self.waited = True


class Button:
    def __init__(self):
        self.enabled = None
        self.tooltip = None

    def setEnabled(self, value):
        self.enabled = value

    def setToolTip(self, value):
        self.tooltip = value


def _state():
    return SimpleNamespace(
        username="alice", server_url="https://node", device_id="alice-device", token="token",
        current_chat_type="ally", current_chat_username="bob", current_chat_device_id="offline",
        allies={"bob": {"devices": [
            {"device_id": "offline", "public_key": "key-offline"},
            {"device_id": "trusted-online", "public_key": "key-online"},
        ]}},
    )


def _screen(state, worker):
    screen = SimpleNamespace(
        _net_workers=[worker], _contact_presence_worker=worker,
        _contact_presence_pending=False, _active_call_device_id=None,
        call_btn=Button(), identity_updates=0,
        _update_contact_identity_status=lambda: setattr(screen, "identity_updates", screen.identity_updates + 1),
    )
    return screen


def test_presence_response_retargets_only_to_online_locally_verified_device():
    state = _state()
    account = (state.username, state.server_url, state.device_id, state.token)
    worker = PresenceWorker(account, "bob", "offline")
    screen = _screen(state, worker)
    handler = _presence_handler(
        state, is_verified=lambda _state, context: context.device_id == "trusted-online"
    )

    handler(screen, True, ["trusted-online"], worker)

    assert worker.waited and not screen._net_workers and screen._contact_presence_worker is None
    assert state.current_chat_device_id == "trusted-online"
    assert screen._contact_presence_known is True
    assert screen._contact_online_device_ids == {"trusted-online"}
    assert screen.call_btn.enabled is True
    assert "подключённом проверенном" in screen.call_btn.tooltip
    assert screen.identity_updates == 1


def test_presence_never_enables_calls_to_unknown_or_unverified_devices():
    state = _state()
    account = (state.username, state.server_url, state.device_id, state.token)
    worker = PresenceWorker(account, "bob", "offline")
    screen = _screen(state, worker)
    handler = _presence_handler(state, is_verified=lambda *_: False)

    handler(screen, True, ["offline", "server-only-device"], worker)

    assert state.current_chat_device_id == "offline"
    assert screen.call_btn.enabled is False
    assert "Нет подключённого проверенного устройства" in screen.call_btn.tooltip
    assert screen._contact_online_device_ids == {"offline", "server-only-device"}


def _call_start_handler(state, messages):
    path = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(path.read_text())
    node = next(
        n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == "MainScreen"
        for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "_on_start_call"
    )
    env = {
        "state": state,
        "QMessageBox": SimpleNamespace(
            information=lambda *args: messages.append(("info", args[1])),
            warning=lambda *args: messages.append(("warning", args[1])),
        ),
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(path), "exec"), env)
    return env["_on_start_call"]


def test_call_waits_for_presence_and_refuses_known_offline_device():
    state = _state()
    messages = []
    handler = _call_start_handler(state, messages)

    class Screen:
        _on_start_call = handler
        _contact_presence_worker = SimpleNamespace(target_username="bob", isRunning=lambda: True)

    Screen()._on_start_call()
    assert messages and messages[-1][0] == "info"

    messages.clear()
    queued_screen = Screen()
    queued_screen._contact_presence_worker = SimpleNamespace(
        target_username="bob", isRunning=lambda: False
    )
    queued_screen._on_start_call()
    assert messages and messages[-1][0] == "info"

    messages.clear()
    screen = Screen()
    screen._contact_presence_worker = None
    screen._contact_presence_pending = True
    screen._on_start_call()
    assert messages and messages[-1][0] == "info"

    messages.clear()
    screen = Screen()
    screen._contact_presence_worker = None
    screen._contact_presence_known = True
    screen._contact_online_device_ids = {"trusted-online"}
    screen._on_start_call()
    assert messages and messages[-1][0] == "warning"
    assert "не подключено" in messages[-1][1]


def test_stale_presence_response_does_not_replace_a_newly_selected_device():
    state = _state()
    account = (state.username, state.server_url, state.device_id, state.token)
    worker = PresenceWorker(account, "bob", "offline")
    screen = _screen(state, worker)
    screen._refresh_current_contact_presence = lambda: None
    state.current_chat_device_id = "new-selection"
    scheduled = []
    timer = SimpleNamespace(singleShot=lambda delay, fn: scheduled.append((delay, fn)))
    handler = _presence_handler(state, is_verified=lambda *_: True, timer=timer)

    handler(screen, True, ["trusted-online"], worker)

    assert state.current_chat_username == "bob"
    assert state.current_chat_device_id == "new-selection"
    assert screen._contact_presence_pending is True
    assert scheduled


def test_stale_presence_response_does_not_change_another_open_chat():
    state = _state()
    account = (state.username, state.server_url, state.device_id, state.token)
    worker = PresenceWorker(account, "bob", "offline")
    screen = _screen(state, worker)
    screen._refresh_current_contact_presence = lambda: None
    state.current_chat_username = "carol"
    state.current_chat_device_id = "carol-device"
    scheduled = []
    timer = SimpleNamespace(singleShot=lambda delay, fn: scheduled.append((delay, fn)))
    handler = _presence_handler(state, is_verified=lambda *_: True, timer=timer)

    handler(screen, True, ["trusted-online"], worker)

    assert state.current_chat_username == "carol"
    assert state.current_chat_device_id == "carol-device"
    assert not getattr(screen, "_contact_presence_known", False)
    assert scheduled  # A fresh request for the newly selected contact is queued.
