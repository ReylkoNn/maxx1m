import ast
from pathlib import Path
from types import SimpleNamespace


def _extract_accept_call(env):
    path = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    methods = [
        node for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == "MainScreen"
        for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "_accept_call"
    ]
    assert len(methods) == 1
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])), str(path), "exec"), env)
    return env["_accept_call"]


def test_accept_call_prepares_incoming_webrtc_session_and_notifies_caller():
    prepared = []
    sent = []
    warnings = []

    # Deliberately expose only the current WebRTCManager API. The previous
    # accept path called the removed activate_call() name, so pressing
    # "Принять" raised AttributeError and the call could never be accepted.
    rtc = SimpleNamespace(
        prepare_incoming_call=lambda device_id, call_id: prepared.append((device_id, call_id)),
        end_call=lambda: None,
    )
    env = {
        "rtc": rtc,
        "state": SimpleNamespace(),
        "call_context_valid": lambda *args: True,
        "QMessageBox": SimpleNamespace(warning=lambda *args: warnings.append(args)),
    }
    accept_call = _extract_accept_call(env)

    widget = SimpleNamespace(
        setText=lambda *args: None,
        setVisible=lambda *args: None,
        hide=lambda *args: None,
        stop=lambda *args: None,
    )
    window = SimpleNamespace(
        _send_call_event=lambda kind, device_id, call_id: sent.append((kind, device_id, call_id)) or True,
    )

    class Screen:
        _accept_call = accept_call

        def __init__(self):
            self.active_call_username = "alice"
            self._active_call_device_id = "alice-device"
            self._active_call_id = "call-1"
            self._active_call_context = object()
            self._call_direction = "incoming"
            self._call_signal_authorized = False
            self._io_fade_anim = widget
            self.incoming_overlay = widget
            self._cw_avatar_label = widget
            self._cw_name = widget
            self._cw_status = widget
            self._cs_screen_btn = widget

        def _verify_call_contact(self, username, device_id):
            return True

        def _check_call_identity(self):
            raise AssertionError("verified context must not trigger identity cleanup")

        def _show_pill(self):
            pass

        def _cleanup_call(self):
            raise AssertionError("successful accept must not clean up the call")

        def window(self):
            return window

    screen = Screen()
    screen._accept_call()

    assert prepared == [("alice-device", "call-1")]
    assert sent == [("call_accept", "alice-device", "call-1")]
    assert screen._call_signal_authorized is True
    assert warnings == []
