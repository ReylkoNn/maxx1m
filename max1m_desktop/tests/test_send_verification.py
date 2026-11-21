"""Test real send entry point without requiring Qt system libraries."""
import ast
from pathlib import Path
from types import SimpleNamespace
from app.recipient_context import capture_recipient, is_active_recipient


def method():
    source = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(source.read_text())
    matches = [node for cls in tree.body if isinstance(cls, ast.ClassDef) for node in cls.body
               if isinstance(node, ast.FunctionDef) and node.name == "_send_ally_text_message"]
    assert len(matches) == 1
    return matches[0], source


def test_rejected_fingerprint_or_chat_switch_does_not_enqueue_or_clear():
    state = SimpleNamespace(username="alice", device_id="mine", server_url="https://node", current_chat_type="ally",
                            current_chat_username="bob", current_chat_device_id="b",
                            allies={"bob": {"devices": [{"device_id": "b", "public_key": "key"}]}})
    cleared, enqueued, warnings = [], [], []
    node, path = method()
    env = dict(state=state, capture_recipient=capture_recipient, is_active_recipient=is_active_recipient,
               QMessageBox=SimpleNamespace(warning=lambda *a: warnings.append(a)))
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(path), "exec"), env)
    class Screen:
        _send_ally_text_message = env["_send_ally_text_message"]
        msg_input = SimpleNamespace(clear=lambda: cleared.append(True))
        def _verify_call_contact(self, *args): return False
        def _send_system_payload(self, *args): enqueued.append(args)
    screen = Screen()
    screen._send_ally_text_message("private")
    assert not enqueued and not cleared
    def switch(*args):
        state.current_chat_username = "eve"
        return True
    screen._verify_call_contact = switch
    screen._send_ally_text_message("private")
    assert not enqueued and not cleared and warnings


def test_attachment_requires_verification_before_encrypt_or_enqueue():
    source = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(source.read_text())
    nodes = [node for cls in tree.body if isinstance(cls, ast.ClassDef) for node in cls.body
             if isinstance(node, ast.FunctionDef) and node.name == "_queue_attachment"]
    assert len(nodes) == 1
    state = SimpleNamespace(username="alice", device_id="mine", server_url="https://node", current_chat_type="ally",
                            current_chat_username="bob", current_chat_device_id="b",
                            allies={"bob": {"devices": [{"device_id": "b", "public_key": "key"}]}})
    ctx = capture_recipient(state)
    warnings = []
    env = dict(state=state, is_active_recipient=is_active_recipient,
               QMessageBox=SimpleNamespace(warning=lambda *args: warnings.append(args)))
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source), "exec"), env)
    class Screen:
        _queue_attachment = env["_queue_attachment"]
        def _verify_call_contact(self, *args): return False
    screen = Screen()
    screen._queue_attachment(b"private", ctx, "image")
    def switch(*args):
        state.current_chat_device_id = "other"
        return True
    screen._verify_call_contact = switch
    screen._queue_attachment(b"private", ctx, "voice")
    assert warnings  # No crypto or queue mocks exist: reaching either fails the test.
