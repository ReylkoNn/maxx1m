import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.group_voice_room import WEBRTC_UNAVAILABLE_MESSAGE, friendly_webrtc_error


def test_dll_load_failure_is_mapped_to_friendly_message():
    exc = ImportError("DLL load failed while importing _rust: Не найден указанный модуль.")
    result = friendly_webrtc_error(exc)
    assert result == WEBRTC_UNAVAILABLE_MESSAGE
    assert "DLL load failed" not in result
    assert "_rust" not in result


def test_broken_aiortc_import_is_mapped_to_friendly_message():
    exc = ImportError("No module named 'aiortc'")
    assert friendly_webrtc_error(exc) == WEBRTC_UNAVAILABLE_MESSAGE


def test_unrelated_errors_pass_through_unchanged():
    assert friendly_webrtc_error(ValueError("bad sdp")) == "bad sdp"
    assert friendly_webrtc_error(RuntimeError("")) == "RuntimeError"


def _room_tree():
    path = Path(__file__).resolve().parents[1] / "app/group_voice_room.py"
    return ast.parse(path.read_text(encoding="utf-8"))


def _function(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"function {name} not found")


def test_offer_failure_reports_friendly_error_to_user():
    fn = _function(_room_tree(), "_create_voice_pc_and_offer")
    assert "friendly_webrtc_error" in ast.unparse(fn)


def test_incoming_signal_import_failure_reports_friendly_error():
    fn = _function(_room_tree(), "_apply_voice_signal")
    src = ast.unparse(fn)
    assert "friendly_webrtc_error" in src
    assert "from aiortc import" in src
