import ast
from pathlib import Path


def _webrtc_tree():
    path = Path(__file__).resolve().parents[1] / "app/webrtc_manager.py"
    return ast.parse(path.read_text(encoding="utf-8")), path


def _function(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"function {name} not found")


def test_unavailable_webrtc_is_a_distinct_error_type():
    tree, path = _webrtc_tree()
    classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    assert "WebRTCUnavailableError" in classes


def test_call_entrypoints_fail_fast_when_aiortc_is_missing():
    tree, _ = _webrtc_tree()
    for name in ("start_call", "prepare_incoming_call", "_create_voice_session"):
        fn = _function(tree, name)
        src = ast.dump(fn)
        assert "WebRTCUnavailableError" in src, name


def test_webrtc_errors_are_reported_as_webrtc_unavailable_state():
    tree, _ = _webrtc_tree()
    for name in ("_start_call_async", "_handle_voice_offer"):
        fn = _function(tree, name)
        assert "webrtc_unavailable" in ast.dump(fn), name


def test_ui_has_a_human_readable_webrtc_unavailable_branch():
    path = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = _function(tree, "_update_rtc_state")
    dumped = ast.dump(fn)
    assert "webrtc_unavailable" in dumped
    assert "WebRTC недоступен" in src


def test_aiortc_import_error_is_not_silently_treated_as_available():
    tree, _ = _webrtc_tree()
    # AIORTC_AVAILABLE must be set False in the import fallback.
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "AIORTC_AVAILABLE" for t in sub.targets
                ) and isinstance(sub.value, ast.Constant) and sub.value.value is False:
                    found = True
    assert found


def test_availability_flag_is_captured_from_module_state():
    # The manager caches the import outcome, so later availability checks do
    # not silently succeed when aiortc failed to import at startup.
    tree, _ = _webrtc_tree()
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "WebRTCManager")
    init = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
    assert "_aiortc_available" in ast.unparse(init)


def test_unavailable_error_type_is_preserved():
    tree, _ = _webrtc_tree()
    classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    assert "WebRTCUnavailableError" in classes
