"""Regression tests for the "connected but no sound" executor fix.

On the user's Python 3.15 machine, aiortc's RTP sender died on its
first frame with ``TypeError: 'lazy_import' object is not callable``
from ``asyncio.base_events.run_in_executor`` lazily constructing a
``ThreadPoolExecutor``. The sender task then cleared its track to
None and sent zero RTP packets while RTCP kept the call "connected".

The fix hands every aiortc loop a pre-built default executor. These
tests pin the wiring (module is AST-loaded because tests/conftest.py
stubs app.webrtc_manager).
"""

import ast
from pathlib import Path


def _source(name: str) -> str:
    path = Path(__file__).resolve().parents[1] / "app" / name
    return path.read_text(encoding="utf-8")


def _function(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"function {name} not found")


def test_make_loop_executor_materializes_thread_pool():
    tree = ast.parse(_source("webrtc_manager.py"))
    src = ast.unparse(_function(tree, "_make_loop_executor"))
    assert "ThreadPoolExecutor" in src
    assert "concurrent.futures" in src
    # Fallback path forces lazy-import materialization and retries.
    assert "importlib" in src
    assert "__name__" in src


def test_ensure_loop_executor_sets_default_executor():
    tree = ast.parse(_source("webrtc_manager.py"))
    src = ast.unparse(_function(tree, "ensure_loop_executor"))
    assert "set_default_executor" in src
    assert "_make_loop_executor" in src


def test_manager_loops_get_executors():
    src = _source("webrtc_manager.py")
    assert 'ensure_loop_executor(self._voice_loop, "max1m-voice")' in src
    assert 'ensure_loop_executor(new_loop, "max1m-screen")' in src


def test_group_voice_room_loops_get_executors():
    src = _source("group_voice_room.py")
    assert 'ensure_loop_executor(loop, "max1m-group-voice")' in src
    assert 'ensure_loop_executor(loop, "max1m-group-screen")' in src


def test_aiortc_log_forwarder_drops_debug_spam():
    tree = ast.parse(_source("webrtc_manager.py"))
    forwarder = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "_AiortcLogForwarder"
    )
    src = ast.unparse(_function(forwarder, "emit"))
    assert "WARNING" in src
