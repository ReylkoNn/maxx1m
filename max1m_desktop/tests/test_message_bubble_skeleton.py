import ast
from pathlib import Path


def _bubble_tree():
    path = Path(__file__).resolve().parents[1] / "app/windows/widgets/message_bubble.py"
    return ast.parse(path.read_text(encoding="utf-8"))


def _class(tree, name):
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise AssertionError(f"class {name} not found")


def _method(cls, name):
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"method {name} not found")


def test_bubble_constructor_does_not_create_skeleton():
    # Regression: every history bubble eagerly built an _ImageSkeleton with
    # a running 40 ms timer; bulk history rendering then flooded the GUI
    # thread with timers and crashed natively (access violation at skeleton
    # creation in _load_message_history).
    tree = _bubble_tree()
    init = _method(_class(tree, "MessageBubble"), "__init__")
    created = [
        node for node in ast.walk(init)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_ImageSkeleton"
    ]
    assert created == []


def test_show_skeleton_creates_it_lazily():
    tree = _bubble_tree()
    show = _method(_class(tree, "MessageBubble"), "show_skeleton")
    src = ast.unparse(show)
    assert "_ImageSkeleton(" in src
    assert "insertWidget" in src


def test_skeleton_timer_runs_only_while_visible():
    tree = _bubble_tree()
    skeleton = _class(tree, "_ImageSkeleton")
    init_src = ast.unparse(_method(skeleton, "__init__"))
    assert ".start(" not in init_src
    show_src = ast.unparse(_method(skeleton, "showEvent"))
    assert ".start(40)" in show_src
    hide_src = ast.unparse(_method(skeleton, "hideEvent"))
    assert ".stop()" in hide_src


def test_hide_skeleton_tolerates_missing_skeleton():
    tree = _bubble_tree()
    hide = _method(_class(tree, "MessageBubble"), "hide_skeleton")
    assert "if self._skeleton" in ast.unparse(hide)
