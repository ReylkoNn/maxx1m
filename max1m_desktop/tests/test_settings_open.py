import ast
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace


DESKTOP_ROOT = Path(__file__).resolve().parents[1]


def _extract(rel_path, class_name, method_name, env):
    path = DESKTOP_ROOT / rel_path
    tree = ast.parse(path.read_text(encoding="utf-8"))
    methods = [
        node for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == class_name
        for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == method_name
    ]
    assert len(methods) == 1
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])), str(path), "exec"), env)
    return env[method_name]


class _Stack:
    def __init__(self):
        self.current = None
        self.widgets = []

    def addWidget(self, widget):
        self.widgets.append(widget)

    def setCurrentWidget(self, widget):
        self.current = widget

    def currentWidget(self):
        return self.current


def _main_screen(open_settings, settings_screen=None):
    class Screen:
        pass

    screen = Screen()
    screen.open_settings = open_settings.__get__(screen)
    screen.settings_screen = settings_screen
    screen.right_stack = _Stack()
    screen.close_settings = lambda: None
    screen.logout_requested = SimpleNamespace(emit=lambda: None)
    screen.on_call_audio_prefs_changed = lambda prefs: None
    screen.on_audio_devices_changed = lambda *args: None
    return screen


def test_open_settings_still_shows_screen_when_refresh_fails(monkeypatch):
    warnings = []
    env = {"QMessageBox": SimpleNamespace(warning=lambda *args: warnings.append(args))}
    open_settings = _extract("app/windows/main_screen.py", "MainScreen", "open_settings", env)

    class FakeSettings:
        def __init__(self):
            self.close_requested = SimpleNamespace(connect=lambda cb: None)
            self.logout_requested = SimpleNamespace(connect=lambda cb: None)
            self.call_audio_prefs_changed = SimpleNamespace(connect=lambda cb: None)
            self.audio_devices_changed = SimpleNamespace(connect=lambda cb: None)

        def refresh(self):
            raise RuntimeError("broken audio driver")

    module = ModuleType("app.windows.settings_screen")
    module.SettingsScreen = FakeSettings
    monkeypatch.setitem(sys.modules, "app.windows.settings_screen", module)

    screen = _main_screen(open_settings)
    screen.open_settings()  # Must not raise: the gear previously looked dead.

    assert screen.right_stack.current is screen.settings_screen
    assert warnings == []


def test_open_settings_reports_creation_failure_without_switching(monkeypatch):
    warnings = []
    env = {"QMessageBox": SimpleNamespace(warning=lambda *args: warnings.append(args))}
    open_settings = _extract("app/windows/main_screen.py", "MainScreen", "open_settings", env)

    class BrokenSettings:
        def __init__(self):
            raise RuntimeError("cannot build settings")

    module = ModuleType("app.windows.settings_screen")
    module.SettingsScreen = BrokenSettings
    monkeypatch.setitem(sys.modules, "app.windows.settings_screen", module)

    screen = _main_screen(open_settings)
    screen.open_settings()

    assert screen.right_stack.current is None
    assert len(warnings) == 1


def test_titlebar_settings_ignores_clicks_before_main_screen_is_visible():
    env = {}
    open_settings = _extract("app/windows/app_window.py", "TitleBar", "_open_settings", env)

    calls = []
    main_screen = SimpleNamespace(open_settings=lambda: calls.append(True))
    auth_screen = object()
    parent = SimpleNamespace(
        main_screen=main_screen,
        stack=SimpleNamespace(currentWidget=lambda: auth_screen),
    )

    class Bar:
        pass

    bar = Bar()
    bar.parent_window = parent
    bar._open_settings = open_settings.__get__(bar)

    bar._open_settings()
    assert calls == []

    parent.stack = SimpleNamespace(currentWidget=lambda: main_screen)
    bar._open_settings()
    assert calls == [True]


def test_security_tab_does_not_shadow_global_qcheckbox_import():
    # Regression from a real client log: a late
    # `from PySide6.QtWidgets import QCheckBox` at the bottom of
    # _build_security_tab made QCheckBox a local variable for the whole
    # method, so its first use raised UnboundLocalError and the settings
    # screen never opened.
    path = DESKTOP_ROOT / "app/windows/settings_screen.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    methods = [
        node for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == "SettingsScreen"
        for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "_build_security_tab"
    ]
    assert len(methods) == 1
    local_imports = [
        alias.name
        for node in ast.walk(methods[0]) if isinstance(node, ast.ImportFrom)
        for alias in node.names
    ]
    assert "QCheckBox" not in local_imports


def test_audio_device_enumeration_failure_returns_empty_lists():
    env = {"logger": SimpleNamespace(warning=lambda *args: None)}
    enumerate_devices = _extract("app/webrtc_manager.py", "PyAudioIO", "enumerate_devices", env)

    class BrokenPa:
        def get_device_count(self):
            raise OSError("audio endpoint unavailable")

    fake = SimpleNamespace(_ensure_pa=lambda: True, pa=BrokenPa())
    assert enumerate_devices(fake) == {"inputs": [], "outputs": []}
