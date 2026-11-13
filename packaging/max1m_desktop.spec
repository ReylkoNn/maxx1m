# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller specification for building standalone desktop bundle (`Max1m.exe` on Windows,
`Max1m` binary on Linux/macOS) from `max1m_desktop/run_desktop.py`.
UPX compression is intentionally disabled (`upx=False`) to preserve cryptographic
DLL integrity (`libsodium` / `av` / `PySide6`) and avoid false-positive AV heuristics.

Includes deterministic filesystem + AST import discovery across all `max1m_desktop/**/*.py`
files so CPython 3.10.0 `bpo-45757` bytecode-disassembly truncation (`dis` `IndexError`
after `EXTENDED_ARG`) never drops lazy-imported `app.*` or stdlib/crypto modules.
"""

import ast
import importlib.util
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

REPO_ROOT = Path(SPECPATH).resolve().parent
DESKTOP_ROOT = REPO_ROOT / "max1m_desktop"
APP_PKG_ROOT = DESKTOP_ROOT / "app"
ASSETS_DIR = APP_PKG_ROOT / "assets"

EXCLUDED_MODULES = [
    "tkinter",
    "matplotlib",
    "scipy",
    "pandas",
    "pytest",
    "PySide6.QtQml",
    "PySide6.QtQuick",
    "PySide6.QtQuickWidgets",
    "PySide6.QtPdf",
    "PySide6.QtVirtualKeyboard",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.Qt3DCore",
]
_EXCLUDED_SET = set(EXCLUDED_MODULES)

datas = []
if ASSETS_DIR.exists():
    datas.append((str(ASSETS_DIR), "app/assets"))

for pkg_data in ("certifi",):
    try:
        datas.extend(collect_data_files(pkg_data))
    except Exception:
        pass


def _discover_app_and_ast_imports(desktop_root: Path) -> list[str]:
    """
    Walk every `.py` file under `max1m_desktop/app` (plus `run_desktop.py`) and collect:
    1. Every `app.*` submodule path directly from the filesystem.
    2. Every `import X` / `from X import Y` found via `ast.parse` (immune to Python 3.10.0
       `dis` bytecode-scanner `IndexError` truncation inside large modules).
    """
    found: set[str] = set()
    app_dir = desktop_root / "app"
    py_files = [desktop_root / "run_desktop.py"]
    if app_dir.is_dir():
        py_files.extend(sorted(app_dir.rglob("*.py")))

    for py_path in py_files:
        if not py_path.is_file():
            continue
        if app_dir in py_path.parents:
            rel_parts = list(py_path.relative_to(desktop_root).with_suffix("").parts)
            if rel_parts[-1] == "__init__":
                rel_parts = rel_parts[:-1]
            if rel_parts:
                found.add(".".join(rel_parts))

        try:
            tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name:
                        found.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module)
                if node.module == "app" or node.module.startswith("app."):
                    for alias in node.names:
                        if alias.name and alias.name != "*":
                            candidate = f"{node.module}.{alias.name}"
                            cand_file = desktop_root.joinpath(*candidate.split(".")).with_suffix(".py")
                            cand_pkg = desktop_root.joinpath(*candidate.split("."), "__init__.py")
                            if cand_file.is_file() or cand_pkg.is_file():
                                found.add(candidate)

    verified: list[str] = []
    for mod_name in sorted(found):
        top = mod_name.split(".", 1)[0]
        if top in _EXCLUDED_SET or mod_name in _EXCLUDED_SET:
            continue
        if mod_name == "app" or mod_name.startswith("app."):
            verified.append(mod_name)
            continue
        try:
            if importlib.util.find_spec(top) is not None:
                verified.append(mod_name if importlib.util.find_spec(mod_name) is not None else top)
        except Exception:
            continue
    return verified


hiddenimports = [
    "nacl._sodium",
    "nacl.bindings",
    "nacl.secret",
    "nacl.signing",
    "nacl.public",
    "nacl.utils",
    "nacl.exceptions",
    "_cffi_backend",
    "cffi",
    "argon2",
    "argon2._password_hasher",
    "cryptography",
    "sqlite3",
    "_sqlite3",
    "PySide6.QtSvg",
    "PySide6.QtNetwork",
    "aiortc",
    "aioice",
    "av",
    "mss",
    "mss.windows",
    "pyaudio",
    "pyaudiowpatch",
    "_portaudiowpatch",
    "websockets",
    "requests",
    "urllib3",
]

hiddenimports.extend(_discover_app_and_ast_imports(DESKTOP_ROOT))

for mod_prefix in ("keyring.backends", "aiortc.codecs", "mss", "argon2"):
    try:
        hiddenimports.extend(collect_submodules(mod_prefix))
    except Exception:
        pass

hiddenimports = sorted(set(hiddenimports) - _EXCLUDED_SET)

a = Analysis(
    [str(DESKTOP_ROOT / "run_desktop.py")],
    pathex=[str(DESKTOP_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDED_MODULES,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Max1m",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="Max1m",
)
