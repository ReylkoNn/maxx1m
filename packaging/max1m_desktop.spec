# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller specification for building standalone desktop bundle (`Max1m.exe` on Windows,
`Max1m` binary on Linux/macOS) from `max1m_desktop/run_desktop.py`.
UPX compression is intentionally disabled (`upx=False`) to preserve cryptographic
DLL integrity (`libsodium` / `av` / `PySide6`) and avoid false-positive AV heuristics.
"""

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

REPO_ROOT = Path(SPECPATH).resolve().parent
DESKTOP_ROOT = REPO_ROOT / "max1m_desktop"
ASSETS_DIR = DESKTOP_ROOT / "app" / "assets"

datas = []
if ASSETS_DIR.exists():
    datas.append((str(ASSETS_DIR), "app/assets"))

for pkg_data in ("certifi",):
    try:
        datas.extend(collect_data_files(pkg_data))
    except Exception:
        pass

hiddenimports = [
    "nacl._sodium",
    "_cffi_backend",
    "cffi",
    "PySide6.QtSvg",
    "PySide6.QtNetwork",
    "aiortc",
    "aioice",
    "av",
    "mss",
    "mss.windows",
    "pyaudio",
    "websockets",
    "requests",
    "urllib3",
]

for mod_prefix in ("keyring.backends", "aiortc.codecs", "mss"):
    try:
        hiddenimports.extend(collect_submodules(mod_prefix))
    except Exception:
        pass

a = Analysis(
    [str(DESKTOP_ROOT / "run_desktop.py")],
    pathex=[str(DESKTOP_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "scipy", "pandas", "pytest"],
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
