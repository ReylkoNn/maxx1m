#!/usr/bin/env python3
"""
Cross-platform portable archive builder for Max1m Desktop (`Max1m.exe` on Windows,
`Max1m` binary folder on Linux/macOS) using `packaging/max1m_desktop.spec`.
Includes `launch_two_instances.bat` inside `dist/Max1m/` so two isolated instances
can be launched side-by-side on one PC for call/screen-share/tunnel testing.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path


def build_bundle() -> Path:
    pkg_dir = Path(__file__).resolve().parent
    spec_file = pkg_dir / "max1m_desktop.spec"
    dist_dir = pkg_dir / "dist"
    work_dir = pkg_dir / "build"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(work_dir),
        str(spec_file),
    ]
    subprocess.run(cmd, check=True)

    bundle_dir = dist_dir / "Max1m"
    if not bundle_dir.is_dir():
        raise RuntimeError(f"Expected output folder not found: {bundle_dir}")

    two_inst_bat = pkg_dir / "launch_two_instances.bat"
    if two_inst_bat.is_file():
        shutil.copy2(two_inst_bat, bundle_dir / "launch_two_instances.bat")

    sys_tag = f"{platform.system()}-{platform.machine()}"
    if platform.system() == "Windows":
        archive_stem = dist_dir / "Max1m-Windows-x64"
    else:
        archive_stem = dist_dir / f"Max1m-{sys_tag}"

    zip_path = Path(shutil.make_archive(str(archive_stem), "zip", root_dir=dist_dir, base_dir="Max1m"))
    print(f"[PACKAGING] Portable bundle ready: {zip_path}")
    return zip_path


if __name__ == "__main__":
    build_bundle()
