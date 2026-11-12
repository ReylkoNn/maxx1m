#!/usr/bin/env python3
"""
Cross-platform portable archive builder for Max1m Desktop (`Max1m.exe` on Windows,
`Max1m` binary folder on Linux/macOS) using `packaging/max1m_desktop.spec`.
Includes:
- Automatic short build/staging root (`MAX1M_SHORT_BUILD_ROOT`) so Windows builds
  never hit the 260-character `MAX_PATH` limit.
- Automatic CPython 3.10.0 `bpo-45757` (`pyinstaller#6301`) `dis` / `modulegraph`
  `IndexError` guard so early Python 3.10 installations scan bytecode cleanly.
"""

from __future__ import annotations

import dis
import inspect
import os
import platform
import shutil
import sys
from pathlib import Path


def _patch_cpython_310_dis_bug() -> None:
    """
    Guard against CPython 3.10.0 bug bpo-45757 (pyinstaller#6301), where dead
    bytecode following an EXTENDED_ARG jump causes `dis` (`_get_const_info`,
    `_get_name_info`, or `cmp_op[arg]`) to raise `IndexError: tuple index out of range`
    during PyInstaller's modulegraph bytecode scan.
    """
    orig_const = getattr(dis, "_get_const_info", None)
    if callable(orig_const) and not getattr(orig_const, "_max1m_patched", False):
        def _safe_const(*args, **kwargs):
            try:
                return orig_const(*args, **kwargs)
            except IndexError:
                idx = args[0] if args else None
                return idx, repr(idx)

        _safe_const._max1m_patched = True  # type: ignore[attr-defined]
        dis._get_const_info = _safe_const  # type: ignore[attr-defined]

    orig_name = getattr(dis, "_get_name_info", None)
    if callable(orig_name) and not getattr(orig_name, "_max1m_patched", False):
        def _safe_name(*args, **kwargs):
            try:
                return orig_name(*args, **kwargs)
            except IndexError:
                idx = args[0] if args else ""
                return str(idx), str(idx)

        _safe_name._max1m_patched = True  # type: ignore[attr-defined]
        dis._get_name_info = _safe_name  # type: ignore[attr-defined]

    try:
        import PyInstaller.lib.modulegraph.util as mg_util

        if not getattr(mg_util.iterate_instructions, "_max1m_patched", False):
            def _safe_iterate_instructions(code_object):
                try:
                    for inst in dis.get_instructions(code_object):
                        if inst.opname != "EXTENDED_ARG":
                            yield inst
                except IndexError:
                    pass
                yield None
                for constant in code_object.co_consts:
                    if inspect.iscode(constant):
                        yield from _safe_iterate_instructions(constant)

            _safe_iterate_instructions._max1m_patched = True  # type: ignore[attr-defined]
            mg_util.iterate_instructions = _safe_iterate_instructions
            try:
                import PyInstaller.lib.modulegraph.modulegraph as mg_mod
                if hasattr(mg_mod, "iterate_instructions"):
                    mg_mod.iterate_instructions = _safe_iterate_instructions
            except Exception:
                pass
    except Exception:
        pass


def _win_long_path(p: Path) -> str:
    s = str(p.resolve())
    if os.name == "nt" and not s.startswith("\\\\?\\") and len(s) >= 200:
        return "\\\\?\\" + s
    return s


def _copytree_win_safe(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(_win_long_path(dst), ignore_errors=True)
    for root, dirs, files in os.walk(_win_long_path(src)):
        rel = os.path.relpath(root, _win_long_path(src))
        target_dir = dst if rel == "." else (dst / rel)
        os.makedirs(_win_long_path(target_dir), exist_ok=True)
        for d in dirs:
            os.makedirs(_win_long_path(target_dir / d), exist_ok=True)
        for f in files:
            shutil.copy2(
                os.path.join(root, f),
                _win_long_path(target_dir / f),
            )


def build_bundle() -> Path:
    _patch_cpython_310_dis_bug()

    pkg_dir = Path(__file__).resolve().parent
    spec_file = pkg_dir / "max1m_desktop.spec"
    repo_dist_dir = pkg_dir / "dist"

    short_root_raw = os.environ.get("MAX1M_SHORT_BUILD_ROOT", "").strip()
    if short_root_raw:
        short_root = Path(short_root_raw).resolve()
        pyi_dist_dir = short_root / "dist"
        pyi_work_dir = short_root / "work"
    else:
        pyi_dist_dir = repo_dist_dir
        pyi_work_dir = pkg_dir / "build"

    pyi_dist_dir.mkdir(parents=True, exist_ok=True)
    pyi_work_dir.mkdir(parents=True, exist_ok=True)

    import PyInstaller.__main__

    PyInstaller.__main__.run(
        [
            "--noconfirm",
            "--clean",
            "--distpath",
            str(pyi_dist_dir),
            "--workpath",
            str(pyi_work_dir),
            str(spec_file),
        ]
    )

    bundle_dir = pyi_dist_dir / "Max1m"
    if not bundle_dir.is_dir():
        raise RuntimeError(f"Expected output folder not found: {bundle_dir}")

    two_inst_bat = pkg_dir / "launch_two_instances.bat"
    if two_inst_bat.is_file():
        shutil.copy2(two_inst_bat, bundle_dir / "launch_two_instances.bat")

    sys_tag = f"{platform.system()}-{platform.machine()}"
    archive_name = "Max1m-Windows-x64" if platform.system() == "Windows" else f"Max1m-{sys_tag}"
    archive_stem = pyi_dist_dir / archive_name

    zip_path = Path(shutil.make_archive(str(archive_stem), "zip", root_dir=pyi_dist_dir, base_dir="Max1m"))

    if pyi_dist_dir.resolve() != repo_dist_dir.resolve():
        os.makedirs(_win_long_path(repo_dist_dir), exist_ok=True)
        try:
            _copytree_win_safe(bundle_dir, repo_dist_dir / "Max1m")
            shutil.copy2(_win_long_path(zip_path), _win_long_path(repo_dist_dir / zip_path.name))
            zip_path = repo_dist_dir / zip_path.name
        except OSError as exc:
            print(f"[PACKAGING] Note: kept bundle in short path due to long repo path ({exc}): {pyi_dist_dir}")

    print(f"[PACKAGING] Portable bundle ready: {zip_path}")
    return zip_path


if __name__ == "__main__":
    build_bundle()
