import hashlib
import sys
from pathlib import Path

PACKAGING = Path(__file__).resolve().parents[2] / "packaging"
sys.path.insert(0, str(PACKAGING))

import build_portable  # noqa: E402


def _make_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "packaging").mkdir(parents=True)
    (root / "packaging" / "max1m_desktop.spec").write_bytes(b"spec-v1")
    desktop = root / "max1m_desktop"
    (desktop / "app").mkdir(parents=True)
    (desktop / "run_desktop.py").write_bytes(b"run-v1")
    (desktop / "app" / "webrtc_manager.py").write_bytes(b"rtc-v1")
    return root


def _stamp(root: Path) -> str:
    return build_portable._source_stamp(root, root / "packaging" / "max1m_desktop.spec")


def test_stamp_is_stable_and_16_hex(tmp_path):
    root = _make_tree(tmp_path)
    stamp = _stamp(root)
    assert stamp == _stamp(root)
    assert len(stamp) == 16
    int(stamp, 16)


def test_stamp_changes_when_app_code_changes(tmp_path):
    # Regression: the old stamp hashed only the .spec file, so the launcher
    # kept treating executables built from ancient application code as
    # "current" and users unknowingly tested stale bundles.
    root = _make_tree(tmp_path)
    before = _stamp(root)
    (root / "max1m_desktop" / "app" / "webrtc_manager.py").write_bytes(b"rtc-v2-fixed")
    assert _stamp(root) != before


def test_stamp_changes_when_spec_changes(tmp_path):
    root = _make_tree(tmp_path)
    before = _stamp(root)
    (root / "packaging" / "max1m_desktop.spec").write_bytes(b"spec-v2")
    assert _stamp(root) != before


def test_stamp_matches_documented_algorithm(tmp_path):
    root = _make_tree(tmp_path)
    lines = []
    for path in (
        root / "packaging" / "max1m_desktop.spec",
        root / "max1m_desktop" / "run_desktop.py",
        root / "max1m_desktop" / "app" / "webrtc_manager.py",
    ):
        rel = path.relative_to(root).as_posix()
        lines.append(f"{rel}:{hashlib.sha256(path.read_bytes()).hexdigest()}\n")
    lines.sort()
    expected = hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()[:16]
    assert _stamp(root) == expected


def test_launcher_computes_source_stamp_not_spec_only():
    ps1 = (PACKAGING / "start_two_windows.ps1").read_text(encoding="utf-8")
    assert "function Get-SourceStamp" in ps1
    assert "$ExpectedStamp = Get-SourceStamp -Root $RepoRoot" in ps1
    assert "max1m_desktop\\app" in ps1


def test_builder_writes_source_stamp():
    src = (PACKAGING / "build_portable.py").read_text(encoding="utf-8")
    assert "_source_stamp(pkg_dir.parent, spec_file)" in src
    assert 'write_text(source_stamp + "\\n", encoding="ascii")' in src
