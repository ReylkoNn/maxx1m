import py_compile
from pathlib import Path


def test_diagnose_webrtc_script_compiles_and_covers_both_checks():
    script = Path(__file__).resolve().parents[1] / "diagnose_webrtc.py"
    assert script.is_file()
    py_compile.compile(str(script), doraise=True)
    src = script.read_text(encoding="utf-8")
    # 1) encoder probe, 2) real two-session loopback with packet counters.
    assert "libopus" in src
    assert "VoicePeerSession" in src
    assert "out_packets" in src
    assert "RESULT:" in src
