import ast
from pathlib import Path


def _tree():
    path = Path(__file__).resolve().parents[1] / "app/webrtc_manager.py"
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


def test_stats_loop_reads_inbound_and_outbound_rtp():
    session = _class(_tree(), "VoicePeerSession")
    src = ast.unparse(_method(session, "_stats_loop"))
    assert "getStats" in src
    assert "inbound-rtp" in src
    assert "outbound-rtp" in src
    assert "RTP stats" in src


def test_stats_task_started_in_create_and_cancelled_in_close():
    session = _class(_tree(), "VoicePeerSession")
    create_src = ast.unparse(_method(session, "create"))
    assert "_stats_loop" in create_src
    close_src = ast.unparse(_method(session, "close"))
    assert "_stats_task" in close_src
    assert ".cancel()" in close_src


def test_play_loop_counts_received_and_empty_frames():
    session = _class(_tree(), "VoicePeerSession")
    src = ast.unparse(_method(session, "_play_loop"))
    assert "_rx_frames" in src
    assert "_rx_empty_frames" in src


def test_stats_loop_reports_transceiver_directions():
    session = _class(_tree(), "VoicePeerSession")
    src = ast.unparse(_method(session, "_stats_loop"))
    assert "getTransceivers" in src
    assert "currentDirection" in src
    assert "play_task" in src


def test_sender_state_checkpoints_cover_negotiation():
    session = _class(_tree(), "VoicePeerSession")
    helper = ast.unparse(_method(session, "_log_sender_state"))
    assert "_enabled" in helper
    assert "transport" in helper
    for method_name, stage in (
        ("create_offer", "after-setLocal-offer"),
        ("handle_offer", "after-setRemote-offer"),
        ("handle_offer", "after-setLocal-answer"),
        ("handle_answer", "after-setRemote-answer"),
    ):
        assert stage in ast.unparse(_method(session, method_name)), (method_name, stage)
    assert "after-addTrack" in ast.unparse(_method(session, "create"))


def test_aiortc_sender_logs_are_forwarded():
    tree = _tree()
    names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert "_forward_aiortc_sender_logs" in names
    path = Path(__file__).resolve().parents[1] / "app/webrtc_manager.py"
    src = path.read_text(encoding="utf-8")
    assert "aiortc.rtcrtpsender" in src


def test_sdp_directions_are_logged_for_offer_and_answer():
    session = _class(_tree(), "VoicePeerSession")
    helper = _method(session, "_sdp_media_directions")
    assert "sendrecv" in ast.unparse(helper)
    offer_src = ast.unparse(_method(session, "create_offer"))
    assert "Voice offer directions" in offer_src
    answer_src = ast.unparse(_method(session, "handle_offer"))
    assert "Voice remote offer directions" in answer_src
    assert "Voice answer directions" in answer_src
