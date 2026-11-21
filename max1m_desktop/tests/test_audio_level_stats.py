import ast
import logging
import struct
import threading
import time
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import numpy as np


def _load_pyaudio_io():
    # tests/conftest.py replaces app.webrtc_manager with a stub, so extract
    # the real class from source (same technique as test_webrtc_loopback).
    source = Path(__file__).resolve().parents[1] / "app/webrtc_manager.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    node = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "PyAudioIO"
    )
    env = {
        "threading": threading,
        "time": time,
        "deque": deque,
        "np": np,
        "Optional": Optional,
        "logger": logging.getLogger("max1m.webrtc"),
        "pyaudio": SimpleNamespace(Stream=object, paInt16=8),
        "RATE": 48000,
        "CHANNELS": 1,
        "CHUNK_SAMPLES": 960,
    }
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
            str(source),
            "exec",
        ),
        env,
    )
    return env["PyAudioIO"]


PyAudioIO = _load_pyaudio_io()


def _frame(value: int, samples: int = 960) -> bytes:
    return b"".join(struct.pack("<h", value if i % 2 == 0 else -value) for i in range(samples))


def _io() -> PyAudioIO:
    io = object.__new__(PyAudioIO)
    io._running = True
    io.is_muted = False
    io.is_deafened = False
    io.remote_volume = 1.0
    io._playback_buffer = deque()
    io._playback_lock = threading.Lock()
    io._rx_remainder = bytearray()
    io._priming = True
    io._first_rx_ts = 0.0
    io._last_rx_sample = 0
    io._concealment_used = False
    io._stat_cap_frames = 0
    io._stat_cap_peak = 0
    io._stat_play_frames = 0
    io._stat_play_peak = 0
    io._stats_last_log = time.monotonic()
    return io


def test_pcm16_peak_levels():
    assert PyAudioIO._pcm16_peak(b"") == 0
    assert PyAudioIO._pcm16_peak(b"\x00" * 1920) == 0
    assert PyAudioIO._pcm16_peak(_frame(12000)) == 12000
    assert PyAudioIO._pcm16_peak(_frame(32767)) == 32767
    # Odd trailing byte must not break the measurement.
    assert PyAudioIO._pcm16_peak(_frame(500) + b"\x01") == 500


def test_write_counts_playback_frames_and_peak():
    io = _io()
    io.write(_frame(0))
    io.write(_frame(9000))
    assert io._stat_play_frames == 2
    assert io._stat_play_peak == 9000


def test_write_while_deafened_counts_nothing():
    io = _io()
    io.is_deafened = True
    io.write(_frame(9000))
    assert io._stat_play_frames == 0
    assert io._stat_play_peak == 0


def test_stats_log_is_throttled_and_resets(caplog):
    io = _io()
    io.write(_frame(7000))
    io._maybe_log_audio_stats()
    assert io._stat_play_frames == 1  # too early: nothing logged, nothing reset
    io._stats_last_log -= 10.0
    with caplog.at_level("INFO", logger="max1m.webrtc"):
        io._maybe_log_audio_stats()
    assert "Audio levels:" in caplog.text
    assert "play_peak=7000" in caplog.text
    assert io._stat_play_frames == 0
    assert io._stat_play_peak == 0
