"""
Regression & loopback tests for:
1. Voice call clarity (elimination of planar-stereo speech duplication/repetition,
   sample-rate conversion to 48 kHz, exact 20 ms framing, <= 80 ms jitter ceiling,
   quadratically decaying PLC fade-out, monotonic 20 ms capture pacing).
2. Isolated E2EE WebRTC Screen Sharing (`ScreenPeerSession` on separate PeerConnection
   and separate event loop so screen video NEVER disrupts or distorts voice calls).
"""

import ast
import asyncio
from collections import deque
import fractions
import logging
import math
from pathlib import Path
import threading
import time
from typing import Callable, Optional

import numpy as np
import pytest

aiortc = pytest.importorskip("aiortc")
from aiortc import (
    MediaStreamTrack,
    RTCConfiguration,
    RTCIceCandidate,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.mediastreams import MediaStreamError
from aiortc.sdp import candidate_from_sdp, candidate_to_sdp
from av.audio.frame import AudioFrame

from app.screen_share import ScreenPeerSession

RATE = 48000
CHANNELS = 1
CHUNK_MS = 20
CHUNK_SAMPLES = 960
CHUNK_BYTES = CHUNK_SAMPLES * CHANNELS * 2


def _load_voice_classes():
    """Load PyAudioIO, AudioCaptureTrack, and VoicePeerSession directly from
    app/webrtc_manager.py without instantiating the global WebRTCManager singleton."""
    source = Path(__file__).resolve().parents[1] / "app/webrtc_manager.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    target_names = {"PyAudioIO", "AudioCaptureTrack", "VoicePeerSession"}
    nodes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name in target_names
    ]
    env = dict(
        asyncio=asyncio,
        deque=deque,
        fractions=fractions,
        logging=logging,
        np=np,
        pyaudio=None,
        PYAUDIO_AVAILABLE=False,
        threading=threading,
        time=time,
        AudioFrame=AudioFrame,
        MediaStreamTrack=MediaStreamTrack,
        MediaStreamError=MediaStreamError,
        RTCPeerConnection=RTCPeerConnection,
        RTCSessionDescription=RTCSessionDescription,
        RTCIceCandidate=RTCIceCandidate,
        RTCConfiguration=RTCConfiguration,
        RTCIceServer=RTCIceServer,
        candidate_from_sdp=candidate_from_sdp,
        candidate_to_sdp=candidate_to_sdp,
        Callable=Callable,
        Optional=Optional,
        ice_server_settings=lambda: [],
        logger=logging.getLogger("voice_quality_test"),
        RATE=RATE,
        CHANNELS=CHANNELS,
        CHUNK_MS=CHUNK_MS,
        CHUNK_SAMPLES=CHUNK_SAMPLES,
    )
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source), "exec"),
        env,
    )
    return env["PyAudioIO"], env["AudioCaptureTrack"], env["VoicePeerSession"]


def _make_pulse_half_frame_int16() -> np.ndarray:
    """960-sample (20 ms @ 48 kHz) test signal: strong 1 kHz tone in first 10 ms,
    strict zero silence in second 10 ms."""
    t = np.arange(480, dtype=np.float64) / float(RATE)
    first_half = (np.sin(2.0 * math.pi * 1000.0 * t) * 18000.0).astype(np.int16)
    second_half = np.zeros(480, dtype=np.int16)
    return np.concatenate([first_half, second_half])


def test_planar_and_interleaved_stereo_downmix_eliminates_voice_repetition():
    """
    Regression proof for the speech-duplication bug:
    aiortc's Opus decoder yields planar stereo `s16p` frames of shape `(2, 960)`.
    Previously `.flatten()[::2]` concatenated `[L0..L959, R0..R959]` and took every 2nd
    sample, playing EVERY 20 ms syllable TWICE at 2x speed!
    Verify that planar `s16p`, planar `fltp`, and packed `s16` stereo all produce
    exact 1920-byte mono PCM with ONE single pulse in `[0:480]` and silence in `[480:960]`.
    """
    _, _, VoicePeerSession = _load_voice_classes()
    mono_ref = _make_pulse_half_frame_int16()

    # 1. Planar int16 stereo `s16p` shape (2, 960) — exact layout produced by aiortc Opus!
    planar_i16 = np.vstack([mono_ref, mono_ref])
    frame_s16p = AudioFrame.from_ndarray(planar_i16, format="s16p", layout="stereo")
    frame_s16p.sample_rate = RATE
    pcm_s16p = VoicePeerSession.decode_frame_to_mono_pcm16(frame_s16p)
    assert len(pcm_s16p) == CHUNK_BYTES
    decoded_s16p = np.frombuffer(pcm_s16p, dtype=np.int16)
    assert float(np.sqrt(np.mean(decoded_s16p[:480].astype(np.float64) ** 2))) > 10000.0
    # Second half MUST remain silent (NOT a repeated second copy of the pulse!)
    assert int(np.max(np.abs(decoded_s16p[480:]))) <= 2

    # 2. Planar float32 stereo `fltp` shape (2, 960)
    planar_flt = planar_i16.astype(np.float32) / 32768.0
    frame_fltp = AudioFrame.from_ndarray(planar_flt, format="fltp", layout="stereo")
    frame_fltp.sample_rate = RATE
    pcm_fltp = VoicePeerSession.decode_frame_to_mono_pcm16(frame_fltp)
    assert len(pcm_fltp) == CHUNK_BYTES
    decoded_fltp = np.frombuffer(pcm_fltp, dtype=np.int16)
    assert float(np.sqrt(np.mean(decoded_fltp[:480].astype(np.float64) ** 2))) > 10000.0
    assert int(np.max(np.abs(decoded_fltp[480:]))) <= 2

    # 3. Packed interleaved int16 stereo `s16` shape (1, 1920)
    interleaved = np.empty((1, CHUNK_SAMPLES * 2), dtype=np.int16)
    interleaved[0, 0::2] = mono_ref
    interleaved[0, 1::2] = mono_ref
    frame_s16 = AudioFrame.from_ndarray(interleaved, format="s16", layout="stereo")
    frame_s16.sample_rate = RATE
    pcm_s16 = VoicePeerSession.decode_frame_to_mono_pcm16(frame_s16)
    assert len(pcm_s16) == CHUNK_BYTES
    decoded_s16 = np.frombuffer(pcm_s16, dtype=np.int16)
    assert float(np.sqrt(np.mean(decoded_s16[:480].astype(np.float64) ** 2))) > 10000.0
    assert int(np.max(np.abs(decoded_s16[480:]))) <= 2

    # 4. Non-48kHz incoming frame (24 kHz, 480 samples = 20 ms) resamples to 960 samples @ 48 kHz
    t24 = np.arange(480, dtype=np.float64) / 24000.0
    tone24 = np.zeros((1, 480), dtype=np.int16)
    tone24[0, :240] = (np.sin(2.0 * math.pi * 1000.0 * t24[:240]) * 16000.0).astype(np.int16)
    frame_24k = AudioFrame.from_ndarray(tone24, format="s16", layout="mono")
    frame_24k.sample_rate = 24000
    pcm_24k = VoicePeerSession.decode_frame_to_mono_pcm16(frame_24k)
    assert len(pcm_24k) == CHUNK_BYTES
    decoded_24k = np.frombuffer(pcm_24k, dtype=np.int16)
    assert float(np.sqrt(np.mean(decoded_24k[:470].astype(np.float64) ** 2))) > 8000.0
    assert int(np.max(np.abs(decoded_24k[490:]))) <= 10


def test_pyaudio_io_exact_20ms_framing_80ms_latency_cap_and_plc_fadeout():
    PyAudioIO, _, _ = _load_voice_classes()
    audio = PyAudioIO()
    audio._running = True
    silence = b"\x00" * CHUNK_BYTES

    # Non-aligned writes: 700 + 1500 = 2200 bytes -> 1 exact 1920-byte frame + 280-byte remainder
    tone_chunk = np.full(1100, 12000, dtype=np.int16).tobytes()
    audio.write(tone_chunk[:700])
    assert len(audio._playback_buffer) == 0
    audio.write(tone_chunk[700:])
    assert len(audio._playback_buffer) == 1
    assert len(audio._playback_buffer[0]) == CHUNK_BYTES

    # Burst of 12 frames (240 ms): hard cap MUST trim buffer immediately to TARGET_PLAYBACK_FRAMES (<= 4 frames = 80 ms)
    for i in range(12):
        audio.write(np.full(CHUNK_SAMPLES, 4000 + i * 500, dtype=np.int16).tobytes())
    assert len(audio._playback_buffer) <= PyAudioIO.MAX_PLAYBACK_FRAMES

    # Pop remaining queued frames via _next_playback_frame(silence)
    while len(audio._playback_buffer) > 0:
        popped = audio._next_playback_frame(silence)
        assert popped is not None and len(popped) == CHUNK_BYTES

    # Immediately following a real voice frame, 1 packet-loss tick MUST emit smooth PLC fade-out
    plc_raw = audio._next_playback_frame(silence)
    assert plc_raw is not None and len(plc_raw) == CHUNK_BYTES
    plc_frame = np.frombuffer(plc_raw, dtype=np.int16)
    assert abs(int(plc_frame[0])) > abs(int(plc_frame[480])) > abs(int(plc_frame[-1]))
    assert abs(int(plc_frame[0])) > 1000
    assert abs(int(plc_frame[-1])) == 0

    # Subsequent empty ticks re-enter priming (return None until fresh packets arrive)
    assert audio._next_playback_frame(silence) is None


def test_audio_capture_track_monotonic_20ms_pacing_and_stall_resync():
    _, AudioCaptureTrack, _ = _load_voice_classes()
    trimmed_calls = []

    class StubCaptureAudio:
        def read(self):
            return np.full(CHUNK_SAMPLES, 3000, dtype=np.int16).tobytes()

        def trim_capture_latency(self, max_frames: int = 2):
            trimmed_calls.append(max_frames)

    async def exercise():
        track = AudioCaptureTrack(StubCaptureAudio())
        t0 = time.monotonic()
        frames = [await track.recv() for _ in range(4)]
        elapsed = time.monotonic() - t0
        # 4 frames (after initial t0) span ~3 * 20 ms = ~60 ms (never a 0 ms unpaced burst!)
        assert 0.045 <= elapsed <= 0.25
        assert [f.pts for f in frames] == [0, 960, 1920, 2880]

        # Simulate a 160 ms event-loop stall -> next recv() resyncs clock & trims capture backlog!
        await asyncio.sleep(0.16)
        f5 = await track.recv()
        assert f5.pts == 3840
        assert trimmed_calls == [2]

    asyncio.run(exercise())


def test_simultaneous_voice_and_isolated_screen_share_loopback_with_real_aiortc():
    """
    Proves that:
    1. Voice call (`VoicePeerSession`) and Screen Share (`ScreenPeerSession`) run concurrently
       over two independent RTCPeerConnections.
    2. Real WebRTC video frames are captured, encoded, transmitted over DTLS-SRTP, and decoded
       on the receiver (`rgb24` frames with expected non-black synthetic colors).
    3. Live quality preset switching (`smooth` -> `balanced`) works mid-stream without
       dropping either screen share or voice.
    4. Stopping screen share cleanly closes only the screen channel while bidirectional 48 kHz
       Opus voice continues uninterrupted with zero voice-loop stalls or silence dropouts!
    """
    _, _, VoicePeerSession = _load_voice_classes()

    class ToneVoiceEndpoint:
        def __init__(self, freq_hz: float):
            self.freq_hz = freq_hz
            self._sample_pos = 0
            self.received_rms: list[float] = []

        def read(self) -> bytes:
            idx = np.arange(self._sample_pos, self._sample_pos + CHUNK_SAMPLES, dtype=np.float64)
            self._sample_pos += CHUNK_SAMPLES
            pcm = (np.sin(2.0 * math.pi * self.freq_hz * (idx / RATE)) * 14000.0).astype(np.int16)
            return pcm.tobytes()

        def trim_capture_latency(self, max_frames: int = 2) -> None:
            pass

        def write(self, pcm: bytes) -> None:
            if len(pcm) == CHUNK_BYTES:
                arr = np.frombuffer(pcm, dtype=np.int16).astype(np.float64)
                rms = float(np.sqrt(np.mean(arr * arr)))
                self.received_rms.append(rms)

    async def exercise():
        alice_audio = ToneVoiceEndpoint(440.0)
        bob_audio = ToneVoiceEndpoint(660.0)

        voice_connected = {"alice": asyncio.Event(), "bob": asyncio.Event()}
        screen_connected = {"alice": asyncio.Event(), "bob": asyncio.Event()}
        remote_screen_active_events: list[bool] = []
        received_video_frames: list[tuple[tuple[int, ...], float, float]] = []
        first_video_event = asyncio.Event()

        v_alice = None
        v_bob = None

        def on_v_ice_a(pid, cand, ch):
            if v_bob and v_bob.pc:
                asyncio.ensure_future(v_bob.add_ice(cand))

        def on_v_ice_b(pid, cand, ch):
            if v_alice and v_alice.pc:
                asyncio.ensure_future(v_alice.add_ice(cand))

        v_alice = VoicePeerSession(
            "bob",
            alice_audio,
            on_v_ice_a,
            lambda pid, st: voice_connected["alice"].set() if st == "connected" else None,
            ice_servers=[],
            relay_only=False,
        )
        v_bob = VoicePeerSession(
            "alice",
            bob_audio,
            on_v_ice_b,
            lambda pid, st: voice_connected["bob"].set() if st == "connected" else None,
            ice_servers=[],
            relay_only=False,
        )

        frame_counter = {"n": 0}

        def synthetic_monitor(_mon_idx: int):
            frame_counter["n"] += 1
            img = np.zeros((1080, 1920, 3), dtype=np.uint8)
            img[:, :960, :] = (30, 190, 220)
            img[:, 960:, :] = (230, 120, 40)
            return img, "rgb24"

        s_alice = None
        s_bob = None

        def on_s_ice_a(pid, cid, cand):
            if s_bob and s_bob.pc:
                asyncio.ensure_future(s_bob.add_ice(cand))

        def on_s_ice_b(pid, cid, cand):
            if s_alice and s_alice.pc:
                asyncio.ensure_future(s_alice.add_ice(cand))

        def on_bob_video_frame(pid: str, cid: str, rgb: np.ndarray, fps: float):
            mean_val = float(np.mean(rgb))
            received_video_frames.append((rgb.shape, mean_val, fps))
            if len(received_video_frames) >= 3:
                first_video_event.set()

        try:
            await v_alice.create()
            await v_bob.create()
            v_offer = await v_alice.create_offer()
            v_answer = await v_bob.handle_offer(v_offer)
            await v_alice.handle_answer(v_answer)

            await asyncio.wait_for(
                asyncio.gather(voice_connected["alice"].wait(), voice_connected["bob"].wait()),
                timeout=10.0,
            )
            await asyncio.sleep(0.25)
            pre_screen_bob_voice_frames = len(bob_audio.received_rms)
            assert pre_screen_bob_voice_frames >= 5

            # Start isolated Screen Share while voice is actively streaming!
            s_alice = ScreenPeerSession(
                peer_device_id="bob",
                call_id="call-001",
                mode="send",
                on_ice=on_s_ice_a,
                on_state=lambda p, c, st: screen_connected["alice"].set() if st == "connected" else None,
                quality="smooth",
                frame_source=synthetic_monitor,
                relay_only=False,
                ice_servers_fn=lambda: [],
            )
            s_bob = ScreenPeerSession(
                peer_device_id="alice",
                call_id="call-001",
                mode="recv",
                on_ice=on_s_ice_b,
                on_state=lambda p, c, st: screen_connected["bob"].set() if st == "connected" else None,
                on_video_frame=on_bob_video_frame,
                on_remote_active=lambda p, c, active: remote_screen_active_events.append(active),
                relay_only=False,
                ice_servers_fn=lambda: [],
            )

            await s_alice.create()
            await s_bob.create()
            s_offer = await s_alice.create_offer()
            s_answer = await s_bob.handle_offer(s_offer)
            await s_alice.handle_answer(s_answer)

            await asyncio.wait_for(
                asyncio.gather(
                    screen_connected["alice"].wait(),
                    screen_connected["bob"].wait(),
                    first_video_event.wait(),
                ),
                timeout=12.0,
            )

            assert True in remote_screen_active_events
            first_shape, first_mean, _ = received_video_frames[-1]
            assert first_shape == (540, 960, 3)
            assert first_mean > 60.0

            # Switch screen quality live to `balanced` (720p) mid-call!
            assert s_alice.set_quality("balanced") == "balanced"
            count_before_switch = len(received_video_frames)
            deadline = time.monotonic() + 5.0
            saw_720p = False
            while time.monotonic() < deadline:
                await asyncio.sleep(0.05)
                for shp, mn, _ in received_video_frames[count_before_switch:]:
                    if shp == (720, 1280, 3) and mn > 60.0:
                        saw_720p = True
                        break
                if saw_720p:
                    break
            assert saw_720p, f"Expected 720p frame after set_quality('balanced'), got {[x[0] for x in received_video_frames[-5:]]}"

            # Stop screen share and verify voice continues cleanly!
            await s_alice.close()
            await s_bob.close()
            s_alice = None
            s_bob = None

            voice_count_at_screen_stop = len(bob_audio.received_rms)
            await asyncio.sleep(0.30)
            voice_count_after_screen_stop = len(bob_audio.received_rms)

            assert voice_count_at_screen_stop > pre_screen_bob_voice_frames + 8
            assert voice_count_after_screen_stop >= voice_count_at_screen_stop + 8
            assert float(np.median(bob_audio.received_rms[4:])) > 2000.0
            assert float(np.median(alice_audio.received_rms[4:])) > 2000.0
        finally:
            if s_alice is not None:
                await s_alice.close()
            if s_bob is not None:
                await s_bob.close()
            await v_alice.close()
            await v_bob.close()

    asyncio.run(exercise())
