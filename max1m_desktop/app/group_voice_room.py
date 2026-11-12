"""
Discord-Grade Group Voice & Screen-Share Rooms (2–8 Participants) for Max1m.

Subsystems:
1. `VoiceActivityGate`:
   - Real-time 48 kHz 20 ms RMS dBFS measurement (`compute_rms_dbfs`).
   - Configurable Noise Gate / VAD with hysteresis (`open_db`, `close_db = open_db - 5 dB`),
     200 ms hold time, and smooth 64-sample cosine fade-in / fade-out (zero audio clicks).
   - Optional Push-to-Talk (PTT) mode with 180 ms hang-over tail so word endings never clip.
2. `GroupAudioMixer`:
   - Independent bounded jitter buffer (`<= 80 ms`) per participant.
   - Individual volume `0% – 200%` (`0.0 .. 2.0`) + per-peer local mute.
   - Per-peer live speaking indicator (`is_peer_speaking`).
   - 20 ms `float32` summing bus with soft-knee `tanh` brickwall limiter (`SOFT_KNEE = 26000`)
     preventing digital int16 clipping even when 8 peers speak at 200% gain simultaneously.
3. `BroadcasterMicDistributor`:
   - Captures microphone once, runs `VoiceActivityGate`, and fans out 20 ms frames lock-free
     to all active peer `RTCPeerConnection` outbound audio tracks.
4. `GroupVoiceRoomController`:
   - Coordinates group voice presence, glare-free E2EE WebRTC mesh audio (`channel="voice"`),
     `Relay-Only` IP hiding (`ice_relay_only()` + `filter_relay_sdp`), and 1-click isolated
     peer screen sharing (`channel="screen"` via `ScreenPeerSession`).
"""

from __future__ import annotations

import asyncio
import fractions
import json
import logging
import math
import threading
import time
from collections import deque
from typing import Callable, Dict, List, Optional

import numpy as np

from app.ice_config import filter_relay_sdp, ice_relay_only, ice_server_settings

try:
    import aioice.stun as _aioice_stun
    _aioice_stun.RETRY_MAX = 2
    _aioice_stun.RETRY_RTO = 0.25
except Exception:
    pass

logger = logging.getLogger("max1m.group_voice")

RATE = 48000
CHANNELS = 1
CHUNK_MS = 20
CHUNK_SAMPLES = 960                 # 20 ms @ 48 kHz mono
FRAME_BYTES = CHUNK_SAMPLES * 2     # 1920 bytes (int16 LE)
SILENCE_FRAME = b"\x00" * FRAME_BYTES
FADE_SAMPLES = 64                   # ~1.33 ms click-free cosine ramp
SOFT_KNEE_LIMIT = 26000.0
HARD_PEAK_LIMIT = 32767.0
MAX_ROOM_PEERS = 8


def compute_rms_dbfs(pcm_bytes: bytes) -> float:
    """Compute RMS level in dBFS (`[-100.0, 0.0]`) for 16-bit little-endian PCM."""
    if not pcm_bytes or len(pcm_bytes) < 2:
        return -100.0
    usable = len(pcm_bytes) & ~1
    if usable <= 0:
        return -100.0
    samples = np.frombuffer(pcm_bytes[:usable], dtype="<i2").astype(np.float32)
    if samples.size == 0:
        return -100.0
    mean_sq = float(np.mean(samples * samples))
    if mean_sq <= 1e-9:
        return -100.0
    rms = math.sqrt(mean_sq)
    db = 20.0 * math.log10(rms / 32768.0)
    return max(-100.0, min(0.0, db))


def soft_knee_limit_int16(mixed_f32: np.ndarray) -> np.ndarray:
    """
    Soft-knee `tanh` brickwall limiter:
    - Linear up to `±26000` (zero coloration at normal speech levels).
    - Smoothly compresses peaks above `26000` asymptotically toward `±32767`
      so multi-speaker laughter or 200% peer boost never hard-clips!
    """
    abs_x = np.abs(mixed_f32)
    over = abs_x > SOFT_KNEE_LIMIT
    if not np.any(over):
        return mixed_f32.astype("<i2")
    out = mixed_f32.copy()
    headroom = HARD_PEAK_LIMIT - SOFT_KNEE_LIMIT
    excess = (abs_x[over] - SOFT_KNEE_LIMIT) / headroom
    compressed = SOFT_KNEE_LIMIT + headroom * np.tanh(excess)
    out[over] = np.sign(mixed_f32[over]) * compressed
    return np.clip(out, -32768.0, 32767.0).astype("<i2")


class VoiceActivityGate:
    """
    Combined Microphone Mute + Push-to-Talk (PTT) + Hysteresis VAD / Noise Gate.
    """

    def __init__(
        self,
        threshold_db: Optional[float] = -45.0,
        hold_frames: int = 10,          # 200 ms VAD hold
        ptt_enabled: bool = False,
        ptt_hangover_frames: int = 9,   # 180 ms PTT tail
        on_speaking_changed: Optional[Callable[[bool], None]] = None,
    ):
        self._lock = threading.Lock()
        self.threshold_db: Optional[float] = threshold_db
        self.hold_frames = max(1, int(hold_frames))
        self.ptt_enabled = bool(ptt_enabled)
        self.ptt_pressed = False
        self.ptt_hangover_frames = max(0, int(ptt_hangover_frames))
        self._ptt_tail_remaining = 0
        self.is_muted = False

        self._gate_open = (threshold_db is None) and (not self.ptt_enabled)
        self._hold_remaining = 0
        self.is_speaking = False
        self.last_rms_db = -100.0
        self._on_speaking_changed = on_speaking_changed

        t = np.linspace(0.0, math.pi / 2.0, FADE_SAMPLES, dtype=np.float32)
        self._fade_in = np.sin(t) ** 2
        self._fade_out = np.cos(t) ** 2

    def set_muted(self, muted: bool) -> None:
        notify = None
        with self._lock:
            self.is_muted = bool(muted)
            if self.is_muted and self.is_speaking:
                self.is_speaking = False
                self._gate_open = False
                self._hold_remaining = 0
                notify = False
        if notify is not None and self._on_speaking_changed:
            self._on_speaking_changed(notify)

    def set_threshold_db(self, threshold_db: Optional[float]) -> None:
        with self._lock:
            if threshold_db is None:
                self.threshold_db = None
            else:
                self.threshold_db = max(-85.0, min(-10.0, float(threshold_db)))

    def set_ptt_mode(self, enabled: bool) -> None:
        with self._lock:
            self.ptt_enabled = bool(enabled)
            if not self.ptt_enabled:
                self._ptt_tail_remaining = 0

    def set_ptt_pressed(self, pressed: bool) -> None:
        with self._lock:
            was_pressed = self.ptt_pressed
            self.ptt_pressed = bool(pressed)
            if was_pressed and not self.ptt_pressed:
                self._ptt_tail_remaining = self.ptt_hangover_frames

    def process_frame(self, pcm_bytes: bytes) -> bytes:
        """Process one 20 ms (`1920` B) mono int16 PCM frame and update `is_speaking`."""
        if not pcm_bytes:
            return SILENCE_FRAME
        if len(pcm_bytes) < FRAME_BYTES:
            pcm_bytes = pcm_bytes + (b"\x00" * (FRAME_BYTES - len(pcm_bytes)))
        elif len(pcm_bytes) > FRAME_BYTES:
            pcm_bytes = pcm_bytes[:FRAME_BYTES]

        rms_db = compute_rms_dbfs(pcm_bytes)
        notify_speaking: Optional[bool] = None

        with self._lock:
            self.last_rms_db = rms_db
            was_open = self._gate_open

            if self.is_muted:
                target_open = False
                self._hold_remaining = 0
                self._ptt_tail_remaining = 0
            else:
                ptt_allowed = True
                if self.ptt_enabled:
                    if self.ptt_pressed:
                        ptt_allowed = True
                        self._ptt_tail_remaining = self.ptt_hangover_frames
                    elif self._ptt_tail_remaining > 0:
                        self._ptt_tail_remaining -= 1
                        ptt_allowed = True
                    else:
                        ptt_allowed = False

                if not ptt_allowed:
                    target_open = False
                    self._hold_remaining = 0
                elif self.threshold_db is None:
                    # Noise gate disabled: open whenever PTT allows; speaking ring tracks -52 dBFS
                    target_open = True
                else:
                    open_th = self.threshold_db
                    close_th = self.threshold_db - 5.0
                    if rms_db >= open_th or (was_open and rms_db >= close_th):
                        target_open = True
                        self._hold_remaining = self.hold_frames
                    elif self._hold_remaining > 0:
                        self._hold_remaining -= 1
                        target_open = True
                    else:
                        target_open = False

            self._gate_open = target_open
            voice_present = target_open and (rms_db >= -54.0 if self.threshold_db is None else True)
            if voice_present != self.is_speaking:
                self.is_speaking = voice_present
                notify_speaking = voice_present

        if notify_speaking is not None and self._on_speaking_changed:
            try:
                self._on_speaking_changed(notify_speaking)
            except Exception:
                pass

        if not target_open and not was_open:
            return SILENCE_FRAME
        if target_open and was_open:
            return pcm_bytes

        samples = np.frombuffer(pcm_bytes, dtype="<i2").astype(np.float32).copy()
        n = min(FADE_SAMPLES, samples.size)
        if target_open and not was_open:
            # Smooth fade-in
            samples[:n] *= self._fade_in[:n]
            return samples.astype("<i2").tobytes()
        else:
            # Smooth fade-out to silence
            samples[:n] *= self._fade_out[:n]
            samples[n:] = 0.0
            return samples.astype("<i2").tobytes()


class _PeerAudioChannel:
    MAX_FRAMES = 4       # <= 80 ms jitter ceiling
    TARGET_FRAMES = 2    # 40 ms nominal prebuffer

    def __init__(self, peer_id: str, volume: float = 1.0):
        self.peer_id = peer_id
        self.volume: float = max(0.0, min(2.0, float(volume)))
        self.muted: bool = False
        self.frames: deque[bytes] = deque()
        self.remainder = bytearray()
        self.priming = True
        self.first_rx_ts = 0.0
        self.last_sample = 0
        self.concealment_used = False
        self.speaking_hold = 0
        self.is_speaking = False


class GroupAudioMixer:
    """
    20 ms Multi-Participant Audio Mixer (`2–8` peers) with:
    - Per-participant volume `0% – 200%` (`0.0 .. 2.0`) and local mute
    - Bounded `<= 80 ms` per-peer jitter buffer + quadratic packet-loss concealment
    - Per-peer speaking activity detection (`-50 dBFS` + `160 ms` hold)
    - Soft-knee `tanh` brickwall limiter (`zero int16 clipping`)
    """

    SPEAKING_DB_THRESHOLD = -50.0
    SPEAKING_HOLD_FRAMES = 8  # 160 ms

    def __init__(
        self,
        on_peer_speaking_changed: Optional[Callable[[str, bool], None]] = None,
    ):
        self._lock = threading.Lock()
        self._peers: Dict[str, _PeerAudioChannel] = {}
        self.is_deafened = False
        self.master_volume: float = 1.0
        self._on_peer_speaking_changed = on_peer_speaking_changed

    def ensure_peer(self, peer_id: str, initial_volume: Optional[float] = None) -> None:
        with self._lock:
            ch = self._peers.get(peer_id)
            if ch is None:
                vol = 1.0 if initial_volume is None else max(0.0, min(2.0, float(initial_volume)))
                self._peers[peer_id] = _PeerAudioChannel(peer_id, volume=vol)
            elif initial_volume is not None:
                ch.volume = max(0.0, min(2.0, float(initial_volume)))

    def remove_peer(self, peer_id: str) -> None:
        was_speaking = False
        with self._lock:
            ch = self._peers.pop(peer_id, None)
            if ch and ch.is_speaking:
                was_speaking = True
        if was_speaking and self._on_peer_speaking_changed:
            try:
                self._on_peer_speaking_changed(peer_id, False)
            except Exception:
                pass

    def clear(self) -> None:
        with self._lock:
            speaking_ids = [pid for pid, ch in self._peers.items() if ch.is_speaking]
            self._peers.clear()
        if self._on_peer_speaking_changed:
            for pid in speaking_ids:
                try:
                    self._on_peer_speaking_changed(pid, False)
                except Exception:
                    pass

    def set_peer_volume(self, peer_id: str, volume: float) -> float:
        """Set individual participant volume `0.0 .. 2.0` (`0% – 200%`)."""
        clamped = max(0.0, min(2.0, float(volume)))
        with self._lock:
            ch = self._peers.get(peer_id)
            if ch is None:
                ch = _PeerAudioChannel(peer_id, volume=clamped)
                self._peers[peer_id] = ch
            else:
                ch.volume = clamped
        return clamped

    def get_peer_volume(self, peer_id: str) -> float:
        with self._lock:
            ch = self._peers.get(peer_id)
            return ch.volume if ch is not None else 1.0

    def set_peer_muted(self, peer_id: str, muted: bool) -> None:
        with self._lock:
            ch = self._peers.get(peer_id)
            if ch is None:
                ch = _PeerAudioChannel(peer_id)
                self._peers[peer_id] = ch
            ch.muted = bool(muted)

    def is_peer_speaking(self, peer_id: str) -> bool:
        with self._lock:
            ch = self._peers.get(peer_id)
            return bool(ch.is_speaking) if ch is not None else False

    def push_peer_pcm(self, peer_id: str, pcm_data: bytes) -> None:
        """Push decoded 48 kHz mono int16 PCM bytes from `peer_id` into their jitter queue."""
        if not pcm_data:
            return
        with self._lock:
            if self.is_deafened:
                return
            ch = self._peers.get(peer_id)
            if ch is None:
                if len(self._peers) >= MAX_ROOM_PEERS:
                    return
                ch = _PeerAudioChannel(peer_id)
                self._peers[peer_id] = ch
            ch.remainder.extend(pcm_data)
            while len(ch.remainder) >= FRAME_BYTES:
                exact = bytes(ch.remainder[:FRAME_BYTES])
                del ch.remainder[:FRAME_BYTES]
                if not ch.frames:
                    ch.first_rx_ts = time.monotonic()
                ch.frames.append(exact)
            if len(ch.frames) > _PeerAudioChannel.MAX_FRAMES:
                while len(ch.frames) > _PeerAudioChannel.TARGET_FRAMES:
                    ch.frames.popleft()
                ch.priming = False

    @staticmethod
    def _concealment_samples(start_sample: int) -> np.ndarray:
        if start_sample == 0:
            return np.zeros(CHUNK_SAMPLES, dtype=np.float32)
        ramp = np.linspace(1.0, 0.0, CHUNK_SAMPLES, endpoint=False, dtype=np.float32)
        return (ramp * ramp) * float(start_sample)

    def mix_frame(self) -> bytes:
        """
        Pull one 20 ms frame per active peer, apply per-peer `0–200%` gain, sum in `float32`,
        apply soft-knee `tanh` brickwall limiter, and return exact `1920`-byte `int16` PCM.
        """
        speaking_events: List[tuple[str, bool]] = []
        now_m = time.monotonic()

        with self._lock:
            if self.is_deafened or not self._peers:
                for pid, ch in self._peers.items():
                    ch.frames.clear()
                    ch.remainder.clear()
                    if ch.is_speaking:
                        ch.is_speaking = False
                        ch.speaking_hold = 0
                        speaking_events.append((pid, False))
                out_bytes = SILENCE_FRAME
            else:
                bus = np.zeros(CHUNK_SAMPLES, dtype=np.float32)
                any_active = False

                for pid, ch in self._peers.items():
                    qlen = len(ch.frames)
                    raw_frame: Optional[bytes] = None
                    peer_samples: Optional[np.ndarray] = None

                    if ch.priming:
                        if qlen >= _PeerAudioChannel.TARGET_FRAMES or (
                            qlen >= 1 and ch.first_rx_ts > 0.0 and (now_m - ch.first_rx_ts) >= 0.025
                        ):
                            ch.priming = False

                    if not ch.priming and qlen > 0:
                        raw_frame = ch.frames.popleft()
                        ch.concealment_used = False
                        ch.last_sample = int.from_bytes(raw_frame[-2:], byteorder="little", signed=True)
                        peer_samples = np.frombuffer(raw_frame, dtype="<i2").astype(np.float32)
                    elif not ch.priming and not ch.concealment_used and ch.last_sample != 0:
                        ch.concealment_used = True
                        peer_samples = self._concealment_samples(ch.last_sample)
                        ch.last_sample = 0
                    else:
                        ch.priming = True
                        ch.first_rx_ts = 0.0
                        ch.last_sample = 0

                    # Speaking detection on incoming voice before local volume scaling
                    if raw_frame is not None and not ch.muted and ch.volume > 0.0:
                        db = compute_rms_dbfs(raw_frame)
                        if db >= self.SPEAKING_DB_THRESHOLD:
                            ch.speaking_hold = self.SPEAKING_HOLD_FRAMES
                            new_spk = True
                        elif ch.speaking_hold > 0:
                            ch.speaking_hold -= 1
                            new_spk = True
                        else:
                            new_spk = False
                    else:
                        if ch.speaking_hold > 0:
                            ch.speaking_hold -= 1
                            new_spk = not ch.muted and ch.volume > 0.0
                        else:
                            new_spk = False

                    if new_spk != ch.is_speaking:
                        ch.is_speaking = new_spk
                        speaking_events.append((pid, new_spk))

                    if peer_samples is not None and not ch.muted and ch.volume > 0.0:
                        bus += peer_samples * (ch.volume * self.master_volume)
                        any_active = True

                if not any_active:
                    out_bytes = SILENCE_FRAME
                else:
                    out_bytes = soft_knee_limit_int16(bus).tobytes()

        if speaking_events and self._on_peer_speaking_changed:
            for pid, spk in speaking_events:
                try:
                    self._on_peer_speaking_changed(pid, spk)
                except Exception:
                    pass

        return out_bytes


class BroadcasterMicDistributor:
    """
    Single-microphone fan-out distributor:
    processes each 20 ms mic frame ONCE through `VoiceActivityGate` and copies it
    into bounded per-peer outbound queues (`maxlen=4`) so `1..7` PeerConnections
    share a single hardware mic stream with zero lock contention.
    """

    MAX_SUBSCRIBER_FRAMES = 4

    def __init__(self, gate: VoiceActivityGate):
        self.gate = gate
        self._lock = threading.Lock()
        self._subscribers: Dict[str, deque[bytes]] = {}

    def subscribe(self, peer_id: str) -> None:
        with self._lock:
            if peer_id not in self._subscribers:
                self._subscribers[peer_id] = deque(maxlen=self.MAX_SUBSCRIBER_FRAMES)

    def unsubscribe(self, peer_id: str) -> None:
        with self._lock:
            self._subscribers.pop(peer_id, None)

    def clear(self) -> None:
        with self._lock:
            self._subscribers.clear()

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def push_raw_mic_frame(self, raw_pcm: bytes) -> bytes:
        processed = self.gate.process_frame(raw_pcm)
        with self._lock:
            for q in self._subscribers.values():
                q.append(processed)
        return processed

    def pop_for_peer(self, peer_id: str) -> bytes:
        with self._lock:
            q = self._subscribers.get(peer_id)
            if q:
                return q.popleft()
        return SILENCE_FRAME


def _normalize_decoded_audio_frame(frame) -> bytes:
    """Convert any decoded `av.AudioFrame` (`s16`, `s16p`, `fltp`, stereo/mono) to 48 kHz mono `int16` bytes."""
    arr = frame.to_ndarray()
    fmt_name = getattr(getattr(frame, "format", None), "name", "") or ""
    is_planar = fmt_name.endswith("p")
    channels = len(getattr(getattr(frame, "layout", None), "channels", []) or [1])

    if arr.ndim == 2:
        if is_planar and arr.shape[0] == channels:
            mono = arr.astype(np.float32).mean(axis=0)
        elif not is_planar and channels > 1 and arr.shape[1] % channels == 0:
            reshaped = arr.reshape(-1, channels).astype(np.float32)
            mono = reshaped.mean(axis=1)
        else:
            mono = arr.reshape(-1).astype(np.float32)
    else:
        mono = arr.reshape(-1).astype(np.float32)

    if fmt_name.startswith(("flt", "dbl")):
        mono = mono * 32767.0

    src_rate = int(getattr(frame, "sample_rate", RATE) or RATE)
    if src_rate != RATE and mono.size > 1:
        out_len = max(1, int(round(mono.size * RATE / float(src_rate))))
        x_old = np.linspace(0.0, 1.0, mono.size, endpoint=False, dtype=np.float32)
        x_new = np.linspace(0.0, 1.0, out_len, endpoint=False, dtype=np.float32)
        mono = np.interp(x_new, x_old, mono)

    return np.clip(mono, -32768.0, 32767.0).astype("<i2").tobytes()


class GroupVoiceRoomController:
    """
    Discord-grade Group Voice & Screen-Share Room client runtime (`2–8` peers).
    - Uses a single hardware mic stream (`BroadcasterMicDistributor` + `VoiceActivityGate`)
      and a single hardware speaker stream (`GroupAudioMixer`) across all peers.
    - Runs WebRTC mesh PeerConnections on dedicated `_voice_loop` and `_screen_loop` threads.
    - Signs and E2EE-encrypts every SDP/ICE packet with `SignalCrypto` bound to `(group_id, channel)`
      and verifies `peer_public_key` against group roster keys.
    """

    def __init__(
        self,
        send_signal_fn: Callable[[str, str, str, str, str], None],
        on_participants_updated: Optional[Callable[[str, List[dict]], None]] = None,
        on_speaking_updated: Optional[Callable[[str, bool], None]] = None,
        on_screen_frame: Optional[Callable[[str, np.ndarray, str], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        """
        `send_signal_fn(group_id, target_device_id, channel, encrypted_blob, signature)`
        dispatches `POST /calls/groups/{group_id}/voice/signal`.
        """
        self._send_signal_fn = send_signal_fn
        self._on_participants_updated = on_participants_updated
        self._on_speaking_updated = on_speaking_updated
        self._on_screen_frame = on_screen_frame
        self._on_error = on_error

        self.active_group_id: Optional[str] = None
        self.our_device_id: str = ""
        self.our_username: str = ""
        self.is_sharing_screen: bool = False
        self.watching_peer_id: Optional[str] = None

        self.gate = VoiceActivityGate(
            threshold_db=-45.0,
            ptt_enabled=False,
            on_speaking_changed=self._on_self_speaking,
        )
        self.distributor = BroadcasterMicDistributor(self.gate)
        self.mixer = GroupAudioMixer(on_peer_speaking_changed=self._on_peer_speaking)

        self._lock = threading.Lock()
        self._participants: Dict[str, dict] = {}
        self._voice_pcs: Dict[str, object] = {}
        self._voice_pending_ice: Dict[str, list] = {}
        self._screen_send_sessions: Dict[str, object] = {}
        self._screen_recv_session: Optional[object] = None

        self._audio_running = False
        self._pa = None
        self._in_stream = None
        self._out_stream = None
        self._cap_thread: Optional[threading.Thread] = None
        self._play_thread: Optional[threading.Thread] = None

        self._voice_loop: Optional[asyncio.AbstractEventLoop] = None
        self._voice_thread: Optional[threading.Thread] = None
        self._screen_loop: Optional[asyncio.AbstractEventLoop] = None
        self._screen_thread: Optional[threading.Thread] = None

    def _on_self_speaking(self, speaking: bool) -> None:
        if self._on_speaking_updated and self.our_device_id:
            self._on_speaking_updated(self.our_device_id, speaking)

    def _on_peer_speaking(self, peer_device_id: str, speaking: bool) -> None:
        if self._on_speaking_updated:
            self._on_speaking_updated(peer_device_id, speaking)

    def _ensure_loops(self) -> None:
        if self._voice_loop is None or not self._voice_loop.is_running():
            ready = threading.Event()

            def _run_v():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._voice_loop = loop
                ready.set()
                loop.run_forever()

            self._voice_thread = threading.Thread(target=_run_v, name="Max1mGroupVoiceLoop", daemon=True)
            self._voice_thread.start()
            ready.wait(timeout=3.0)

        if self._screen_loop is None or not self._screen_loop.is_running():
            s_ready = threading.Event()

            def _run_s():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._screen_loop = loop
                s_ready.set()
                loop.run_forever()

            self._screen_thread = threading.Thread(target=_run_s, name="Max1mGroupScreenLoop", daemon=True)
            self._screen_thread.start()
            s_ready.wait(timeout=3.0)

    def _start_hardware_audio(self) -> None:
        if self._audio_running:
            return
        try:
            import pyaudio
        except ImportError:
            pyaudio = None
        if pyaudio is None or not hasattr(pyaudio, "PyAudio"):
            return
        try:
            self._pa = pyaudio.PyAudio()
            self._in_stream = self._pa.open(
                format=pyaudio.paInt16,
                channels=CHANNELS,
                rate=RATE,
                input=True,
                frames_per_buffer=CHUNK_SAMPLES,
            )
            self._out_stream = self._pa.open(
                format=pyaudio.paInt16,
                channels=CHANNELS,
                rate=RATE,
                output=True,
                frames_per_buffer=CHUNK_SAMPLES,
            )
        except Exception as exc:
            logger.warning("Group voice hardware audio unavailable (%s); continuing headless", exc)
            self._stop_hardware_audio()
            return

        self._audio_running = True

        def _cap():
            while self._audio_running and self._in_stream is not None:
                try:
                    raw = self._in_stream.read(CHUNK_SAMPLES, exception_on_overflow=False)
                    self.distributor.push_raw_mic_frame(raw)
                except Exception:
                    time.sleep(0.01)

        def _play():
            next_t = time.monotonic()
            while self._audio_running and self._out_stream is not None:
                try:
                    mixed = self.mixer.mix_frame()
                    self._out_stream.write(mixed, CHUNK_SAMPLES)
                    next_t += 0.020
                    rem = next_t - time.monotonic()
                    if rem > 0.001:
                        time.sleep(rem)
                    elif rem < -0.060:
                        next_t = time.monotonic()
                except Exception:
                    time.sleep(0.01)

        self._cap_thread = threading.Thread(target=_cap, name="Max1mGroupMicCap", daemon=True)
        self._play_thread = threading.Thread(target=_play, name="Max1mGroupSpkMix", daemon=True)
        self._cap_thread.start()
        self._play_thread.start()

    def _stop_hardware_audio(self) -> None:
        self._audio_running = False
        for s in (self._in_stream, self._out_stream):
            if s is not None:
                try:
                    s.stop_stream()
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
        self._in_stream = None
        self._out_stream = None
        for t in (self._cap_thread, self._play_thread):
            if t is not None and t is not threading.current_thread():
                t.join(timeout=1.0)
        self._cap_thread = None
        self._play_thread = None
        if self._pa is not None:
            try:
                self._pa.terminate()
            except Exception:
                pass
            self._pa = None

    def apply_audio_prefs(self, prefs: dict) -> None:
        if not isinstance(prefs, dict):
            return
        self.gate.set_threshold_db(prefs.get("noise_gate_db", -45.0))
        self.gate.set_ptt_mode(bool(prefs.get("push_to_talk", False)))
        vols = prefs.get("peer_volumes")
        if isinstance(vols, dict):
            for pid, v in vols.items():
                if isinstance(v, (int, float)):
                    self.mixer.set_peer_volume(pid, float(v))

    def start_local_session(
        self,
        group_id: str,
        our_device_id: str,
        our_username: str,
        initial_participants: List[dict],
        audio_prefs: Optional[dict] = None,
    ) -> None:
        if self.active_group_id and self.active_group_id != group_id:
            self.leave_local_session()
        self.active_group_id = group_id
        self.our_device_id = our_device_id
        self.our_username = our_username
        if audio_prefs:
            self.apply_audio_prefs(audio_prefs)
        self._ensure_loops()
        self._start_hardware_audio()
        self.update_participants(group_id, initial_participants)

    def leave_local_session(self) -> None:
        self.active_group_id = None
        self.is_sharing_screen = False
        self.watching_peer_id = None
        self._stop_hardware_audio()
        self.distributor.clear()
        self.mixer.clear()

        with self._lock:
            pcs = list(self._voice_pcs.values())
            self._voice_pcs.clear()
            self._voice_pending_ice.clear()
            self._participants.clear()
            send_screens = list(self._screen_send_sessions.values())
            self._screen_send_sessions.clear()
            recv_screen = self._screen_recv_session
            self._screen_recv_session = None

        if self._voice_loop and self._voice_loop.is_running() and pcs:
            async def _close_all():
                for pc in pcs:
                    try:
                        await pc.close()
                    except Exception:
                        pass
            asyncio.run_coroutine_threadsafe(_close_all(), self._voice_loop)

        if self._screen_loop and self._screen_loop.is_running() and (send_screens or recv_screen):
            async def _close_screens():
                for ss in send_screens:
                    try:
                        await ss.close()
                    except Exception:
                        pass
                if recv_screen is not None:
                    try:
                        await recv_screen.close()
                    except Exception:
                        pass
            asyncio.run_coroutine_threadsafe(_close_screens(), self._screen_loop)

    def _encrypt_and_send(self, group_id: str, peer_device_id: str, peer_pub: str, channel: str, payload: dict) -> None:
        from app.crypto_box import crypto

        envelope = {
            **payload,
            "group_id": group_id,
            "channel": channel,
            "sender_device_id": self.our_device_id,
            "target_device_id": peer_device_id,
        }
        res = crypto.encrypt_message(json.dumps(envelope, separators=(",", ":"), allow_nan=False), peer_pub)
        self._send_signal_fn(group_id, peer_device_id, channel, res["encrypted_blob"], res["signature"])

    def update_participants(self, group_id: str, participants: List[dict]) -> None:
        if self.active_group_id != group_id:
            if self._on_participants_updated:
                self._on_participants_updated(group_id, participants)
            return

        new_map = {
            p["device_id"]: dict(p)
            for p in (participants or [])
            if isinstance(p, dict) and isinstance(p.get("device_id"), str) and isinstance(p.get("public_key"), str)
        }

        with self._lock:
            removed = [pid for pid in self._participants if pid not in new_map]
            added = [pid for pid in new_map if pid != self.our_device_id and pid not in self._voice_pcs]
            self._participants = new_map

        for pid in removed:
            self.distributor.unsubscribe(pid)
            self.mixer.remove_peer(pid)
            with self._lock:
                pc = self._voice_pcs.pop(pid, None)
                self._voice_pending_ice.pop(pid, None)
            if pc is not None and self._voice_loop and self._voice_loop.is_running():
                asyncio.run_coroutine_threadsafe(pc.close(), self._voice_loop)

        for pid in added:
            peer_meta = new_map[pid]
            self.mixer.ensure_peer(pid)
            self.distributor.subscribe(pid)
            # Glare-free mesh rule: lexicographically smaller device_id initiates SDP offer
            if self.our_device_id and self.our_device_id < pid and self._voice_loop:
                asyncio.run_coroutine_threadsafe(
                    self._create_voice_pc_and_offer(group_id, pid, peer_meta["public_key"]),
                    self._voice_loop,
                )

        if self._on_participants_updated:
            self._on_participants_updated(group_id, participants)

    async def _build_voice_pc(self, group_id: str, peer_id: str, peer_pub: str):
        from aiortc import MediaStreamTrack, RTCConfiguration, RTCIceServer, RTCPeerConnection
        from aiortc.sdp import candidate_to_sdp
        from av.audio.frame import AudioFrame

        relay_only = ice_relay_only()
        servers_cfg = ice_server_settings()
        ice_servers = [RTCIceServer(**srv) for srv in servers_cfg]
        pc = RTCPeerConnection(RTCConfiguration(iceServers=ice_servers))

        distributor = self.distributor
        mixer = self.mixer

        class _FanoutMicTrack(MediaStreamTrack):
            kind = "audio"

            def __init__(self):
                super().__init__()
                self._pts = 0
                self._t0: Optional[float] = None

            async def recv(self):
                if self._t0 is None:
                    self._t0 = time.monotonic()
                else:
                    target = self._t0 + (self._pts / float(RATE))
                    wait = target - time.monotonic()
                    if wait > 0:
                        await asyncio.sleep(wait)
                pcm = distributor.pop_for_peer(peer_id)
                af = AudioFrame(format="s16", layout="mono", samples=CHUNK_SAMPLES)
                af.planes[0].update(pcm)
                af.sample_rate = RATE
                af.pts = self._pts
                af.time_base = fractions.Fraction(1, RATE)
                self._pts += CHUNK_SAMPLES
                return af

        pc.addTrack(_FanoutMicTrack())

        if relay_only and hasattr(pc, "getTransceivers"):
            try:
                from aioice import TransportPolicy
                for tr in pc.getTransceivers():
                    for side in (getattr(tr, "sender", None), getattr(tr, "receiver", None)):
                        conn = getattr(getattr(getattr(getattr(side, "transport", None), "transport", None), "iceGatherer", None), "_connection", None)
                        if conn is not None:
                            conn._transport_policy = TransportPolicy.RELAY
            except Exception:
                pass

        @pc.on("icecandidate")
        def _on_ice(cand):
            if cand is None or self.active_group_id != group_id:
                return
            if relay_only and getattr(cand, "type", None) != "relay":
                return
            self._encrypt_and_send(
                group_id,
                peer_id,
                peer_pub,
                "voice",
                {
                    "action": "ice",
                    "candidate": "candidate:" + candidate_to_sdp(cand),
                    "sdpMid": cand.sdpMid,
                    "sdpMLineIndex": cand.sdpMLineIndex,
                },
            )

        @pc.on("track")
        def _on_track(track):
            if track.kind != "audio":
                return

            async def _pump():
                while True:
                    try:
                        frame = await track.recv()
                        pcm = _normalize_decoded_audio_frame(frame)
                        mixer.push_peer_pcm(peer_id, pcm)
                    except Exception:
                        break

            asyncio.ensure_future(_pump())

        with self._lock:
            self._voice_pcs[peer_id] = pc
        return pc, relay_only

    async def _create_voice_pc_and_offer(self, group_id: str, peer_id: str, peer_pub: str) -> None:
        try:
            pc, relay_only = await self._build_voice_pc(group_id, peer_id, peer_pub)
            offer = await pc.createOffer()
            await pc.setLocalDescription(offer)
            sdp = pc.localDescription.sdp
            if relay_only:
                sdp = filter_relay_sdp(sdp)
            self._encrypt_and_send(group_id, peer_id, peer_pub, "voice", {"action": "offer", "sdp": sdp})
        except Exception as exc:
            logger.warning("Group voice offer failed (%s): %s", peer_id, exc)
            if self._on_error:
                self._on_error(str(exc))

    def handle_incoming_signal(self, event: dict) -> bool:
        """
        Verify Ed25519 signature + NaCl Box ciphertext of an incoming `group_voice_signal`
        against the verified room participant public key, then apply SDP/ICE or screen request.
        """
        from app.crypto_box import crypto

        group_id = event.get("group_id")
        sender_id = event.get("sender_device_id")
        channel = event.get("channel", "voice")
        enc_blob = event.get("encrypted_blob")
        sig_blob = event.get("signature")
        if (
            not group_id
            or group_id != self.active_group_id
            or not isinstance(sender_id, str)
            or sender_id == self.our_device_id
            or not isinstance(enc_blob, str)
            or not isinstance(sig_blob, str)
        ):
            return False

        with self._lock:
            peer_meta = self._participants.get(sender_id)
        if not peer_meta:
            return False
        peer_pub = peer_meta["public_key"]

        if not crypto.verify_signature(enc_blob, sig_blob, peer_pub):
            logger.warning("Rejected group_voice_signal with invalid signature from %s", sender_id)
            return False
        try:
            data = json.loads(crypto.decrypt_message(enc_blob, peer_pub))
        except Exception:
            logger.warning("Failed to decrypt group_voice_signal from %s", sender_id)
            return False

        if (
            not isinstance(data, dict)
            or data.get("group_id") != group_id
            or data.get("sender_device_id") != sender_id
            or data.get("target_device_id") != self.our_device_id
            or data.get("channel") != channel
        ):
            return False

        if channel == "voice" and self._voice_loop:
            asyncio.run_coroutine_threadsafe(
                self._apply_voice_signal(group_id, sender_id, peer_pub, data),
                self._voice_loop,
            )
            return True
        if channel == "screen" and self._screen_loop:
            asyncio.run_coroutine_threadsafe(
                self._apply_screen_signal(group_id, sender_id, peer_pub, data),
                self._screen_loop,
            )
            return True
        return False

    async def _apply_voice_signal(self, group_id: str, peer_id: str, peer_pub: str, data: dict) -> None:
        from aiortc import RTCSessionDescription
        from aiortc.sdp import candidate_from_sdp

        action = data.get("action")
        relay_only = ice_relay_only()
        try:
            if action == "offer":
                with self._lock:
                    old_pc = self._voice_pcs.pop(peer_id, None)
                if old_pc is not None:
                    try:
                        await old_pc.close()
                    except Exception:
                        pass
                self.mixer.ensure_peer(peer_id)
                self.distributor.subscribe(peer_id)
                pc, relay_only = await self._build_voice_pc(group_id, peer_id, peer_pub)
                sdp_in = filter_relay_sdp(data["sdp"]) if relay_only else data["sdp"]
                await pc.setRemoteDescription(RTCSessionDescription(sdp=sdp_in, type="offer"))
                for cand_obj in self._voice_pending_ice.pop(peer_id, []):
                    await pc.addIceCandidate(cand_obj)
                answer = await pc.createAnswer()
                await pc.setLocalDescription(answer)
                sdp_out = filter_relay_sdp(pc.localDescription.sdp) if relay_only else pc.localDescription.sdp
                self._encrypt_and_send(group_id, peer_id, peer_pub, "voice", {"action": "answer", "sdp": sdp_out})
            elif action == "answer":
                with self._lock:
                    pc = self._voice_pcs.get(peer_id)
                if pc is not None:
                    sdp_in = filter_relay_sdp(data["sdp"]) if relay_only else data["sdp"]
                    await pc.setRemoteDescription(RTCSessionDescription(sdp=sdp_in, type="answer"))
                    for cand_obj in self._voice_pending_ice.pop(peer_id, []):
                        await pc.addIceCandidate(cand_obj)
            elif action == "ice":
                cand_raw = str(data.get("candidate", ""))
                if cand_raw.startswith("candidate:"):
                    cand_raw = cand_raw[len("candidate:"):]
                if relay_only and "typ relay" not in cand_raw:
                    return
                cand = candidate_from_sdp(cand_raw)
                cand.sdpMid = data.get("sdpMid")
                cand.sdpMLineIndex = data.get("sdpMLineIndex")
                with self._lock:
                    pc = self._voice_pcs.get(peer_id)
                if pc is not None and pc.remoteDescription is not None:
                    await pc.addIceCandidate(cand)
                else:
                    self._voice_pending_ice.setdefault(peer_id, []).append(cand)
        except Exception as exc:
            logger.warning("Group voice signal apply error (%s/%s): %s", peer_id, action, exc)

    # ── 1-Click Peer Screen Share (Isolated RTCPeerConnection on _screen_loop) ──

    def watch_peer_screen(self, peer_device_id: str) -> bool:
        """Request 1-click E2EE DTLS-SRTP screen stream from `peer_device_id`."""
        if not self.active_group_id or not peer_device_id or peer_device_id == self.our_device_id:
            return False
        with self._lock:
            peer_meta = self._participants.get(peer_device_id)
        if not peer_meta or not peer_meta.get("is_sharing_screen"):
            return False
        self.watching_peer_id = peer_device_id
        self._encrypt_and_send(
            self.active_group_id,
            peer_device_id,
            peer_meta["public_key"],
            "screen",
            {"action": "watch_request", "quality": "balanced"},
        )
        return True

    def stop_watching_screen(self) -> None:
        self.watching_peer_id = None
        with self._lock:
            sess = self._screen_recv_session
            self._screen_recv_session = None
        if sess is not None and self._screen_loop and self._screen_loop.is_running():
            asyncio.run_coroutine_threadsafe(sess.close(), self._screen_loop)

    async def _apply_screen_signal(self, group_id: str, peer_id: str, peer_pub: str, data: dict) -> None:
        from app.screen_share import ScreenPeerSession

        action = data.get("action")
        call_tag = f"grp_scr_{group_id}"
        try:
            if action == "watch_request" and self.is_sharing_screen:
                old = self._screen_send_sessions.pop(peer_id, None)
                if old is not None:
                    await old.close()
                sess = ScreenPeerSession(
                    peer_device_id=peer_id,
                    call_id=call_tag,
                    mode="send",
                    quality=str(data.get("quality", "balanced")),
                    on_ice=lambda pid, _cid, ice_d: self._encrypt_and_send(
                        group_id, pid, peer_pub, "screen", {"action": "ice", **ice_d}
                    ),
                    on_state=lambda _pid, _cid, _st: None,
                )
                self._screen_send_sessions[peer_id] = sess
                await sess.create()
                offer_sdp = await sess.create_offer()
                self._encrypt_and_send(group_id, peer_id, peer_pub, "screen", {"action": "offer", "sdp": offer_sdp})
            elif action == "offer" and self.watching_peer_id == peer_id:
                if self._screen_recv_session is not None:
                    await self._screen_recv_session.close()
                recv_s = ScreenPeerSession(
                    peer_device_id=peer_id,
                    call_id=call_tag,
                    mode="recv",
                    on_ice=lambda pid, _cid, ice_d: self._encrypt_and_send(
                        group_id, pid, peer_pub, "screen", {"action": "ice", **ice_d}
                    ),
                    on_state=lambda _pid, _cid, _st: None,
                    on_video_frame=lambda pid, _cid, rgb, res: (
                        self._on_screen_frame(pid, rgb, res) if self._on_screen_frame else None
                    ),
                )
                self._screen_recv_session = recv_s
                await recv_s.create()
                ans_sdp = await recv_s.accept_offer_and_create_answer(data["sdp"])
                self._encrypt_and_send(group_id, peer_id, peer_pub, "screen", {"action": "answer", "sdp": ans_sdp})
            elif action == "answer":
                sess = self._screen_send_sessions.get(peer_id)
                if sess is not None:
                    await sess.accept_answer(data["sdp"])
            elif action == "ice":
                target_sess = (
                    self._screen_recv_session
                    if self.watching_peer_id == peer_id and self._screen_recv_session is not None
                    else self._screen_send_sessions.get(peer_id)
                )
                if target_sess is not None:
                    await target_sess.add_ice_candidate(data)
        except Exception as exc:
            logger.warning("Group screen share signal error (%s/%s): %s", peer_id, action, exc)
