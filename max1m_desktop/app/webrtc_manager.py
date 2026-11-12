"""
WebRTC Voice + Isolated E2EE Screen Share Manager.

Architecture:
1. Voice channel (channel="voice"):
   - Dedicated _voice_loop & VoicePeerSession (RTCPeerConnection #1, Opus 48 kHz mono).
   - Monotonic 20 ms wall-clock capture pacing (eliminates RTP bursting and 20x2ms sleep gaps).
   - Proper planar & interleaved stereo/multichannel downmix + sample-rate normalization
     (eliminates voice syllable repetition on planar Opus s16p/fltp frames).
   - Exact 1920-byte (20 ms) playback framing with bounded <= 80 ms adaptive jitter buffer
     and smooth packet-loss fade-out concealment.
2. Screen-share channel (channel="screen"):
   - Dedicated _screen_loop & ScreenPeerSession (RTCPeerConnection #2, DTLS-SRTP video).
   - Physically isolated OS thread, event loop, and peer connection so screen sharing
     NEVER delays, starves, or distorts voice packets.
   - All SDP/ICE/stop control packets are E2EE signed & encrypted via SignalCrypto
     inside call_envelope, bound to the verified peer public key and active call_id.
"""

import asyncio
import fractions
import json
import logging
import threading
import time
from collections import deque
from typing import Callable, Dict, List, Optional

import numpy as np

from app.call_lifecycle import CallLifecycle
from app.ice_config import ice_server_settings

logger = logging.getLogger("max1m.webrtc")

try:
    import pyaudio
    PYAUDIO_AVAILABLE = True
except ImportError:
    pyaudio = None
    PYAUDIO_AVAILABLE = False

try:
    from av.audio.frame import AudioFrame
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
    try:
        import aioice.stun as _aioice_stun
        _aioice_stun.RETRY_MAX = 2
        _aioice_stun.RETRY_RTO = 0.25
    except Exception:
        pass
    AIORTC_AVAILABLE = True
except ImportError as _e:
    AIORTC_AVAILABLE = False
    MediaStreamTrack = object
    RTCPeerConnection = object
    RTCSessionDescription = object
    RTCIceCandidate = object
    RTCConfiguration = object
    RTCIceServer = object
    MediaStreamError = Exception
    AudioFrame = object
    candidate_from_sdp = None
    candidate_to_sdp = None
    logger.warning("aiortc not available (%s)", _e)

RATE = 48000
CHANNELS = 1
CHUNK_MS = 20
CHUNK_SAMPLES = int(RATE * CHUNK_MS / 1000)  # 960 samples (20 ms)

SCREEN_QUALITY_PRESETS = {
    "smooth":   (960,  540,  30),
    "balanced": (1280, 720,  24),
    "sharp":    (1600, 900,  20),
}

CALL_STATE_IDLE = "idle"
CALL_STATE_CALLING = "calling"
CALL_STATE_RINGING = "ringing"
CALL_STATE_CONNECTING = "connecting"
CALL_STATE_CONNECTED = "connected"
CALL_STATE_ENDED = "ended"


# ═════════════════════════════════════════════════════════════════════════════
# SIGNAL CRYPTO — E2EE for SDP / ICE / screen control
# ═════════════════════════════════════════════════════════════════════════════

class SignalCrypto:
    MAX_SIGNAL_CIPHERTEXT_CHARS = 128 * 1024
    MAX_SIGNAL_SIGNATURE_CHARS = 512
    MAX_SIGNAL_JSON_DEPTH = 16

    @staticmethod
    def _reject_non_finite_json(constant: str):
        raise ValueError(f"Unsupported JSON constant: {constant}")

    @classmethod
    def _signal_depth_ok(cls, obj) -> bool:
        stack = [(obj, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > cls.MAX_SIGNAL_JSON_DEPTH:
                return False
            if isinstance(current, dict):
                for k, v in current.items():
                    if not isinstance(k, str) or len(k) > 128:
                        return False
                    if isinstance(v, (dict, list)):
                        stack.append((v, depth + 1))
            elif isinstance(current, list):
                for item in current:
                    if isinstance(item, (dict, list)):
                        stack.append((item, depth + 1))
        return True

    @staticmethod
    def encrypt_signal(signal_data: dict, recipient_pub_b64: str) -> tuple:
        from app.crypto_box import crypto
        plaintext = json.dumps(signal_data, separators=(",", ":"), allow_nan=False)
        result = crypto.encrypt_message(plaintext, recipient_pub_b64)
        return result["encrypted_blob"], result["signature"]

    @staticmethod
    def decrypt_signal(enc_b64: str, sig_b64: str, sender_pub_b64: str) -> Optional[dict]:
        from app.crypto_box import crypto
        if (
            not isinstance(enc_b64, str)
            or not 0 < len(enc_b64) <= SignalCrypto.MAX_SIGNAL_CIPHERTEXT_CHARS
            or not isinstance(sig_b64, str)
            or not 0 < len(sig_b64) <= SignalCrypto.MAX_SIGNAL_SIGNATURE_CHARS
            or not isinstance(sender_pub_b64, str)
            or not sender_pub_b64
        ):
            return None
        if not crypto.verify_signature(enc_b64, sig_b64, sender_pub_b64):
            logger.error("Invalid signal signature")
            return None
        try:
            plaintext = crypto.decrypt_message(enc_b64, sender_pub_b64)
            parsed = json.loads(plaintext, parse_constant=SignalCrypto._reject_non_finite_json)
            if not isinstance(parsed, dict) or not SignalCrypto._signal_depth_ok(parsed):
                return None
            return parsed
        except Exception as e:
            logger.error("Signal decrypt failed: %s", type(e).__name__)
            return None

    @staticmethod
    def verify_dtls(pc, expected=None) -> bool:
        if not pc or not pc.remoteDescription:
            return False
        for line in pc.remoteDescription.sdp.split("\n"):
            if line.startswith("a=fingerprint:"):
                fp = line.split(" ", 1)[1].strip()
                if expected and fp != expected:
                    logger.error("DTLS fingerprint MISMATCH!")
                    return False
                return True
        return False


# ═════════════════════════════════════════════════════════════════════════════
# PYAUDIO IO — Exact 20 ms framer, <= 80 ms jitter buffer & PLC fade-out
# ═════════════════════════════════════════════════════════════════════════════

class PyAudioIO:
    MAX_CAPTURE_FRAMES = 4      # 80 ms hard ceiling on mic queue
    TARGET_PLAYBACK_FRAMES = 2  # 40 ms nominal jitter prebuffer
    MAX_PLAYBACK_FRAMES = 4     # 80 ms hard ceiling on speaker latency

    def __init__(self):
        self.pa = None
        if pyaudio is not None and hasattr(pyaudio, "PyAudio"):
            try:
                self.pa = pyaudio.PyAudio()
            except Exception as e:
                self.pa = None
                logger.warning("PyAudio init deferred: %s", e)

        self._input_stream: Optional[pyaudio.Stream] = None
        self._output_stream: Optional[pyaudio.Stream] = None
        self._running = False

        self.input_device: Optional[int] = None
        self.output_device: Optional[int] = None
        self.remote_volume: float = 1.0
        self.is_muted = False
        self.is_deafened = False

        self._playback_buffer: deque = deque()
        self._playback_thread: Optional[threading.Thread] = None
        self._playback_lock = threading.Lock()
        self._rx_remainder = bytearray()
        self._priming = True
        self._first_rx_ts: float = 0.0
        self._last_rx_sample: int = 0
        self._concealment_used = False

        self._capture_queue: deque = deque(maxlen=self.MAX_CAPTURE_FRAMES)
        self._capture_thread: Optional[threading.Thread] = None
        self._capture_lock = threading.Lock()

    def _ensure_pa(self) -> bool:
        if self.pa is not None:
            return True
        if pyaudio is None or not hasattr(pyaudio, "PyAudio"):
            return False
        try:
            self.pa = pyaudio.PyAudio()
            return True
        except Exception as e:
            logger.error("PyAudio unavailable: %s", e)
            return False

    def _open_input_stream(self):
        try:
            self._input_stream = self.pa.open(
                format=pyaudio.paInt16,
                channels=CHANNELS,
                rate=RATE,
                input=True,
                input_device_index=self.input_device,
                frames_per_buffer=CHUNK_SAMPLES,
            )
            return True
        except Exception as e:
            logger.error("Input device %s failed: %s", self.input_device, e)
            try:
                self._input_stream = self.pa.open(
                    format=pyaudio.paInt16,
                    channels=CHANNELS,
                    rate=RATE,
                    input=True,
                    frames_per_buffer=CHUNK_SAMPLES,
                )
                return True
            except Exception as e2:
                logger.error("Default input failed: %s", e2)
                self._input_stream = None
                return False

    def _open_output_stream(self):
        try:
            self._output_stream = self.pa.open(
                format=pyaudio.paInt16,
                channels=CHANNELS,
                rate=RATE,
                output=True,
                output_device_index=self.output_device,
                frames_per_buffer=CHUNK_SAMPLES,
            )
            return True
        except Exception as e:
            logger.error("Output device %s failed: %s", self.output_device, e)
            try:
                self._output_stream = self.pa.open(
                    format=pyaudio.paInt16,
                    channels=CHANNELS,
                    rate=RATE,
                    output=True,
                    frames_per_buffer=CHUNK_SAMPLES,
                )
                return True
            except Exception as e2:
                logger.error("Default output failed: %s", e2)
                self._output_stream = None
                return False

    def start(self):
        if self._running:
            return
        if not self._ensure_pa():
            return
        if not self._open_input_stream():
            return
        if not self._open_output_stream():
            if self._input_stream:
                try:
                    self._input_stream.stop_stream()
                except Exception:
                    pass
                try:
                    self._input_stream.close()
                except Exception:
                    pass
                self._input_stream = None
            return

        with self._playback_lock:
            self._playback_buffer.clear()
            self._rx_remainder.clear()
            self._priming = True
            self._first_rx_ts = 0.0
            self._last_rx_sample = 0
            self._concealment_used = False
        with self._capture_lock:
            self._capture_queue.clear()

        self._running = True
        self._capture_thread = threading.Thread(
            target=self._capture_loop, name="Max1mVoiceCapture", daemon=True
        )
        self._capture_thread.start()
        self._playback_thread = threading.Thread(
            target=self._playback_loop, name="Max1mVoicePlayback", daemon=True
        )
        self._playback_thread.start()
        logger.info("PyAudio started (input=%s, output=%s)", self.input_device, self.output_device)

    def switch_input_device(self, idx: Optional[int]):
        self.input_device = idx
        if not self._running or not self.pa:
            return
        with self._capture_lock:
            old, self._input_stream = self._input_stream, None
            if old:
                try:
                    old.stop_stream()
                except Exception:
                    pass
                try:
                    old.close()
                except Exception:
                    pass
            self._capture_queue.clear()
            self._open_input_stream()

    def switch_output_device(self, idx: Optional[int]):
        self.output_device = idx
        if not self._running or not self.pa:
            return
        with self._playback_lock:
            old, self._output_stream = self._output_stream, None
            if old:
                try:
                    old.stop_stream()
                except Exception:
                    pass
                try:
                    old.close()
                except Exception:
                    pass
            self._playback_buffer.clear()
            self._rx_remainder.clear()
            self._priming = True
            self._open_output_stream()

    def stop(self):
        self._running = False
        in_s = getattr(self, "_input_stream", None)
        self._input_stream = None
        if in_s:
            try:
                in_s.stop_stream()
            except Exception:
                pass
            try:
                in_s.close()
            except Exception:
                pass

        out_s = getattr(self, "_output_stream", None)
        self._output_stream = None
        if out_s:
            try:
                out_s.stop_stream()
            except Exception:
                pass
            try:
                out_s.close()
            except Exception:
                pass

        for t in (getattr(self, "_playback_thread", None), getattr(self, "_capture_thread", None)):
            if t and t is not threading.current_thread():
                t.join(timeout=2.0)
        self._playback_thread = None
        self._capture_thread = None

        pb_lock = getattr(self, "_playback_lock", None)
        if pb_lock is not None:
            with pb_lock:
                if getattr(self, "_playback_buffer", None) is not None:
                    self._playback_buffer.clear()
                rem = getattr(self, "_rx_remainder", None)
                if rem is not None:
                    rem.clear()
                self._priming = True
                self._last_rx_sample = 0

        cap_lock = getattr(self, "_capture_lock", None)
        if cap_lock is not None:
            with cap_lock:
                if getattr(self, "_capture_queue", None) is not None:
                    self._capture_queue.clear()
        logger.info("PyAudio stopped")

    def _capture_loop(self):
        silence = b"\x00" * (CHUNK_SAMPLES * CHANNELS * 2)
        while self._running:
            try:
                stream = self._input_stream
                if not stream:
                    time.sleep(0.005)
                    continue
                data = stream.read(CHUNK_SAMPLES, exception_on_overflow=False)
                if self.is_muted:
                    data = silence
                with self._capture_lock:
                    while len(self._capture_queue) >= self.MAX_CAPTURE_FRAMES:
                        try:
                            self._capture_queue.popleft()
                        except IndexError:
                            break
                    self._capture_queue.append(data)
            except Exception as e:
                if self._running:
                    logger.warning("Capture error: %s", e)
                time.sleep(0.005)

    def read(self) -> Optional[bytes]:
        with self._capture_lock:
            if self._capture_queue:
                return self._capture_queue.popleft()
        return None

    def trim_capture_latency(self, max_frames: int = 2):
        keep = max(0, int(max_frames))
        with self._capture_lock:
            while len(self._capture_queue) > keep:
                self._capture_queue.popleft()

    def write(self, pcm_data: bytes):
        if not self._running or self.is_deafened or not pcm_data:
            return
        frame_bytes = CHUNK_SAMPLES * CHANNELS * 2
        with self._playback_lock:
            self._rx_remainder.extend(pcm_data)
            while len(self._rx_remainder) >= frame_bytes:
                exact_frame = bytes(self._rx_remainder[:frame_bytes])
                del self._rx_remainder[:frame_bytes]
                if not self._playback_buffer:
                    self._first_rx_ts = time.monotonic()
                self._playback_buffer.append(exact_frame)
            # Enforce hard <= 80 ms latency ceiling on network burst arrival.
            if len(self._playback_buffer) > self.MAX_PLAYBACK_FRAMES:
                while len(self._playback_buffer) > self.TARGET_PLAYBACK_FRAMES:
                    self._playback_buffer.popleft()
                self._priming = False

    def _make_concealment_frame(self, start_sample: int) -> bytes:
        if start_sample == 0:
            return b"\x00" * (CHUNK_SAMPLES * CHANNELS * 2)
        ramp = np.linspace(1.0, 0.0, CHUNK_SAMPLES, endpoint=False, dtype=np.float32)
        curved = (ramp * ramp) * float(start_sample)
        return np.clip(curved, -32768.0, 32767.0).astype(np.int16).tobytes()

    def _next_playback_frame(self, silence: bytes) -> Optional[bytes]:
        with self._playback_lock:
            if self.is_deafened:
                self._playback_buffer.clear()
                self._rx_remainder.clear()
                self._priming = True
                self._last_rx_sample = 0
                self._concealment_used = False
                return silence

            qlen = len(self._playback_buffer)
            if self._priming:
                if qlen >= self.TARGET_PLAYBACK_FRAMES or (
                    qlen >= 1 and self._first_rx_ts > 0.0 and (time.monotonic() - self._first_rx_ts) >= 0.025
                ):
                    self._priming = False
                else:
                    return None

            if qlen > 0:
                frame = self._playback_buffer.popleft()
                self._concealment_used = False
                if len(frame) >= 2:
                    self._last_rx_sample = int.from_bytes(frame[-2:], byteorder="little", signed=True)
                return frame

            if not self._concealment_used and self._last_rx_sample != 0:
                self._concealment_used = True
                last_val = self._last_rx_sample
                self._last_rx_sample = 0
                return self._make_concealment_frame(last_val)

            self._priming = True
            self._first_rx_ts = 0.0
            self._last_rx_sample = 0
            return None

    def _playback_loop(self):
        frame_bytes = CHUNK_SAMPLES * CHANNELS * 2
        silence = b"\x00" * frame_bytes
        while self._running:
            try:
                data = self._next_playback_frame(silence)
                out_stream = self._output_stream
                if out_stream and not self.is_deafened:
                    pcm = data if data is not None else silence
                    out_stream.write(pcm, CHUNK_SAMPLES)
                else:
                    if data is None:
                        time.sleep(0.005)
            except Exception as e:
                if self._running:
                    logger.warning("Playback error: %s", e)
                time.sleep(0.005)

    def enumerate_devices(self) -> dict:
        if not self._ensure_pa():
            return {"inputs": [], "outputs": []}
        inputs, outputs = [], []
        seen_in, seen_out = set(), set()
        for i in range(self.pa.get_device_count()):
            try:
                info = self.pa.get_device_info_by_index(i)
            except Exception:
                continue
            name = str(info.get("name", "")).strip()
            if not name:
                continue
            if info.get("maxInputChannels", 0) > 0 and name.lower() not in seen_in:
                seen_in.add(name.lower())
                inputs.append({"index": i, "name": name})
            if info.get("maxOutputChannels", 0) > 0 and name.lower() not in seen_out:
                seen_out.add(name.lower())
                outputs.append({"index": i, "name": name})
        return {"inputs": inputs, "outputs": outputs}


# ═════════════════════════════════════════════════════════════════════════════
# AIORTC TRACK — Monotonic 20 ms wall-clock pacer (zero burst, zero drift)
# ═════════════════════════════════════════════════════════════════════════════

class AudioCaptureTrack(MediaStreamTrack):
    kind = "audio"

    def __init__(self, audio_io: PyAudioIO):
        super().__init__()
        self.audio_io = audio_io
        self._pts = 0
        self._time_base = fractions.Fraction(1, RATE)
        self._start_time: Optional[float] = None
        self._last_sample: int = 0

    async def recv(self):
        loop = asyncio.get_running_loop()
        now = loop.time()
        if self._start_time is None:
            self._start_time = now
        else:
            target = self._start_time + (self._pts / RATE)
            wait = target - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = loop.time()
            elif (now - target) > 0.100:
                # Resync clock after OS stall and trim stale buffered mic frames.
                self._start_time = now - (self._pts / RATE)
                trim_fn = getattr(self.audio_io, "trim_capture_latency", None)
                if callable(trim_fn):
                    trim_fn(2)

        pcm_data = self.audio_io.read()
        if pcm_data is None:
            # Brief <= 4 ms grace poll if capture thread is right on the 20 ms boundary.
            for _ in range(2):
                await asyncio.sleep(0.002)
                pcm_data = self.audio_io.read()
                if pcm_data is not None:
                    break

        expected_bytes = CHUNK_SAMPLES * CHANNELS * 2
        if pcm_data is None or len(pcm_data) < expected_bytes or (len(pcm_data) % 2) != 0:
            if self._last_sample != 0:
                ramp = np.linspace(1.0, 0.0, CHUNK_SAMPLES, endpoint=False, dtype=np.float32)
                pcm_data = (
                    np.clip((ramp * ramp) * float(self._last_sample), -32768.0, 32767.0)
                    .astype(np.int16)
                    .tobytes()
                )
                self._last_sample = 0
            else:
                pcm_data = b"\x00" * expected_bytes
        else:
            if len(pcm_data) > expected_bytes:
                pcm_data = pcm_data[:expected_bytes]
            samples_arr = np.frombuffer(pcm_data, dtype=np.int16)
            if samples_arr.size > 0:
                self._last_sample = int(samples_arr[-1])

        samples = len(pcm_data) // 2
        frame = AudioFrame(format="s16", layout="mono", samples=samples)
        frame.planes[0].update(pcm_data)
        frame.pts = self._pts
        frame.time_base = self._time_base
        frame.sample_rate = RATE
        self._pts += samples
        return frame


# ═════════════════════════════════════════════════════════════════════════════
# VOICE PEER SESSION — 1 peer = 1 RTCPeerConnection (voice only)
# ═════════════════════════════════════════════════════════════════════════════

class VoicePeerSession:
    MAX_SDP_CHARS = 64 * 1024

    def __init__(
        self,
        peer_device_id: str,
        audio_io: PyAudioIO,
        on_ice: Callable,
        on_state: Callable,
        ice_servers: Optional[list] = None,
        relay_only: Optional[bool] = None,
    ):
        self.peer_device_id = peer_device_id
        self.call_id: Optional[str] = None
        self.audio_io = audio_io
        self._on_ice = on_ice
        self._on_state = on_state
        self._ice_servers = ice_servers
        self._relay_only_override = relay_only
        self._effective_relay_only = False
        self._pending_remote_ice = []
        self.pc: Optional[RTCPeerConnection] = None
        self._play_task: Optional[asyncio.Task] = None
        self.remote_dtls_fp: Optional[str] = None
        self._closed = False

    @staticmethod
    def decode_frame_to_mono_pcm16(
        frame,
        target_rate: int = RATE,
        volume: float = 1.0,
    ) -> bytes:
        """Convert any PyAV/aiortc AudioFrame (planar or packed, mono/stereo, any rate)
        into clean 16-bit mono PCM at target_rate without duplicating channels."""
        raw = frame.to_ndarray()
        if raw is None or raw.size == 0:
            return b""

        fmt = getattr(frame, "format", None)
        is_planar = bool(getattr(fmt, "is_planar", False)) if fmt is not None else False
        layout = getattr(frame, "layout", None)
        layout_channels = getattr(layout, "channels", None) if layout is not None else None

        if layout_channels:
            channels = len(layout_channels)
        elif is_planar and raw.ndim == 2 and raw.shape[0] > 1:
            channels = int(raw.shape[0])
        elif not is_planar and raw.ndim == 2 and raw.shape[0] == 1 and raw.shape[1] == CHUNK_SAMPLES * 2:
            channels = 2
        else:
            channels = 1

        # Downmix multi-channel frames properly instead of flattening [L0..LN, R0..RN]!
        if channels > 1:
            if is_planar and raw.ndim == 2 and raw.shape[0] == channels:
                mono = raw.astype(np.float32).mean(axis=0)
            else:
                flat = raw.reshape(-1)
                usable = (flat.size // channels) * channels
                if usable == 0:
                    return b""
                mono = flat[:usable].reshape(-1, channels).astype(np.float32).mean(axis=1)
        else:
            mono = raw.reshape(-1).astype(np.float32)

        if mono.size == 0:
            return b""

        # Normalize sample amplitude to int16 domain [-32768, 32767].
        dt = raw.dtype
        if np.issubdtype(dt, np.floating):
            mono = mono * 32768.0
        elif dt == np.int32 or dt == np.uint32:
            mono = mono / 65536.0
        elif dt == np.uint8:
            mono = (mono - 128.0) * 256.0

        # Resample if incoming frame rate differs from 48 kHz output rate.
        src_rate = int(getattr(frame, "sample_rate", target_rate) or target_rate)
        if src_rate > 0 and target_rate > 0 and src_rate != target_rate and mono.size > 1:
            out_len = max(1, int(round(mono.size * float(target_rate) / float(src_rate))))
            if out_len != mono.size:
                x_old = np.linspace(0.0, 1.0, num=mono.size, endpoint=False, dtype=np.float32)
                x_new = np.linspace(0.0, 1.0, num=out_len, endpoint=False, dtype=np.float32)
                mono = np.interp(x_new, x_old, mono).astype(np.float32)

        vol = max(0.0, min(2.0, float(volume)))
        if vol != 1.0:
            mono = mono * vol

        return np.clip(mono, -32768.0, 32767.0).astype(np.int16).tobytes()

    def _apply_relay_policy(self):
        if not self._effective_relay_only or not self.pc or not hasattr(self.pc, "getTransceivers"):
            return
        from aioice import TransportPolicy

        for transceiver in self.pc.getTransceivers():
            for side in (getattr(transceiver, "sender", None), getattr(transceiver, "receiver", None)):
                dtls = getattr(side, "transport", None)
                ice = getattr(dtls, "transport", None)
                gatherer = getattr(ice, "iceGatherer", None)
                conn = getattr(gatherer, "_connection", None)
                if conn is not None:
                    conn._transport_policy = TransportPolicy.RELAY

    async def create(self):
        if self._relay_only_override is None:
            from app.ice_config import ice_relay_only
            self._effective_relay_only = ice_relay_only()
        else:
            self._effective_relay_only = bool(self._relay_only_override)

        servers_cfg = (
            self._ice_servers if self._ice_servers is not None else ice_server_settings()
        )
        ice = [RTCIceServer(**srv) for srv in servers_cfg]
        self.pc = RTCPeerConnection(RTCConfiguration(iceServers=ice))
        pid = self.peer_device_id

        @self.pc.on("connectionstatechange")
        async def _s():
            if not self.pc or self._closed:
                return
            s = self.pc.connectionState
            logger.info("Peer %s state -> %s", pid[:8], s)
            if self._on_state:
                self._on_state(pid, s)

        @self.pc.on("icecandidate")
        def _ice(c):
            if c is None or self._closed:
                return
            if self._effective_relay_only and getattr(c, "type", None) != "relay":
                return
            if self._on_ice:
                self._on_ice(
                    pid,
                    {
                        "candidate": "candidate:" + candidate_to_sdp(c),
                        "sdpMid": c.sdpMid,
                        "sdpMLineIndex": c.sdpMLineIndex,
                    },
                    "voice",
                )

        @self.pc.on("track")
        def _track(track):
            if track.kind == "audio" and not self._closed:
                logger.info("Received audio from %s", pid[:8])
                self._play_task = asyncio.ensure_future(self._play_loop(track))

        self.pc.addTrack(AudioCaptureTrack(self.audio_io))
        self._apply_relay_policy()

    async def _play_loop(self, track):
        try:
            while not self._closed:
                frame = await track.recv()
                if self._closed:
                    break
                vol = float(getattr(self.audio_io, "remote_volume", 1.0))
                pcm = self.decode_frame_to_mono_pcm16(frame, target_rate=RATE, volume=vol)
                if pcm:
                    self.audio_io.write(pcm)
        except asyncio.CancelledError:
            pass
        except MediaStreamError:
            logger.info("Audio stream ended from %s", self.peer_device_id[:8])
        except Exception as e:
            logger.error("Voice play error [%s]: %s", self.peer_device_id[:8], type(e).__name__)

    async def _wait_ice(self, timeout: float = 4.0):
        waited = 0.0
        while self.pc and self.pc.iceGatheringState != "complete" and waited < timeout:
            await asyncio.sleep(0.05)
            waited += 0.05

    async def _flush_pending_remote_ice(self):
        if not self.pc or not self._pending_remote_ice:
            return
        queued = list(self._pending_remote_ice)
        self._pending_remote_ice.clear()
        for cand in queued:
            try:
                await self.pc.addIceCandidate(cand)
            except Exception as e:
                logger.debug("Deferred ICE error [%s]: %s", self.peer_device_id[:8], e)

    async def create_offer(self) -> str:
        offer = await self.pc.createOffer()
        self._apply_relay_policy()
        await self.pc.setLocalDescription(offer)
        await self._wait_ice()
        sdp = self.pc.localDescription.sdp
        if self._effective_relay_only:
            from app.ice_config import filter_relay_sdp
            sdp = filter_relay_sdp(sdp)
            if "typ relay" not in sdp:
                raise RuntimeError("Relay candidate unavailable in relay-only mode")
        return sdp

    async def handle_offer(self, sdp: str) -> str:
        if not isinstance(sdp, str) or not sdp.strip() or len(sdp) > self.MAX_SDP_CHARS:
            raise ValueError("Invalid or oversized SDP offer")
        if self._effective_relay_only:
            from app.ice_config import filter_relay_sdp
            sdp = filter_relay_sdp(sdp)
        await self.pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="offer"))
        self._apply_relay_policy()
        await self._flush_pending_remote_ice()
        answer = await self.pc.createAnswer()
        self._apply_relay_policy()
        await self.pc.setLocalDescription(answer)
        await self._wait_ice()
        answer_sdp = self.pc.localDescription.sdp
        if self._effective_relay_only:
            from app.ice_config import filter_relay_sdp
            answer_sdp = filter_relay_sdp(answer_sdp)
            if "typ relay" not in answer_sdp:
                raise RuntimeError("Relay candidate unavailable in relay-only mode")
        return answer_sdp

    async def handle_answer(self, sdp: str):
        if not isinstance(sdp, str) or not sdp.strip() or len(sdp) > self.MAX_SDP_CHARS:
            raise ValueError("Invalid or oversized SDP answer")
        if self._effective_relay_only:
            from app.ice_config import filter_relay_sdp
            sdp = filter_relay_sdp(sdp)
        await self.pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="answer"))
        await self._flush_pending_remote_ice()

    async def add_ice(self, data: dict):
        if not isinstance(data, dict):
            return
        c = data.get("candidate", "")
        if not c:
            return
        try:
            if not isinstance(c, str) or len(c) > 8192:
                raise ValueError("Invalid ICE candidate string")
            sdp_mid = data.get("sdpMid")
            if sdp_mid is not None and (not isinstance(sdp_mid, str) or len(sdp_mid) > 64):
                raise ValueError("Invalid sdpMid")
            sdp_mline = data.get("sdpMLineIndex")
            if sdp_mline is not None and (
                isinstance(sdp_mline, bool)
                or not isinstance(sdp_mline, int)
                or not 0 <= sdp_mline <= 64
            ):
                raise ValueError("Invalid sdpMLineIndex")
            if c.startswith("candidate:"):
                c = c[len("candidate:"):]
            candidate = candidate_from_sdp(c)
            if self._effective_relay_only and getattr(candidate, "type", None) != "relay":
                return
            candidate.sdpMid = sdp_mid
            candidate.sdpMLineIndex = sdp_mline
            if self.pc is None or getattr(self.pc, "remoteDescription", True) is None:
                if len(self._pending_remote_ice) < 64:
                    self._pending_remote_ice.append(candidate)
                return
            await self.pc.addIceCandidate(candidate)
        except Exception as e:
            logger.debug("ICE error [%s]: %s", self.peer_device_id[:8], e)

    async def close(self):
        self._closed = True
        self._pending_remote_ice.clear()
        if self._play_task and not self._play_task.done():
            self._play_task.cancel()
        if self.pc:
            try:
                await self.pc.close()
            except Exception:
                pass
            self.pc = None


def decode_audio_frame_to_mono_pcm16(frame, target_rate: int = RATE, volume: float = 1.0) -> bytes:
    """Module-level helper delegating to VoicePeerSession.decode_frame_to_mono_pcm16."""
    return VoicePeerSession.decode_frame_to_mono_pcm16(
        frame, target_rate=target_rate, volume=volume
    )


# ═════════════════════════════════════════════════════════════════════════════
# MAIN MANAGER — Dual isolated loops: Voice (_voice_loop) + Screen (_screen_loop)
# ═════════════════════════════════════════════════════════════════════════════

class WebRTCManager:
    def __init__(self):
        from app.screen_share import ScreenShareManager

        self.audio_io = PyAudioIO()
        self.screen = ScreenShareManager()

        self.is_muted = False
        self.is_deafened = False
        self.remote_volume = 1.0
        self.call_state = CALL_STATE_IDLE

        self.input_device_index: Optional[int] = None
        self.output_device_index: Optional[int] = None

        self.on_signal_generated: Optional[Callable[[dict], None]] = None
        self.on_state_change: Optional[Callable] = None
        self.on_frame_ready: Optional[Callable] = None
        self.on_screen_share_state: Optional[Callable[[bool, str], None]] = None
        self.on_remote_screen_state: Optional[Callable[[str, str, bool], None]] = None
        self.get_peer_public_key: Optional[Callable[[str], Optional[str]]] = None

        self._voice_peers: Dict[str, VoicePeerSession] = {}
        self._pending_ice: Dict[tuple, list] = {}
        self._lifecycle = CallLifecycle()
        self._voice_gate = asyncio.Lock()

        self._voice_loop = asyncio.new_event_loop()
        self._voice_thread = threading.Thread(
            target=lambda: (
                asyncio.set_event_loop(self._voice_loop),
                self._voice_loop.run_forever(),
            ),
            name="Max1mVoiceLoop",
            daemon=True,
        )
        self._voice_thread.start()

        # Isolated Screen-Share loop & peer maps (started lazily on demand)
        self._screen_lock = threading.Lock()
        self._screen_loop: Optional[asyncio.AbstractEventLoop] = None
        self._screen_thread: Optional[threading.Thread] = None
        self._screen_gate: Optional[asyncio.Lock] = None
        self._screen_send_peers: Dict = {}
        self._screen_recv_peers: Dict = {}
        self._pending_screen_ice: Dict[tuple, list] = {}

        logger.info("WebRTCManager initialized")

    def _ensure_screen_loop(self) -> asyncio.AbstractEventLoop:
        lock = getattr(self, "_screen_lock", None)
        if lock is None:
            self._screen_lock = lock = threading.Lock()
        with lock:
            loop = getattr(self, "_screen_loop", None)
            thread = getattr(self, "_screen_thread", None)
            if loop is not None and not loop.is_closed() and thread is not None and thread.is_alive():
                return loop

            new_loop = asyncio.new_event_loop()
            ready = threading.Event()

            def _runner():
                asyncio.set_event_loop(new_loop)
                self._screen_gate = asyncio.Lock()
                ready.set()
                new_loop.run_forever()

            new_thread = threading.Thread(
                target=_runner, name="Max1mScreenLoop", daemon=True
            )
            new_thread.start()
            ready.wait(timeout=2.0)
            self._screen_loop = new_loop
            self._screen_thread = new_thread
            if getattr(self, "_screen_send_peers", None) is None:
                self._screen_send_peers = {}
            if getattr(self, "_screen_recv_peers", None) is None:
                self._screen_recv_peers = {}
            if getattr(self, "_pending_screen_ice", None) is None:
                self._pending_screen_ice = {}
            return new_loop

    def _active_call_pair(self) -> Optional[tuple]:
        lc = getattr(self, "_lifecycle", None)
        if lc is None:
            return None
        with lc._lock:
            return lc._active

    # ─── Signaling helpers ────────────────────────────────────────────────────

    def _send_encrypted_signal(self, to_device_id: str, call_id: str, signal_data: dict):
        if not self.on_signal_generated or not self.get_peer_public_key:
            return
        if not self._lifecycle.matches(to_device_id, call_id):
            return
        pub_key = self.get_peer_public_key(to_device_id)
        if not pub_key:
            return
        try:
            enc, sig = SignalCrypto.encrypt_signal(signal_data, pub_key)
            if not self._lifecycle.matches(to_device_id, call_id):
                return
            self.on_signal_generated(
                {
                    "type": "webrtc_signal",
                    "to_device_id": to_device_id,
                    "encrypted_signal": enc,
                    "signature": sig,
                    "_local_call_id": call_id,
                }
            )
        except Exception as e:
            logger.error("Signal encrypt failed: %s", e)

    def _decrypt_signal(self, data: dict) -> Optional[dict]:
        from_id = data.get("from_device_id", "")
        enc = data.get("encrypted_signal", "")
        sig = data.get("signature", "")
        if not enc or not sig:
            return None
        pub_key = self.get_peer_public_key(from_id) if self.get_peer_public_key else None
        if not pub_key:
            return None
        return SignalCrypto.decrypt_signal(enc, sig, pub_key)

    def _emit_state(self, peer_id: str, call_id: str, state_str: str):
        if self.on_state_change and self._lifecycle.matches(peer_id, call_id):
            self.on_state_change(peer_id, call_id, state_str)

    # ─── Voice calls ──────────────────────────────────────────────────────────

    async def _create_voice_session(self, peer_id: str, call_id: str) -> VoicePeerSession:
        existing = self._voice_peers.get(peer_id)
        if existing and getattr(existing, "call_id", None) == call_id:
            return existing

        # Validate ICE config and peer key BEFORE touching microphone/audio streams.
        ice_servers = ice_server_settings()
        if not self.get_peer_public_key or not self.get_peer_public_key(peer_id):
            raise ValueError("Missing verified peer public key")

        started_here = False
        if not self.audio_io._running:
            self.audio_io.input_device = self.input_device_index
            self.audio_io.output_device = self.output_device_index
            if hasattr(self, "remote_volume"):
                self.audio_io.remote_volume = self.remote_volume
            try:
                self.audio_io.start()
                started_here = True
            except BaseException:
                if self.audio_io._running:
                    self.audio_io.stop()
                raise
            await asyncio.sleep(0.05)
            if not self._lifecycle.matches(peer_id, call_id):
                if not self._voice_peers and self.audio_io._running:
                    self.audio_io.stop()
                return None
            if not self.get_peer_public_key or not self.get_peer_public_key(peer_id):
                if not self._voice_peers and self.audio_io._running:
                    self.audio_io.stop()
                raise ValueError("Peer identity invalidated during audio startup")
            logger.info(
                "Audio IO started: input=%s, output=%s",
                self.input_device_index,
                self.output_device_index,
            )

        ice_cb = getattr(self, "_on_peer_ice", None)
        state_cb = getattr(self, "_on_voice_state", None)
        session = VoicePeerSession(
            peer_id,
            self.audio_io,
            (lambda pid, ice, ch: ice_cb(pid, call_id, ice, ch)) if callable(ice_cb) else None,
            (lambda pid, st: state_cb(pid, call_id, st)) if callable(state_cb) else None,
            ice_servers,
        )
        session.call_id = call_id
        try:
            await session.create()
        except BaseException:
            if (started_here or not self._voice_peers) and self.audio_io._running:
                self.audio_io.stop()
            await session.close()
            raise

        if not self._lifecycle.matches(peer_id, call_id):
            await session.close()
            if not self._voice_peers and self.audio_io._running:
                self.audio_io.stop()
            return None

        self._voice_peers[peer_id] = session
        pending = getattr(self, "_pending_ice", None)
        if pending:
            early = pending.pop((peer_id, call_id), [])
            for item in early:
                await session.add_ice(item)
        logger.info("Voice session created for %s", peer_id[:8])
        return session

    def _on_peer_ice(self, peer_id: str, call_id: str, ice: dict, channel: str = "voice"):
        if not self._lifecycle.matches(peer_id, call_id):
            return
        self._send_encrypted_signal(
            peer_id,
            call_id,
            {"signal_type": "ice", "channel": channel, **ice},
        )

    def _on_voice_state(self, peer_id: str, call_id: str, state_str: str):
        if not self._lifecycle.matches(peer_id, call_id):
            return
        session = self._voice_peers.get(peer_id)
        if not session or getattr(session, "call_id", None) != call_id:
            return
        if state_str == "connected":
            self.call_state = CALL_STATE_CONNECTED
        elif state_str in ("failed", "closed", "disconnected"):
            self.call_state = CALL_STATE_IDLE
        self._emit_state(peer_id, call_id, state_str)

    async def _start_call_async(self, to_device_id: str, call_id: str):
        session = None
        try:
            async with self._voice_gate:
                if not self._lifecycle.matches(to_device_id, call_id):
                    return
                old = self._voice_peers.pop(to_device_id, None)
                if old is not None:
                    await old.close()
                session = await self._create_voice_session(to_device_id, call_id)
            if not session:
                return
            sdp = await session.create_offer()
            if not self._lifecycle.matches(to_device_id, call_id):
                return
            self._send_encrypted_signal(
                to_device_id,
                call_id,
                {"signal_type": "offer", "channel": "voice", "sdp": sdp},
            )
        except asyncio.CancelledError:
            if session and self._voice_peers.get(to_device_id) is not session:
                await session.close()
            if not self._voice_peers and self.audio_io._running and self._lifecycle.idle():
                self.audio_io.stop()
            raise
        except Exception as e:
            if session and self._voice_peers.get(to_device_id) is not session:
                await session.close()
            if not self._voice_peers and self.audio_io._running:
                self.audio_io.stop()
            logger.error("Voice offer failed [%s]: %s", to_device_id[:8], e)
            if self._lifecycle.matches(to_device_id, call_id):
                self._emit_state(to_device_id, call_id, "failed")

    async def _handle_voice_offer(self, from_id: str, call_id: str, sdp: str):
        session = None
        try:
            async with self._voice_gate:
                if not self._lifecycle.matches(from_id, call_id):
                    return
                self.call_state = CALL_STATE_CONNECTING
                old = self._voice_peers.pop(from_id, None)
                if old is not None:
                    await old.close()
                session = await self._create_voice_session(from_id, call_id)
            if not session:
                return
            answer_sdp = await session.handle_offer(sdp)
            if not self._lifecycle.matches(from_id, call_id):
                return
            self._send_encrypted_signal(
                from_id,
                call_id,
                {"signal_type": "answer", "channel": "voice", "sdp": answer_sdp},
            )
        except asyncio.CancelledError:
            if session and self._voice_peers.get(from_id) is not session:
                await session.close()
            if not self._voice_peers and self.audio_io._running and self._lifecycle.idle():
                self.audio_io.stop()
            raise
        except Exception as e:
            if session and self._voice_peers.get(from_id) is not session:
                await session.close()
            if not self._voice_peers and self.audio_io._running:
                self.audio_io.stop()
            logger.error("Handle voice offer failed [%s]: %s", from_id[:8], e)
            if self._lifecycle.matches(from_id, call_id):
                self._emit_state(from_id, call_id, "failed")

    async def _handle_voice_answer(self, from_id: str, call_id: str, sdp: str):
        async with self._voice_gate:
            s = self._voice_peers.get(from_id)
            if not s or getattr(s, "call_id", None) != call_id or not self._lifecycle.matches(from_id, call_id):
                return
        try:
            await s.handle_answer(sdp)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Handle voice answer failed [%s]: %s", from_id[:8], e)
            if self._lifecycle.matches(from_id, call_id):
                self._emit_state(from_id, call_id, "failed")

    async def _handle_voice_ice(self, from_id: str, call_id: str, data: dict):
        s = self._voice_peers.get(from_id)
        if s and getattr(s, "call_id", None) == call_id and self._lifecycle.matches(from_id, call_id):
            await s.add_ice(data)
            return
        if self._lifecycle.matches(from_id, call_id):
            pending = getattr(self, "_pending_ice", None)
            if pending is None:
                self._pending_ice = pending = {}
            bucket = pending.setdefault((from_id, call_id), [])
            if len(bucket) < 64:
                bucket.append(data)

    async def _end_voice_async(self, device_id=None, call_id=None):
        gate = getattr(self, "_voice_gate", None)

        async def _cleanup_body():
            first_err = None
            pending = getattr(self, "_pending_ice", None)
            if device_id:
                if pending is not None:
                    if call_id is not None:
                        pending.pop((device_id, call_id), None)
                    else:
                        for k in [k for k in list(pending.keys()) if k[0] == device_id]:
                            pending.pop(k, None)
                s = self._voice_peers.get(device_id)
                if s and (call_id is None or getattr(s, "call_id", None) == call_id):
                    self._voice_peers.pop(device_id, None)
                    try:
                        await s.close()
                    except BaseException as exc:
                        first_err = exc
            else:
                if pending is not None:
                    pending.clear()
                sessions = list(self._voice_peers.values())
                self._voice_peers.clear()
                for s in sessions:
                    try:
                        await s.close()
                    except BaseException as exc:
                        if first_err is None:
                            first_err = exc

            try:
                if getattr(self, "screen", None) and getattr(self.screen, "is_sharing", False):
                    stop_fn = getattr(self.screen, "stop", None)
                    if callable(stop_fn):
                        await stop_fn()
            finally:
                if not self._voice_peers and (self._lifecycle.idle() or device_id is None or call_id is not None):
                    if getattr(self.audio_io, "_running", True):
                        self.audio_io.stop()
                    self.call_state = CALL_STATE_IDLE

            if first_err is not None:
                raise first_err

        if gate is not None:
            async with gate:
                await _cleanup_body()
        else:
            await _cleanup_body()

    # ─── Public Call Entrypoints ──────────────────────────────────────────────

    def start_call(self, to_device_id: str, call_id: str):
        self._lifecycle.activate(to_device_id, call_id)
        self.call_state = CALL_STATE_CALLING
        try:
            fut = self._lifecycle.submit(
                self._voice_loop,
                to_device_id,
                call_id,
                self._start_call_async(to_device_id, call_id),
            )
            if fut is None:
                raise RuntimeError("Failed to schedule outgoing call")
        except BaseException:
            self.end_call()
            raise

    def prepare_incoming_call(self, from_device_id: str, call_id: str):
        self._lifecycle.activate(from_device_id, call_id)
        self.call_state = CALL_STATE_CONNECTING

    def end_call(self, device_id: Optional[str] = None):
        previous = self._lifecycle.invalidate()
        self.call_state = CALL_STATE_IDLE

        if getattr(self, "screen", None) and getattr(self.screen, "is_sharing", False):
            self.screen.is_sharing = False
            cb = getattr(self, "on_screen_share_state", None)
            if callable(cb):
                cb(False, getattr(self.screen, "quality", "balanced"))
        if getattr(self, "screen", None):
            self.screen.is_receiving = False

        screen_loop = getattr(self, "_screen_loop", None)
        if screen_loop is not None and not screen_loop.is_closed():
            asyncio.run_coroutine_threadsafe(self._close_all_screen_async(), screen_loop)

        prev_peer = device_id or (previous[0] if previous else None)
        prev_cid = previous[1] if previous else None
        asyncio.run_coroutine_threadsafe(
            self._end_voice_async(prev_peer, prev_cid), self._voice_loop
        )

    def handle_encrypted_signal(self, data: dict, call_id: Optional[str] = None):
        from_id = data.get("from_device_id", "")
        if call_id is None:
            active = self._active_call_pair()
            call_id = active[1] if active and active[0] == from_id else ""
        if not call_id or not self._lifecycle.matches(from_id, call_id):
            return
        decrypted = self._decrypt_signal(data)
        if decrypted is None or not self._lifecycle.matches(from_id, call_id):
            return

        channel = decrypted.get("channel", "voice")
        sig_type = decrypted.get("signal_type", "")

        if channel == "voice":
            self._lifecycle.submit(
                self._voice_loop,
                from_id,
                call_id,
                self._route_voice(from_id, call_id, sig_type, decrypted),
            )
        elif channel == "screen":
            screen_loop = self._ensure_screen_loop()
            self._lifecycle.submit(
                screen_loop,
                from_id,
                call_id,
                self._route_screen_async(from_id, call_id, sig_type, decrypted),
            )

    async def _route_voice(self, from_id: str, call_id: str, sig_type: str, d: dict):
        if sig_type == "offer":
            await self._handle_voice_offer(from_id, call_id, d.get("sdp", ""))
        elif sig_type == "answer":
            await self._handle_voice_answer(from_id, call_id, d.get("sdp", ""))
        elif sig_type == "ice":
            await self._handle_voice_ice(from_id, call_id, d)

    # ─── Isolated E2EE Screen Share (channel="screen", _screen_loop) ──────────

    def start_screen_share(
        self,
        quality: str = "balanced",
        monitor_index: int = 0,
        frame_source: Optional[Callable] = None,
    ) -> bool:
        """Start outbound E2EE WebRTC screen share on its own isolated loop & PeerConnection."""
        active = self._active_call_pair()
        if not active or self.call_state != CALL_STATE_CONNECTED:
            logger.warning("start_screen_share: requires connected call")
            return False
        peer_device_id, call_id = active
        from app.screen_share import normalize_preset
        preset_name, _, _, _ = normalize_preset(quality)
        screen_loop = self._ensure_screen_loop()
        self.screen.is_sharing = True
        self.screen.quality = preset_name
        fut = self._lifecycle.submit(
            screen_loop,
            peer_device_id,
            call_id,
            self._start_screen_offer(peer_device_id, call_id, preset_name, monitor_index, frame_source),
        )
        if fut is None:
            self.screen.is_sharing = False
            return False
        if self.on_screen_share_state:
            self.on_screen_share_state(True, preset_name)
        return True

    def set_screen_share_quality(self, quality: str) -> str:
        from app.screen_share import normalize_preset
        preset_name, _, _, _ = normalize_preset(quality)
        self.screen.quality = preset_name
        send_peers = getattr(self, "_screen_send_peers", None) or {}
        for sess in list(send_peers.values()):
            sess.set_quality(preset_name)
        if self.screen.is_sharing and self.on_screen_share_state:
            self.on_screen_share_state(True, preset_name)
        return preset_name

    def stop_screen_share(self, notify_peer: bool = True):
        was_sharing = bool(getattr(self.screen, "is_sharing", False))
        self.screen.is_sharing = False
        active = self._active_call_pair()
        if notify_peer and was_sharing and active:
            peer_device_id, call_id = active
            self._send_encrypted_signal(
                peer_device_id,
                call_id,
                {"signal_type": "stop", "channel": "screen", "direction": "send"},
            )
        screen_loop = getattr(self, "_screen_loop", None)
        if screen_loop is not None and not screen_loop.is_closed():
            asyncio.run_coroutine_threadsafe(self._close_outbound_screen_async(), screen_loop)
        if was_sharing and self.on_screen_share_state:
            self.on_screen_share_state(False, getattr(self.screen, "quality", "balanced"))

    def stop_remote_screen_view(self):
        self.screen.is_receiving = False
        screen_loop = getattr(self, "_screen_loop", None)
        if screen_loop is not None and not screen_loop.is_closed():
            asyncio.run_coroutine_threadsafe(self._close_inbound_screen_async(), screen_loop)

    async def _close_outbound_screen_async(self):
        gate = getattr(self, "_screen_gate", None)
        send_peers = getattr(self, "_screen_send_peers", None)
        if not send_peers:
            return
        if gate is not None:
            async with gate:
                sessions = list(send_peers.values())
                send_peers.clear()
        else:
            sessions = list(send_peers.values())
            send_peers.clear()
        for s in sessions:
            await s.close()

    async def _close_inbound_screen_async(self):
        gate = getattr(self, "_screen_gate", None)
        recv_peers = getattr(self, "_screen_recv_peers", None)
        if not recv_peers:
            return
        if gate is not None:
            async with gate:
                sessions = list(recv_peers.values())
                recv_peers.clear()
        else:
            sessions = list(recv_peers.values())
            recv_peers.clear()
        for s in sessions:
            await s.close()

    async def _close_all_screen_async(self):
        await self._close_outbound_screen_async()
        await self._close_inbound_screen_async()
        pending = getattr(self, "_pending_screen_ice", None)
        if pending is not None:
            pending.clear()
        if getattr(self, "screen", None):
            self.screen.is_sharing = False
            self.screen.is_receiving = False

    async def _start_screen_offer(
        self,
        peer_device_id: str,
        call_id: str,
        quality: str,
        monitor_index: int,
        frame_source: Optional[Callable],
    ):
        from app.screen_share import ScreenPeerSession

        session = None
        try:
            async with self._screen_gate:
                if not self._lifecycle.matches(peer_device_id, call_id):
                    self.screen.is_sharing = False
                    return
                old = self._screen_send_peers.pop(peer_device_id, None)
                if old is not None:
                    await old.close()
                session = ScreenPeerSession(
                    peer_device_id=peer_device_id,
                    call_id=call_id,
                    mode="send",
                    on_ice=self._on_screen_send_ice,
                    on_state=self._on_screen_peer_state,
                    quality=quality,
                    monitor_index=monitor_index,
                    frame_source=frame_source,
                    ice_servers_fn=globals().get("ice_server_settings"),
                )
                await session.create()
                if not self._lifecycle.matches(peer_device_id, call_id):
                    await session.close()
                    self.screen.is_sharing = False
                    return
                self._screen_send_peers[peer_device_id] = session
                early = self._pending_screen_ice.pop((peer_device_id, call_id, "send"), [])
                for item in early:
                    await session.add_ice(item)

            sdp = await session.create_offer()
            if not self._lifecycle.matches(peer_device_id, call_id):
                return
            self._send_encrypted_signal(
                peer_device_id,
                call_id,
                {
                    "signal_type": "offer",
                    "channel": "screen",
                    "sdp": sdp,
                    "quality": quality,
                },
            )
        except asyncio.CancelledError:
            if session and self._screen_send_peers.get(peer_device_id) is not session:
                await session.close()
            raise
        except Exception as e:
            logger.error("Screen share offer failed [%s]: %s", peer_device_id[:8], e)
            self.screen.is_sharing = False
            if session:
                self._screen_send_peers.pop(peer_device_id, None)
                await session.close()
            if self.on_screen_share_state:
                self.on_screen_share_state(False, quality)

    async def _route_screen_async(self, from_dev: str, call_id: str, sig_type: str, signal: dict):
        if sig_type == "offer":
            await self._handle_screen_offer(
                from_dev,
                call_id,
                signal.get("sdp", ""),
                signal.get("quality", "balanced"),
            )
        elif sig_type == "answer":
            await self._handle_screen_answer(from_dev, call_id, signal.get("sdp", ""))
        elif sig_type == "ice":
            await self._handle_screen_ice(from_dev, call_id, signal)
        elif sig_type == "stop":
            await self._handle_screen_stop(from_dev, call_id)

    async def _handle_screen_offer(self, from_dev: str, call_id: str, sdp: str, quality: str):
        from app.screen_share import ScreenPeerSession

        session = None
        try:
            async with self._screen_gate:
                if not self._lifecycle.matches(from_dev, call_id):
                    return
                old = self._screen_recv_peers.pop(from_dev, None)
                if old is not None:
                    await old.close()
                session = ScreenPeerSession(
                    peer_device_id=from_dev,
                    call_id=call_id,
                    mode="recv",
                    on_ice=self._on_screen_recv_ice,
                    on_state=self._on_screen_peer_state,
                    on_video_frame=self._on_remote_screen_frame,
                    on_remote_active=self._on_remote_screen_active,
                    quality=quality,
                    ice_servers_fn=globals().get("ice_server_settings"),
                )
                await session.create()
                if not self._lifecycle.matches(from_dev, call_id):
                    await session.close()
                    return
                self._screen_recv_peers[from_dev] = session
                self.screen.is_receiving = True
                early = self._pending_screen_ice.pop((from_dev, call_id, "recv"), [])
                for item in early:
                    await session.add_ice(item)

            answer_sdp = await session.handle_offer(sdp)
            if not self._lifecycle.matches(from_dev, call_id):
                return
            self._send_encrypted_signal(
                from_dev,
                call_id,
                {"signal_type": "answer", "channel": "screen", "sdp": answer_sdp},
            )
        except asyncio.CancelledError:
            if session and self._screen_recv_peers.get(from_dev) is not session:
                await session.close()
            raise
        except Exception as e:
            logger.error("Handle screen offer failed [%s]: %s", from_dev[:8], e)
            self.screen.is_receiving = False
            if session:
                self._screen_recv_peers.pop(from_dev, None)
                await session.close()
            if self.on_remote_screen_state:
                self.on_remote_screen_state(from_dev, call_id, False)

    async def _handle_screen_answer(self, from_dev: str, call_id: str, sdp: str):
        async with self._screen_gate:
            session = self._screen_send_peers.get(from_dev)
            if not session or session.call_id != call_id or not self._lifecycle.matches(from_dev, call_id):
                return
        try:
            await session.handle_answer(sdp)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Handle screen answer failed [%s]: %s", from_dev[:8], e)
            self.stop_screen_share(notify_peer=False)

    async def _handle_screen_ice(self, from_dev: str, call_id: str, signal: dict):
        if not self._lifecycle.matches(from_dev, call_id):
            return
        role = signal.get("role", "")
        if role == "answerer":
            sess = self._screen_send_peers.get(from_dev)
            if sess and sess.call_id == call_id:
                await sess.add_ice(signal)
                return
            bucket = self._pending_screen_ice.setdefault((from_dev, call_id, "send"), [])
            if len(bucket) < 64:
                bucket.append(signal)
        elif role == "offerer":
            sess = self._screen_recv_peers.get(from_dev)
            if sess and sess.call_id == call_id:
                await sess.add_ice(signal)
                return
            bucket = self._pending_screen_ice.setdefault((from_dev, call_id, "recv"), [])
            if len(bucket) < 64:
                bucket.append(signal)
        else:
            for sess in (self._screen_recv_peers.get(from_dev), self._screen_send_peers.get(from_dev)):
                if sess and sess.call_id == call_id:
                    await sess.add_ice(signal)

    async def _handle_screen_stop(self, from_dev: str, call_id: str):
        if not self._lifecycle.matches(from_dev, call_id):
            return
        async with self._screen_gate:
            sess = self._screen_recv_peers.pop(from_dev, None)
        if sess is not None:
            await sess.close()
        self.screen.is_receiving = False
        if self.on_remote_screen_state:
            self.on_remote_screen_state(from_dev, call_id, False)

    def _on_screen_send_ice(self, peer_device_id: str, call_id: str, cand_dict: dict):
        if not self._lifecycle.matches(peer_device_id, call_id):
            return
        self._send_encrypted_signal(
            peer_device_id,
            call_id,
            {"signal_type": "ice", "channel": "screen", "role": "offerer", **cand_dict},
        )

    def _on_screen_recv_ice(self, peer_device_id: str, call_id: str, cand_dict: dict):
        if not self._lifecycle.matches(peer_device_id, call_id):
            return
        self._send_encrypted_signal(
            peer_device_id,
            call_id,
            {"signal_type": "ice", "channel": "screen", "role": "answerer", **cand_dict},
        )

    def _on_screen_peer_state(self, peer_device_id: str, call_id: str, state_str: str):
        if not self._lifecycle.matches(peer_device_id, call_id):
            return
        if state_str in ("failed", "closed"):
            send_sess = (getattr(self, "_screen_send_peers", None) or {}).get(peer_device_id)
            if send_sess and send_sess.pc and send_sess.pc.connectionState in ("failed", "closed"):
                if self.screen.is_sharing:
                    self.screen.is_sharing = False
                    if self.on_screen_share_state:
                        self.on_screen_share_state(False, getattr(self.screen, "quality", "balanced"))

    def _on_remote_screen_active(self, peer_device_id: str, call_id: str, active: bool):
        if not self._lifecycle.matches(peer_device_id, call_id):
            return
        self.screen.is_receiving = bool(active)
        cb = getattr(self, "on_remote_screen_state", None)
        if callable(cb):
            cb(peer_device_id, call_id, bool(active))

    def _on_remote_screen_frame(
        self, peer_device_id: str, call_id: str, rgb_array, fps: float
    ):
        if not self._lifecycle.matches(peer_device_id, call_id):
            return
        cb = getattr(self, "on_frame_ready", None)
        if callable(cb):
            cb(peer_device_id, call_id, rgb_array, fps)

    # ─── Audio device & mute controls ─────────────────────────────────────────

    def set_mute(self, muted: bool):
        self.is_muted = muted
        self.audio_io.is_muted = muted

    def set_deafen(self, deafened: bool):
        self.is_deafened = deafened
        self.audio_io.is_deafened = deafened
        if deafened:
            self.set_mute(True)

    def set_remote_volume(self, volume: float):
        v = max(0.0, min(2.0, float(volume)))
        self.remote_volume = v
        self.audio_io.remote_volume = v

    def set_volume(self, volume: float):
        self.set_remote_volume(volume)

    def set_input_device(self, idx: Optional[int]):
        self.input_device_index = idx
        if hasattr(self.audio_io, "switch_input_device"):
            self.audio_io.switch_input_device(idx)
        else:
            self.audio_io.input_device = idx

    def set_output_device(self, idx: Optional[int]):
        self.output_device_index = idx
        if hasattr(self.audio_io, "switch_output_device"):
            self.audio_io.switch_output_device(idx)
        else:
            self.audio_io.output_device = idx

    def shutdown(self):
        self._lifecycle.invalidate()
        screen_loop = getattr(self, "_screen_loop", None)
        screen_thread = getattr(self, "_screen_thread", None)
        if screen_loop is not None and not screen_loop.is_closed():
            try:
                fut_scr = asyncio.run_coroutine_threadsafe(self._close_all_screen_async(), screen_loop)
                fut_scr.result(timeout=3.0)
            except Exception:
                pass
            screen_loop.call_soon_threadsafe(screen_loop.stop)
            if screen_thread is not None:
                screen_thread.join(timeout=2.0)

        try:
            fut = asyncio.run_coroutine_threadsafe(self._end_voice_async(), self._voice_loop)
            fut.result(timeout=3.0)
        except Exception:
            pass
        self._voice_loop.call_soon_threadsafe(self._voice_loop.stop)
        self._voice_thread.join(timeout=2.0)

    def is_in_call(self) -> bool:
        return not self._lifecycle.idle() or len(self._voice_peers) > 0

    def get_call_state(self) -> str:
        return self.call_state

    def get_active_peers(self) -> list:
        return list(self._voice_peers.keys())

    @property
    def pa(self):
        return self.audio_io.pa

    def get_audio_devices(self) -> dict:
        return self.audio_io.enumerate_devices()


rtc = WebRTCManager()
