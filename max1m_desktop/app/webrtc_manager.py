"""
WebRTC Manager v9.2 — Clean Voice Calls

Голос:
- aiortc Opus 96kbps — deinterleave stereo→mono (корневой фикс роботизации)
- Чистый recv() без timeout — никаких микрофризов и эха
- playback_buffer(6) + capture_queue(10) — запас для стабильности
- Clean stream teardown: close streams BEFORE join threads

Архитектура звука:
  mic → capture_queue(10) → WebRTC(Opus 96k) send
  WebRTC(Opus 96k) recv → deinterleave → playback_buffer(6) → speaker
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
import pyaudio
from av.audio.frame import AudioFrame
from aiortc import (
    RTCPeerConnection,
    RTCSessionDescription,
    RTCIceCandidate,
    RTCConfiguration,
    RTCIceServer,
    MediaStreamTrack,
)
from aiortc.mediastreams import MediaStreamError

logger = logging.getLogger("max1m.webrtc")

RATE = 48000
CHANNELS = 1
CHUNK_MS = 20
CHUNK_SAMPLES = int(RATE * CHUNK_MS / 1000)

SCREEN_QUALITY_PRESETS = {
    "smooth":   (960,  540,  30),
    "balanced": (1280, 720,  24),
    "sharp":    (1600, 900,  20),
}

CALL_STATE_IDLE       = "idle"
CALL_STATE_CALLING    = "calling"
CALL_STATE_CONNECTING = "connecting"
CALL_STATE_CONNECTED  = "connected"
CALL_STATE_ENDED      = "ended"


class SignalCrypto:
    @staticmethod
    def encrypt_signal(signal_data: dict, recipient_pub_b64: str) -> tuple:
        from app.crypto_box import crypto
        plaintext = json.dumps(signal_data, separators=(",", ":"))
        result = crypto.encrypt_message(plaintext, recipient_pub_b64)
        return result["encrypted_blob"], result["signature"]

    @staticmethod
    def decrypt_signal(enc_b64: str, sig_b64: str, sender_pub_b64: str) -> Optional[dict]:
        from app.crypto_box import crypto
        if not crypto.verify_signature(enc_b64, sig_b64, sender_pub_b64):
            logger.error("Invalid signal signature")
            return None
        try:
            plaintext = crypto.decrypt_message(enc_b64, sender_pub_b64)
            return json.loads(plaintext)
        except Exception as e:
            logger.error("Signal decrypt failed: %s", e)
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


class PyAudioIO:
    def __init__(self):
        self.pa = pyaudio.PyAudio()
        self._input_stream: Optional[pyaudio.Stream] = None
        self._output_stream: Optional[pyaudio.Stream] = None
        self._running = False

        self.input_device: Optional[int] = None
        self.output_device: Optional[int] = None
        self.is_muted = False
        self.is_deafened = False

        self._playback_buffer: deque = deque(maxlen=6)
        self._playback_thread: Optional[threading.Thread] = None
        self._playback_lock = threading.Lock()

        self._capture_queue: deque = deque(maxlen=10)
        self._capture_lock = threading.Lock()

    def start(self):
        if self._running:
            return

        try:
            self._input_stream = self.pa.open(
                format=pyaudio.paInt16, channels=CHANNELS, rate=RATE,
                input=True, input_device_index=self.input_device,
                frames_per_buffer=CHUNK_SAMPLES,
            )
        except Exception as e:
            logger.error("Input device %s failed: %s", self.input_device, e)
            try:
                self._input_stream = self.pa.open(
                    format=pyaudio.paInt16, channels=CHANNELS, rate=RATE,
                    input=True, frames_per_buffer=CHUNK_SAMPLES,
                )
            except Exception as e2:
                logger.error("Default input failed: %s", e2)
                return

        try:
            self._output_stream = self.pa.open(
                format=pyaudio.paInt16, channels=CHANNELS, rate=RATE,
                output=True, output_device_index=self.output_device,
                frames_per_buffer=CHUNK_SAMPLES,
            )
        except Exception as e:
            logger.error("Output device %s failed: %s", self.output_device, e)
            try:
                self._output_stream = self.pa.open(
                    format=pyaudio.paInt16, channels=CHANNELS, rate=RATE,
                    output=True, frames_per_buffer=CHUNK_SAMPLES,
                )
            except Exception as e2:
                logger.error("Default output failed: %s", e2)
                self._input_stream.stop_stream()
                self._input_stream.close()
                self._input_stream = None
                return

        self._running = True
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()
        self._playback_thread = threading.Thread(target=self._playback_loop, daemon=True)
        self._playback_thread.start()

        logger.info("PyAudio started (input=%s, output=%s)",
                    self.input_device, self.output_device)

    def stop(self):
        self._running = False
        if self._input_stream:
            try:
                self._input_stream.stop_stream()
                self._input_stream.close()
            except Exception:
                pass
        if self._output_stream:
            try:
                self._output_stream.stop_stream()
                self._output_stream.close()
            except Exception:
                pass
        self._input_stream = None
        self._output_stream = None
        for t in (self._playback_thread, getattr(self, '_capture_thread', None)):
            if t:
                t.join(timeout=2.0)
        with self._playback_lock:
            self._playback_buffer.clear()
        with self._capture_lock:
            self._capture_queue.clear()
        logger.info("PyAudio stopped")

    def _capture_loop(self):
        silence = b"\x00" * (CHUNK_SAMPLES * CHANNELS * 2)
        while self._running:
            try:
                if not self._input_stream:
                    time.sleep(0.005)
                    continue
                data = self._input_stream.read(CHUNK_SAMPLES, exception_on_overflow=False)
                if self.is_muted:
                    data = silence
                with self._capture_lock:
                    if len(self._capture_queue) >= self._capture_queue.maxlen:
                        try:
                            self._capture_queue.popleft()
                        except IndexError:
                            pass
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

    def write(self, pcm_data: bytes):
        if not self._running or self.is_deafened:
            return
        with self._playback_lock:
            if len(self._playback_buffer) >= self._playback_buffer.maxlen:
                try:
                    self._playback_buffer.popleft()
                except IndexError:
                    pass
            self._playback_buffer.append(pcm_data)

    def _playback_loop(self):
        frame_bytes = CHUNK_SAMPLES * CHANNELS * 2
        silence = b"\x00" * frame_bytes

        while self._running:
            try:
                with self._playback_lock:
                    data = self._playback_buffer.popleft() if self._playback_buffer else None

                if self._output_stream and not self.is_deafened:
                    pcm = data if data is not None else silence
                    self._output_stream.write(pcm, CHUNK_SAMPLES)
                else:
                    if data is None:
                        time.sleep(0.001)

            except Exception as e:
                if self._running:
                    logger.warning("Playback error: %s", e)
                time.sleep(0.005)

    def enumerate_devices(self) -> dict:
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


class AudioCaptureTrack(MediaStreamTrack):
    kind = "audio"

    def __init__(self, audio_io: PyAudioIO):
        super().__init__()
        self.audio_io = audio_io
        self._pts = 0
        self._time_base = fractions.Fraction(1, RATE)
        self._frame_count = 0

    async def recv(self):
        pcm_data = None
        for _ in range(20):
            pcm_data = self.audio_io.read()
            if pcm_data is not None:
                break
            await asyncio.sleep(0.002)

        if pcm_data is None:
            pcm_data = b"\x00" * (CHUNK_SAMPLES * CHANNELS * 2)

        self._frame_count += 1
        if self._frame_count <= 3:
            raw = np.frombuffer(pcm_data, dtype=np.int16)
            logger.info(
                "[AUDIO TX] frame #%d samples=%d min=%d max=%d rms=%.1f",
                self._frame_count, len(raw),
                int(raw.min()), int(raw.max()),
                float(np.sqrt(np.mean(raw.astype(np.float64) ** 2))),
            )

        samples = len(pcm_data) // 2
        frame = AudioFrame(format="s16", layout="mono", samples=samples)
        frame.planes[0].update(pcm_data)
        frame.pts = self._pts
        frame.time_base = self._time_base
        frame.sample_rate = RATE
        self._pts += samples
        return frame


class VoicePeerSession:
    def __init__(self, peer_device_id: str, audio_io: PyAudioIO,
                 on_ice: Callable, on_state: Callable):
        self.peer_device_id = peer_device_id
        self.audio_io = audio_io
        self._on_ice = on_ice
        self._on_state = on_state
        self.pc: Optional[RTCPeerConnection] = None
        self._play_task: Optional[asyncio.Task] = None
        self.remote_dtls_fp: Optional[str] = None

    async def create(self):
        ice = [
            RTCIceServer(urls=["stun:stun.l.google.com:19302"]),
            RTCIceServer(urls=["stun:stun1.l.google.com:19302"]),
        ]
        self.pc = RTCPeerConnection(RTCConfiguration(iceServers=ice))
        pid = self.peer_device_id

        @self.pc.on("connectionstatechange")
        async def _s():
            if not self.pc:
                return
            s = self.pc.connectionState
            logger.info("Peer %s state -> %s", pid[:8], s)
            self._on_state(pid, s)
            if s == "connected":
                SignalCrypto.verify_dtls(self.pc, self.remote_dtls_fp)

        @self.pc.on("icecandidate")
        def _ice(c):
            if c is None:
                return
            self._on_ice(pid, {
                "candidate": c.candidate,
                "sdpMid": c.sdpMid,
                "sdpMLineIndex": c.sdpMLineIndex,
            }, "voice")

        @self.pc.on("track")
        def _track(track):
            if track.kind == "audio":
                logger.info("Received audio from %s", pid[:8])
                self._play_task = asyncio.ensure_future(self._play_loop(track))

        self.pc.addTrack(AudioCaptureTrack(self.audio_io))

    async def _play_loop(self, track):
        frame_count = 0
        try:
            while True:
                frame = await track.recv()
                frame_count += 1

                if frame_count <= 3:
                    arr_raw = frame.to_ndarray()
                    logger.info(
                        "[AUDIO RX] frame #%d dtype=%s shape=%s is_planar=%s sample_rate=%s "
                        "min=%.4f max=%.4f",
                        frame_count, arr_raw.dtype, arr_raw.shape,
                        getattr(frame.format, 'is_planar', '?'),
                        frame.sample_rate,
                        float(arr_raw.min()), float(arr_raw.max()),
                    )

                arr = frame.to_ndarray().flatten()

                if frame.format and not frame.format.is_planar and arr.shape[0] > 1:
                    arr = arr[0::2]

                if arr.dtype in (np.float32, np.float64):
                    arr = np.clip(arr * 32768.0, -32768, 32767).astype(np.int16)
                elif arr.dtype != np.int16:
                    arr = arr.astype(np.int16)

                pcm = arr.tobytes()
                if len(pcm) > 0:
                    self.audio_io.write(pcm)
        except asyncio.CancelledError:
            pass
        except MediaStreamError:
            logger.info("Audio stream ended from %s", self.peer_device_id[:8])
        except Exception as e:
            logger.error("Playback error: %s", e, exc_info=True)

    async def create_offer(self) -> str:
        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)
        await self._wait_ice()
        return self.pc.localDescription.sdp

    async def handle_offer(self, sdp: str) -> str:
        await self.pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="offer"))
        self._extract_fp(sdp)
        answer = await self.pc.createAnswer()
        await self.pc.setLocalDescription(answer)
        await self._wait_ice()
        return self.pc.localDescription.sdp

    async def handle_answer(self, sdp: str):
        await self.pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="answer"))
        self._extract_fp(sdp)

    async def add_ice(self, data: dict):
        c = data.get("candidate", "")
        if not c:
            return
        try:
            await self.pc.addIceCandidate(RTCIceCandidate(
                candidate=c,
                sdpMid=data.get("sdpMid"),
                sdpMLineIndex=data.get("sdpMLineIndex"),
            ))
        except Exception as e:
            logger.error("ICE error: %s", e)

    async def close(self):
        if self._play_task and not self._play_task.done():
            self._play_task.cancel()
        if self.pc:
            try:
                await self.pc.close()
            except Exception:
                pass
            self.pc = None

    async def _wait_ice(self, timeout=4.0):
        w = 0.0
        while self.pc and self.pc.iceGatheringState != "complete" and w < timeout:
            await asyncio.sleep(0.05)
            w += 0.05

    def _extract_fp(self, sdp: str):
        for line in sdp.split("\n"):
            if line.startswith("a=fingerprint:"):
                self.remote_dtls_fp = line.split(" ", 1)[1].strip()
                break


class WebRTCManager:
    def __init__(self):
        self.audio_io = PyAudioIO()
        self._voice_peers: Dict[str, VoicePeerSession] = {}

        from app.screen_share import ScreenShareManager
        self.screen = ScreenShareManager()

        self.is_muted = False
        self.is_deafened = False
        self.remote_volume = 1.0
        self.call_state = CALL_STATE_IDLE

        self.input_device_index: Optional[int] = None
        self.output_device_index: Optional[int] = None

        self.on_signal_generated: Callable[[dict], None] = None
        self.on_state_change: Callable[[str, str], None] = None
        self.on_frame_ready: Callable = None
        self.on_screen_share_state: Callable[[bool, str], None] = None
        self.get_peer_public_key: Callable[[str], Optional[str]] = None

        self._voice_loop = asyncio.new_event_loop()
        self._voice_thread = threading.Thread(
            target=lambda: (
                asyncio.set_event_loop(self._voice_loop),
                self._voice_loop.run_forever(),
            ),
            daemon=True,
        )
        self._voice_thread.start()

        logger.info("WebRTCManager initialized")

    def _run_voice(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._voice_loop)

    def _send_encrypted_signal(self, to_device_id: str, signal_data: dict):
        if not self.on_signal_generated:
            return
        pub_key = (
            self.get_peer_public_key(to_device_id)
            if self.get_peer_public_key
            else None
        )
        if not pub_key:
            return
        try:
            enc, sig = SignalCrypto.encrypt_signal(signal_data, pub_key)
            self.on_signal_generated({
                "type": "webrtc_signal",
                "to_device_id": to_device_id,
                "encrypted_signal": enc,
                "signature": sig,
            })
        except Exception as e:
            logger.error("Signal encrypt failed: %s", e)

    def _decrypt_signal(self, data: dict) -> Optional[dict]:
        from_id = data.get("from_device_id", "")
        enc = data.get("encrypted_signal", "")
        sig = data.get("signature", "")
        if not enc:
            return None
        pub_key = (
            self.get_peer_public_key(from_id)
            if self.get_peer_public_key
            else None
        )
        if not pub_key:
            return None
        return SignalCrypto.decrypt_signal(enc, sig, pub_key)

    async def _create_voice_session(self, peer_id: str) -> VoicePeerSession:
        if peer_id in self._voice_peers:
            logger.info("Reusing existing session for %s", peer_id[:8])
            return self._voice_peers[peer_id]

        if not self.audio_io._running:
            self.audio_io.input_device = self.input_device_index
            self.audio_io.output_device = self.output_device_index
            self.audio_io.start()
            await asyncio.sleep(0.05)
            logger.info("Audio IO started: input=%s, output=%s",
                        self.input_device_index, self.output_device_index)

        session = VoicePeerSession(
            peer_id, self.audio_io, self._on_peer_ice, self._on_voice_state
        )
        await session.create()
        self._voice_peers[peer_id] = session
        logger.info("Voice session created for %s", peer_id[:8])
        return session

    def _on_peer_ice(self, peer_id, ice, channel):
        self._send_encrypted_signal(peer_id, {
            "signal_type": "ice", "channel": channel, **ice
        })

    def _on_voice_state(self, peer_id, state):
        if peer_id not in self._voice_peers:
            return
        if state == "connected":
            self.call_state = CALL_STATE_CONNECTED
        if self.on_state_change:
            self.on_state_change(peer_id, state)

    async def _start_call_async(self, to_device_id):
        self.call_state = CALL_STATE_CALLING
        session = await self._create_voice_session(to_device_id)
        sdp = await session.create_offer()
        self._send_encrypted_signal(to_device_id, {
            "signal_type": "offer", "channel": "voice", "sdp": sdp
        })

    async def _handle_voice_offer(self, from_id, sdp):
        self.call_state = CALL_STATE_CONNECTING
        ex = self._voice_peers.get(from_id)
        if ex and ex.pc and ex.pc.connectionState in ("failed", "closed"):
            await ex.close()
            del self._voice_peers[from_id]
        session = await self._create_voice_session(from_id)
        answer_sdp = await session.handle_offer(sdp)
        self._send_encrypted_signal(from_id, {
            "signal_type": "answer", "channel": "voice", "sdp": answer_sdp
        })

    async def _handle_voice_answer(self, from_id, sdp):
        s = self._voice_peers.get(from_id)
        if s:
            await s.handle_answer(sdp)

    async def _handle_voice_ice(self, from_id, data):
        s = self._voice_peers.get(from_id)
        if s:
            await s.add_ice(data)

    async def _end_voice_async(self, device_id=None):
        if device_id:
            s = self._voice_peers.pop(device_id, None)
            if s:
                await s.close()
        else:
            for s in list(self._voice_peers.values()):
                await s.close()
            self._voice_peers.clear()
        if self.screen.is_sharing:
            await self.screen.stop()
        self.audio_io.stop()
        await asyncio.sleep(0.05)
        self.call_state = CALL_STATE_IDLE

    def handle_encrypted_signal(self, data):
        from_id = data.get("from_device_id", "")
        decrypted = self._decrypt_signal(data)
        if decrypted is None:
            return
        channel = decrypted.get("channel", "voice")
        sig_type = decrypted.get("signal_type")

        if channel == "voice":
            self._run_voice(self._route_voice(from_id, sig_type, decrypted))
        elif channel == "screen":
            self._route_screen(from_id, sig_type, decrypted)

    async def _route_voice(self, from_id, sig_type, d):
        if sig_type == "offer":
            await self._handle_voice_offer(from_id, d.get("sdp", ""))
        elif sig_type == "answer":
            await self._handle_voice_answer(from_id, d.get("sdp", ""))
        elif sig_type == "ice":
            await self._handle_voice_ice(from_id, d)

    def _route_screen(self, from_id, sig_type, d):
        pass

    def start_screen_share(self, quality="balanced", monitor_index=0):
        if self.screen.is_sharing:
            logger.warning("start_screen_share: already sharing")
            return

        peer_ids = list(self._voice_peers.keys())
        if not peer_ids:
            logger.warning("start_screen_share: no active call")
            return

        to_device_id = peer_ids[0]

        def send_frame_via_ws(payload: dict):
            if self.on_signal_generated:
                self.on_signal_generated(payload)

        self.screen.on_send_frame = send_frame_via_ws

        preset = SCREEN_QUALITY_PRESETS.get(quality, SCREEN_QUALITY_PRESETS["balanced"])
        _w, _h, fps = preset

        self.screen.start_sharing(
            to_device_id=to_device_id,
            fps=fps,
            quality=60,
            target_width=_w,
            monitor_index=monitor_index,
        )

        if self.on_signal_generated:
            self.on_signal_generated({
                "type": "screen_control",
                "to_device_id": to_device_id,
                "action": "start",
            })

        if self.on_screen_share_state:
            self.on_screen_share_state(True, quality)

        logger.info("Screen share started → %s (quality=%s, fps=%d)",
                    to_device_id[:8], quality, fps)

    def stop_screen_share(self):
        if not self.screen.is_sharing:
            return

        peer_ids = list(self._voice_peers.keys())

        if peer_ids and self.on_signal_generated:
            self.on_signal_generated({
                "type": "screen_control",
                "to_device_id": peer_ids[0],
                "action": "stop",
            })

        self.screen.stop_sharing()

        if self.on_screen_share_state:
            self.on_screen_share_state(False, "balanced")

        logger.info("Screen share stopped")

    def start_call(self, to_device_id):
        self._run_voice(self._start_call_async(to_device_id))

    def end_call(self, device_id=None):
        self._run_voice(self._end_voice_async(device_id))

    def handle_offer(self, data):
        self._run_voice(self._handle_voice_offer(
            data.get("from_device_id", ""), data.get("sdp", "")
        ))

    def handle_answer(self, data):
        self._run_voice(self._handle_voice_answer(
            data.get("from_device_id", ""), data.get("sdp", "")
        ))

    def handle_ice(self, data):
        self._run_voice(self._handle_voice_ice(
            data.get("from_device_id", ""), data
        ))

    def set_mute(self, muted):
        self.is_muted = muted
        self.audio_io.is_muted = muted

    def set_deafen(self, deafened):
        self.is_deafened = deafened
        self.audio_io.is_deafened = deafened
        if deafened:
            self.set_mute(True)

    def set_remote_volume(self, volume: float):
        self.remote_volume = max(0.0, min(2.0, volume))

    def set_input_device(self, idx):
        self.input_device_index = idx
        if self.audio_io._running:
            self.audio_io.input_device = idx

    def set_output_device(self, idx):
        self.output_device_index = idx
        if self.audio_io._running:
            self.audio_io.output_device = idx

    def shutdown(self):
        try:
            self.end_call()
        except Exception:
            pass

    def is_in_call(self):
        return len(self._voice_peers) > 0

    def get_call_state(self):
        return self.call_state

    def get_active_peers(self):
        return list(self._voice_peers.keys())

    @property
    def pa(self):
        return self.audio_io.pa

    def get_audio_devices(self):
        return self.audio_io.enumerate_devices()


rtc = WebRTCManager()
