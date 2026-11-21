"""
Isolated E2EE WebRTC Screen Sharing (channel="screen").

Architecture:
- Runs on its own dedicated asyncio event loop & OS thread inside WebRTCManager,
  and its own dedicated RTCPeerConnection (separate from voice RTCPeerConnection).
  Video CPU load, keyframes, or packet loss NEVER delay or distort 20 ms Opus voice.
- End-to-end encrypted via WebRTC DTLS-SRTP; SDP/ICE/stop signaling is signed
  and encrypted with SignalCrypto + call_envelope, pinned to the verified peer
  public key and active call_id. Legacy unencrypted WebSocket frame relay is unused.
- Single-slot latest-frame capture mailbox prevents frame queue buildup (zero lag).
"""

import asyncio
import fractions
import logging
import threading
import time
from typing import Callable, Optional, Tuple

import numpy as np

logger = logging.getLogger("max1m.screen")

SCREEN_QUALITY_PRESETS = {
    "smooth":   {"width": 960,  "height": 540,  "fps": 30, "jpeg_quality": 50},
    "balanced": {"width": 1280, "height": 720,  "fps": 24, "jpeg_quality": 60},
    "sharp":    {"width": 1600, "height": 900,  "fps": 20, "jpeg_quality": 75},
}

VIDEO_CLOCK_RATE = 90000


def normalize_preset(quality: str) -> Tuple[str, int, int, int]:
    name = quality if quality in SCREEN_QUALITY_PRESETS else "balanced"
    cfg = SCREEN_QUALITY_PRESETS[name]
    # yuv420p requires even width and height.
    w = max(160, int(cfg["width"]) & ~1)
    h = max(120, int(cfg["height"]) & ~1)
    fps = max(1, min(60, int(cfg["fps"])))
    return name, w, h, fps


class ScreenFrameCapture:
    """Background monitor grabber writing into a single-slot latest-frame mailbox."""

    def __init__(
        self,
        fps: int = 24,
        monitor_index: int = 0,
        frame_source: Optional[Callable[[int], Optional[Tuple[np.ndarray, str]]]] = None,
    ):
        self.fps = max(1, min(60, int(fps)))
        self.monitor_index = max(0, int(monitor_index))
        self._frame_source = frame_source
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._latest: Optional[Tuple[np.ndarray, str]] = None

    def set_fps(self, fps: int) -> None:
        self.fps = max(1, min(60, int(fps)))

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._capture_loop, name="Max1mScreenCapture", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        thread = self._thread
        self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.5)
        with self._lock:
            self._latest = None

    def latest_frame(self) -> Optional[Tuple[np.ndarray, str]]:
        with self._lock:
            return self._latest

    def _grab_qt_fallback(self) -> Optional[Tuple[np.ndarray, str]]:
        try:
            from PySide6.QtGui import QGuiApplication, QImage

            screens = QGuiApplication.screens()
            if not screens:
                return None
            idx = min(self.monitor_index, len(screens) - 1)
            pixmap = screens[idx].grabWindow(0)
            if pixmap.isNull():
                return None
            qimg = pixmap.toImage().convertToFormat(QImage.Format_RGB888)
            w, h = qimg.width(), qimg.height()
            if w <= 0 or h <= 0:
                return None
            bpl = qimg.bytesPerLine()
            ptr = qimg.constBits()
            arr = np.frombuffer(ptr, dtype=np.uint8, count=bpl * h).reshape((h, bpl))
            rgb = arr[:, : w * 3].reshape((h, w, 3)).copy()
            return rgb, "rgb24"
        except Exception:
            return None

    def _capture_loop(self) -> None:
        sct = None
        if self._frame_source is None:
            try:
                import mss

                sct = mss.mss()
            except Exception:
                sct = None

        try:
            while self._running:
                t0 = time.monotonic()
                captured: Optional[Tuple[np.ndarray, str]] = None
                try:
                    if self._frame_source is not None:
                        captured = self._frame_source(self.monitor_index)
                    elif sct is not None:
                        monitors = sct.monitors
                        if len(monitors) > 1:
                            mon_idx = min(self.monitor_index + 1, len(monitors) - 1)
                        else:
                            mon_idx = 0
                        shot = sct.grab(monitors[mon_idx])
                        bgra = np.asarray(shot, dtype=np.uint8)
                        if bgra.ndim == 3 and bgra.shape[2] >= 4 and bgra.shape[0] > 0 and bgra.shape[1] > 0:
                            captured = (bgra.copy(), "bgra")
                    else:
                        captured = self._grab_qt_fallback()
                except Exception as exc:
                    logger.debug("Screen capture tick failed: %s", type(exc).__name__)

                if captured is not None:
                    with self._lock:
                        self._latest = captured

                interval = 1.0 / max(1, self.fps)
                remaining = interval - (time.monotonic() - t0)
                if remaining > 0:
                    time.sleep(min(remaining, 0.1))
                else:
                    time.sleep(0.002)
        finally:
            if sct is not None:
                try:
                    sct.close()
                except Exception:
                    pass


def _build_screen_video_track(
    capture: ScreenFrameCapture,
    width: int,
    height: int,
    fps: int,
):
    from aiortc import MediaStreamTrack
    from av import VideoFrame

    class ScreenVideoTrack(MediaStreamTrack):
        kind = "video"

        def __init__(self):
            super().__init__()
            self._capture = capture
            self._lock = threading.Lock()
            self._target_w = max(160, int(width) & ~1)
            self._target_h = max(120, int(height) & ~1)
            self._fps = max(1, min(60, int(fps)))
            self._time_base = fractions.Fraction(1, VIDEO_CLOCK_RATE)
            self._pts = 0
            self._last_tick: Optional[float] = None
            self._cached_yuv: Optional[VideoFrame] = None
            self._cached_source_id: Optional[int] = None
            self._cached_dims: Optional[Tuple[int, int]] = None

        def update_preset(self, new_w: int, new_h: int, new_fps: int) -> None:
            with self._lock:
                self._target_w = max(160, int(new_w) & ~1)
                self._target_h = max(120, int(new_h) & ~1)
                self._fps = max(1, min(60, int(new_fps)))
            self._capture.set_fps(new_fps)

        async def recv(self):
            with self._lock:
                tw, th, fps_now = self._target_w, self._target_h, self._fps

            frame_interval = 1.0 / max(1, fps_now)
            loop = asyncio.get_running_loop()
            now = loop.time()
            if self._last_tick is None:
                self._last_tick = now
            else:
                target = self._last_tick + frame_interval
                wait = target - now
                if wait > 0:
                    await asyncio.sleep(wait)
                    now = loop.time()
                if now - target > 0.25:
                    self._last_tick = now
                else:
                    self._last_tick = target

            step_pts = max(1, int(round(VIDEO_CLOCK_RATE / max(1, fps_now))))
            item = self._capture.latest_frame()

            if item is not None:
                arr, pix_fmt = item
                src_id = id(arr)
                if (
                    self._cached_yuv is not None
                    and self._cached_source_id == src_id
                    and self._cached_dims == (tw, th)
                ):
                    out_frame = self._cached_yuv
                else:
                    src_h, src_w = arr.shape[:2]
                    # Preserve aspect ratio within target bounding box (even dims).
                    scale = min(tw / max(1, src_w), th / max(1, src_h), 1.0)
                    out_w = max(2, int(round(src_w * scale)) & ~1)
                    out_h = max(2, int(round(src_h * scale)) & ~1)
                    raw_vf = VideoFrame.from_ndarray(arr, format=pix_fmt)
                    out_frame = raw_vf.reformat(width=out_w, height=out_h, format="yuv420p")
                    self._cached_yuv = out_frame
                    self._cached_source_id = src_id
                    self._cached_dims = (tw, th)
            elif self._cached_yuv is not None:
                out_frame = self._cached_yuv
            else:
                blank = np.zeros((th, tw, 3), dtype=np.uint8)
                out_frame = VideoFrame.from_ndarray(blank, format="rgb24").reformat(
                    width=tw, height=th, format="yuv420p"
                )
                self._cached_yuv = out_frame
                self._cached_dims = (tw, th)

            # Emit a shallow packet-timestamped frame with monotonic PTS.
            plane_arr = out_frame.to_ndarray(format="yuv420p")
            pkt_frame = VideoFrame.from_ndarray(plane_arr, format="yuv420p")
            pkt_frame.pts = self._pts
            pkt_frame.time_base = self._time_base
            self._pts += step_pts
            return pkt_frame

        def stop(self):
            super().stop()
            self._capture.stop()

    return ScreenVideoTrack()


class ScreenPeerSession:
    """Dedicated RTCPeerConnection for E2EE screen sharing (isolated from voice)."""

    MAX_SDP_CHARS = 64 * 1024

    def __init__(
        self,
        peer_device_id: str,
        call_id: str,
        mode: str,
        on_ice: Callable,
        on_state: Callable,
        on_video_frame: Optional[Callable[[str, str, np.ndarray, float], None]] = None,
        on_remote_active: Optional[Callable[[str, str, bool], None]] = None,
        quality: str = "balanced",
        monitor_index: int = 0,
        frame_source: Optional[Callable[[int], Optional[Tuple[np.ndarray, str]]]] = None,
        relay_only: Optional[bool] = None,
        ice_servers_fn: Optional[Callable[[], list]] = None,
    ):
        self.peer_device_id = peer_device_id
        self.call_id = call_id
        self.mode = mode  # "send" or "recv"
        self.quality, self.width, self.height, self.fps = normalize_preset(quality)
        self.monitor_index = max(0, int(monitor_index))
        self._frame_source = frame_source
        self._on_ice = on_ice
        self._on_state = on_state
        self._on_video_frame = on_video_frame
        self._on_remote_active = on_remote_active
        self._relay_only_override = relay_only
        self._effective_relay_only = bool(relay_only) if relay_only is not None else False
        self._ice_servers_fn = ice_servers_fn
        self._pending_remote_ice = []
        self.pc = None
        self._capture: Optional[ScreenFrameCapture] = None
        self._track = None
        self._recv_task: Optional[asyncio.Task] = None
        self._closed = False

    def _apply_relay_policy(self) -> None:
        if not self._effective_relay_only or not self.pc or not hasattr(self.pc, "getTransceivers"):
            return
        from aioice import TransportPolicy

        for transceiver in self.pc.getTransceivers():
            for side in (getattr(transceiver, "sender", None), getattr(transceiver, "receiver", None)):
                dtls = getattr(side, "transport", None)
                ice_transport = getattr(dtls, "transport", None)
                gatherer = getattr(ice_transport, "iceGatherer", None)
                conn = getattr(gatherer, "_connection", None)
                if conn is not None:
                    conn._transport_policy = TransportPolicy.RELAY

    async def create(self) -> None:
        from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection
        from aiortc.sdp import candidate_to_sdp
        from app.ice_config import ice_relay_only, ice_server_settings

        if self._relay_only_override is None:
            self._effective_relay_only = ice_relay_only()
        else:
            self._effective_relay_only = bool(self._relay_only_override)

        servers_cfg = (
            self._ice_servers_fn() if self._ice_servers_fn is not None else ice_server_settings()
        )
        ice = [RTCIceServer(**srv) for srv in servers_cfg]
        self.pc = RTCPeerConnection(RTCConfiguration(iceServers=ice))
        pid = self.peer_device_id
        cid = self.call_id

        @self.pc.on("connectionstatechange")
        async def _on_conn_state():
            if not self.pc or self._closed:
                return
            st = self.pc.connectionState
            self._on_state(pid, cid, st)
            if st in ("failed", "closed", "disconnected") and self.mode == "recv" and self._on_remote_active:
                self._on_remote_active(pid, cid, False)

        @self.pc.on("icecandidate")
        def _on_cand(c):
            if c is None or self._closed:
                return
            if self._effective_relay_only and getattr(c, "type", None) != "relay":
                return
            self._on_ice(
                pid,
                cid,
                {
                    "candidate": "candidate:" + candidate_to_sdp(c),
                    "sdpMid": c.sdpMid,
                    "sdpMLineIndex": c.sdpMLineIndex,
                },
            )

        @self.pc.on("track")
        def _on_track(track):
            if track.kind == "video" and not self._closed:
                if self._on_remote_active:
                    self._on_remote_active(pid, cid, True)
                self._recv_task = asyncio.ensure_future(self._recv_video_loop(track))

        if self.mode == "send":
            self._capture = ScreenFrameCapture(
                fps=self.fps,
                monitor_index=self.monitor_index,
                frame_source=self._frame_source,
            )
            self._capture.start()
            self._track = _build_screen_video_track(
                self._capture, self.width, self.height, self.fps
            )
            self.pc.addTrack(self._track)

        self._apply_relay_policy()

    def set_quality(self, quality: str) -> str:
        name, w, h, fps = normalize_preset(quality)
        self.quality, self.width, self.height, self.fps = name, w, h, fps
        if self._track is not None:
            self._track.update_preset(w, h, fps)
        return name

    async def _recv_video_loop(self, track) -> None:
        from aiortc.mediastreams import MediaStreamError

        frames_in_window = 0
        window_start = time.monotonic()
        measured_fps = 0.0
        try:
            while not self._closed:
                frame = await track.recv()
                if self._closed:
                    break
                rgb = frame.to_ndarray(format="rgb24")
                if rgb.size == 0 or rgb.ndim != 3 or rgb.shape[2] != 3:
                    continue
                frames_in_window += 1
                now = time.monotonic()
                elapsed = now - window_start
                if elapsed >= 0.5:
                    measured_fps = frames_in_window / elapsed
                    frames_in_window = 0
                    window_start = now
                if self._on_video_frame:
                    self._on_video_frame(self.peer_device_id, self.call_id, rgb, measured_fps)
        except asyncio.CancelledError:
            pass
        except MediaStreamError:
            pass
        except Exception as exc:
            logger.error("Screen video receive error: %s", type(exc).__name__)
        finally:
            if not self._closed and self._on_remote_active:
                self._on_remote_active(self.peer_device_id, self.call_id, False)

    async def _wait_ice(self, timeout: float = 4.0) -> None:
        waited = 0.0
        while self.pc and self.pc.iceGatheringState != "complete" and waited < timeout:
            await asyncio.sleep(0.05)
            waited += 0.05

    async def _flush_pending_remote_ice(self) -> None:
        if not self.pc or not self._pending_remote_ice:
            return
        queued = list(self._pending_remote_ice)
        self._pending_remote_ice.clear()
        for cand in queued:
            try:
                await self.pc.addIceCandidate(cand)
            except Exception as exc:
                logger.debug("Screen deferred ICE error: %s", type(exc).__name__)

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
                raise RuntimeError("Relay candidate unavailable for screen share")
        return sdp

    async def handle_offer(self, sdp: str) -> str:
        from aiortc import RTCSessionDescription

        if not isinstance(sdp, str) or not sdp.strip() or len(sdp) > self.MAX_SDP_CHARS:
            raise ValueError("Invalid screen SDP offer")
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
                raise RuntimeError("Relay candidate unavailable for screen share")
        return answer_sdp

    async def handle_answer(self, sdp: str) -> None:
        from aiortc import RTCSessionDescription

        if not isinstance(sdp, str) or not sdp.strip() or len(sdp) > self.MAX_SDP_CHARS:
            raise ValueError("Invalid screen SDP answer")
        if self._effective_relay_only:
            from app.ice_config import filter_relay_sdp

            sdp = filter_relay_sdp(sdp)
        await self.pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="answer"))
        await self._flush_pending_remote_ice()

    async def add_ice(self, data: dict) -> None:
        from aiortc.sdp import candidate_from_sdp

        if not isinstance(data, dict):
            return
        c = data.get("candidate", "")
        if not c:
            return
        try:
            if not isinstance(c, str) or len(c) > 8192:
                raise ValueError("Invalid ICE candidate")
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
        except Exception as exc:
            logger.debug("Screen ICE rejected: %s", type(exc).__name__)

    async def close(self) -> None:
        self._closed = True
        self._pending_remote_ice.clear()
        if self._track is not None:
            try:
                self._track.stop()
            except Exception:
                pass
            self._track = None
        if self._capture is not None:
            try:
                self._capture.stop()
            except Exception:
                pass
            self._capture = None
        if self._recv_task and not self._recv_task.done():
            self._recv_task.cancel()
        if self.pc is not None:
            try:
                await self.pc.close()
            except Exception:
                pass
            self.pc = None


class ScreenShareManager:
    """State tracker for active E2EE WebRTC screen share; legacy cleartext WS hooks are inert."""

    def __init__(self):
        self.is_sharing = False
        self.is_receiving = False
        self.quality = "balanced"
        self.on_send_frame = None
        self.on_frame_received = None

    async def stop(self) -> None:
        self.is_sharing = False
        self.is_receiving = False

    def stop_sharing(self) -> None:
        self.is_sharing = False

    def stop_receiving(self) -> None:
        self.is_receiving = False

    def handle_incoming_frame(self, data: dict) -> None:
        # Unencrypted legacy WebSocket frames are never accepted.
        return

    def handle_incoming_frame_bytes(self, jpeg_bytes: bytes) -> None:
        return

    def handle_control(self, data: dict) -> None:
        return
