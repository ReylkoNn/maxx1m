"""
Screen Share v2.0 — Binary WebSocket, High FPS, Voice-Isolated

Архитектура:
- Отправка: mss → numpy → cv2 JPEG → binary WS frame (без base64/JSON)
- Приём: binary WS frame → cv2 decode → QImage → UI
- Полная изоляция от voice channel (отдельный тип сообщений)
- Адаптивное качество: auto-downscale при лагах

Поток:
  Sender:  mss → numpy → cv2 JPEG → on_frame_callback(jpeg_bytes)
  Receiver: jpeg_bytes → cv2 decode → on_frame_decoded(numpy_frame)
"""

import logging
import threading
import time
from typing import Callable, Optional

import numpy as np

logger = logging.getLogger("max1m.screen")

SCREEN_QUALITY_PRESETS = {
    "smooth":   {"width": 960,  "height": 540,  "fps": 30, "jpeg_quality": 50},
    "balanced": {"width": 1280, "height": 720,  "fps": 24, "jpeg_quality": 60},
    "sharp":    {"width": 1600, "height": 900,  "fps": 20, "jpeg_quality": 75},
}


class ScreenShareSender:
    """Захватывает экран и шлёт JPEG кадры через callback."""

    def __init__(self, fps: int = 24, quality: int = 60, target_width: int = 1280):
        self.fps = fps
        self.quality = quality
        self.target_width = target_width
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_frame: Optional[Callable[[bytes], None]] = None
        self._monitor_index = 0
        self._frame_count = 0
        self._actual_fps = 0.0
        self._last_fps_time = time.perf_counter()

    def start(self, on_frame: Callable[[bytes], None], monitor_index: int = 0):
        if self._running:
            return
        self._on_frame = on_frame
        self._monitor_index = monitor_index
        self._running = True
        self._frame_count = 0
        self._last_fps_time = time.perf_counter()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        logger.info("Screen capture started (fps=%d, quality=%d, target_w=%d)",
                    self.fps, self.quality, self.target_width)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("Screen capture stopped (sent %d frames)", self._frame_count)

    def set_quality(self, quality: int):
        self.quality = max(10, min(100, quality))

    def set_fps(self, fps: int):
        self.fps = max(1, min(60, fps))

    def get_stats(self) -> dict:
        return {
            "fps": round(self._actual_fps, 1),
            "frames_sent": self._frame_count,
        }

    def _capture_loop(self):
        try:
            import mss
            import cv2
        except ImportError:
            logger.error("mss or cv2 not installed")
            return

        sct = mss.mss()
        interval = 1.0 / self.fps

        while self._running:
            try:
                start = time.perf_counter()

                monitor = sct.monitors[self._monitor_index + 1]
                screenshot = sct.grab(monitor)
                frame = np.array(screenshot)[:, :, :3]

                orig_h, orig_w = frame.shape[:2]
                if self.target_width > 0 and orig_w > self.target_width:
                    scale = self.target_width / orig_w
                    new_h = int(orig_h * scale)
                    frame = cv2.resize(frame, (self.target_width, new_h),
                                       interpolation=cv2.INTER_LINEAR)

                _, buffer = cv2.imencode(
                    ".jpg", frame,
                    [cv2.IMWRITE_JPEG_QUALITY, self.quality,
                     cv2.IMWRITE_JPEG_OPTIMIZE, 0]
                )
                jpeg_bytes = buffer.tobytes()

                if self._on_frame:
                    self._on_frame(jpeg_bytes)

                self._frame_count += 1
                now = time.perf_counter()
                elapsed = now - self._last_fps_time
                if elapsed >= 1.0:
                    self._actual_fps = self._frame_count / elapsed
                    self._frame_count = 0
                    self._last_fps_time = now

                sleep_time = interval - (time.perf_counter() - start)
                if sleep_time > 0:
                    time.sleep(sleep_time)

            except Exception as e:
                logger.error("Capture error: %s", e)
                time.sleep(0.05)

        sct.close()


class ScreenShareReceiver:
    """Получает JPEG кадры и декодирует."""

    def __init__(self):
        self._running = False
        self._on_frame: Optional[Callable[[np.ndarray], None]] = None
        self._frame_count = 0
        self._actual_fps = 0.0
        self._last_fps_time = time.perf_counter()

    def start(self, on_frame: Callable[[np.ndarray], None]):
        self._running = True
        self._on_frame = on_frame
        self._frame_count = 0
        self._last_fps_time = time.perf_counter()
        logger.info("Screen receiver started")

    def stop(self):
        self._running = False
        logger.info("Screen receiver stopped (received %d frames)", self._frame_count)

    def process_frame_bytes(self, jpeg_bytes: bytes):
        if not self._running or not self._on_frame:
            return
        try:
            import cv2
            nparr = np.frombuffer(jpeg_bytes, np.uint8)
            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if frame is not None:
                self._on_frame(frame)
                self._frame_count += 1
                now = time.perf_counter()
                elapsed = now - self._last_fps_time
                if elapsed >= 1.0:
                    self._actual_fps = self._frame_count / elapsed
                    self._frame_count = 0
                    self._last_fps_time = now
        except Exception as e:
            logger.error("Frame decode error: %s", e)

    def process_frame(self, b64_data: str):
        """Legacy: base64 строка."""
        import base64
        try:
            jpeg_bytes = base64.b64decode(b64_data)
            self.process_frame_bytes(jpeg_bytes)
        except Exception as e:
            logger.error("Base64 decode error: %s", e)

    def get_stats(self) -> dict:
        return {"fps": round(self._actual_fps, 1)}


class ScreenShareManager:
    """Управляет демкой. Полностью изолирован от voice channel."""

    def __init__(self):
        self.sender = ScreenShareSender()
        self.receiver = ScreenShareReceiver()
        self.is_sharing = False
        self.is_receiving = False

        self.on_send_frame: Optional[Callable[[dict], None]] = None
        self.on_frame_received: Optional[Callable[[np.ndarray], None]] = None

        self._to_device_id = ""

    def start_sharing(self, to_device_id: str, fps: int = 24,
                      quality: int = 60, target_width: int = 1280,
                      monitor_index: int = 0):
        if self.is_sharing:
            return

        self._to_device_id = to_device_id

        def on_capture_frame(jpeg_bytes: bytes):
            if self.on_send_frame:
                self.on_send_frame({
                    "type": "screen_frame",
                    "to_device_id": self._to_device_id,
                    "frame": jpeg_bytes,
                })

        self.sender.fps = fps
        self.sender.quality = quality
        self.sender.target_width = target_width
        self.sender.start(on_capture_frame, monitor_index)
        self.is_sharing = True
        logger.info("Screen sharing started → %s (fps=%d, quality=%d)",
                    to_device_id[:8], fps, quality)

    def stop_sharing(self):
        self.sender.stop()
        self.is_sharing = False
        logger.info("Screen sharing stopped")

    def start_receiving(self, on_frame: Callable[[np.ndarray], None]):
        self.on_frame_received = on_frame
        self.receiver.start(on_frame)
        self.is_receiving = True

    def stop_receiving(self):
        self.receiver.stop()
        self.is_receiving = False

    def handle_incoming_frame(self, data: dict):
        frame_b64 = data.get("frame")
        if frame_b64:
            self.receiver.process_frame(frame_b64)

    def handle_incoming_frame_bytes(self, jpeg_bytes: bytes):
        self.receiver.process_frame_bytes(jpeg_bytes)

    def handle_control(self, data: dict):
        action = data.get("action")
        if action == "start":
            self.start_receiving(self.on_frame_received or (lambda f: None))
        elif action == "stop":
            self.stop_receiving()

    def change_monitor(self, monitor_index: int):
        if self.is_sharing:
            self.sender._monitor_index = monitor_index

    def change_quality(self, profile: str):
        preset = SCREEN_QUALITY_PRESETS.get(profile)
        if preset and self.is_sharing:
            self.sender.fps = preset["fps"]
            self.sender.quality = preset["jpeg_quality"]
            self.sender.target_width = preset["width"]

    async def stop(self):
        self.stop_sharing()
        self.stop_receiving()
