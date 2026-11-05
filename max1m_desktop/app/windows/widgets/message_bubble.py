from PySide6.QtCore import Qt, QRect, Signal, QPoint
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QVBoxLayout, QLabel, QSizePolicy,
    QPushButton, QMenu, QWidget
)
from PySide6.QtGui import (
    QFontMetrics, QPixmap, QPainter, QPainterPath,
    QCursor, QColor, QPen, QIcon
)
from PySide6.QtSvg import QSvgRenderer
from pathlib import Path
from datetime import datetime
import wave
import io
import struct

ICONS_PATH = Path(__file__).parent.parent.parent / "assets" / "icons"


def _render_svg(svg_name: str, color: str, size: int = 16) -> QIcon:
    svg_path = ICONS_PATH / svg_name
    if not svg_path.exists():
        return QIcon()
    try:
        svg_content = svg_path.read_text(encoding="utf-8")
        svg_colored = svg_content.replace("currentColor", color)
        renderer = QSvgRenderer(svg_colored.encode("utf-8"))
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)
        renderer.render(painter)
        painter.end()
        return QIcon(pixmap)
    except Exception as e:
        print(f"[SVG] Ошибка рендера {svg_name}: {e}")
        return QIcon()


# ============================================================================
# VOICE PLAY BUTTON
# ============================================================================

class _VoicePlayButton(QPushButton):
    def __init__(self, is_mine: bool = True, parent=None):
        super().__init__(parent)
        self.is_mine = is_mine
        self._playing = False
        self.setFixedSize(36, 36)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.NoFocus)
        self.setObjectName("VoicePlayBtn")
        self.setText("")
        self._render_icon()

    def set_playing(self, playing: bool):
        if self._playing != playing:
            self._playing = playing
            self._render_icon()

    def _render_icon(self):
        from app.theme import get_theme
        t = get_theme()
        color = t.get("text_soft", "#a4aab8")
        icon_name = "pause.svg" if self._playing else "play.svg"
        icon = _render_svg(icon_name, color, 16)
        self.setIcon(icon)
        self.setIconSize(QPixmap(16, 16).size())
        self.setText("")

    def refresh_theme(self):
        self._render_icon()


# ============================================================================
# VOICE WAVEFORM
# ============================================================================

class VoiceWaveform(QWidget):
    seek_requested = Signal(float)

    BAR_COUNT = 30
    BAR_WIDTH = 3
    BAR_GAP = 2
    BAR_MIN_H = 3
    BAR_MAX_H = 28

    def __init__(self, duration: float, is_mine: bool, parent=None):
        super().__init__(parent)
        self.duration = duration
        self.is_mine = is_mine
        self._progress = 0.0
        self._bars = []
        self._is_playing = False

        total_w = self.BAR_COUNT * (self.BAR_WIDTH + self.BAR_GAP) - self.BAR_GAP
        self.setFixedSize(total_w, self.BAR_MAX_H + 4)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.NoFocus)
        self._generate_placeholder_bars()

    def _generate_placeholder_bars(self):
        import random
        rng = random.Random(42)
        self._bars = [rng.uniform(0.15, 0.9) for _ in range(self.BAR_COUNT)]
        self.update()

    def load_waveform_from_wav(self, wav_data: bytes):
        try:
            wav_io = io.BytesIO(wav_data)
            with wave.open(wav_io, 'rb') as wf:
                n_frames = wf.getnframes()
                sampwidth = wf.getsampwidth()
                n_channels = wf.getnchannels()
                raw = wf.readframes(n_frames)

            if sampwidth == 2:
                fmt = f"{len(raw) // 2}h"
                samples = struct.unpack(fmt, raw)
            elif sampwidth == 1:
                fmt = f"{len(raw)}B"
                samples = tuple(s - 128 for s in struct.unpack(fmt, raw))
            else:
                self._generate_placeholder_bars()
                return

            if n_channels > 1:
                samples = samples[::n_channels]

            if not samples:
                self._generate_placeholder_bars()
                return

            chunk_size = max(1, len(samples) // self.BAR_COUNT)
            bars = []
            max_val = 32768 if sampwidth == 2 else 128

            for i in range(self.BAR_COUNT):
                chunk = samples[i * chunk_size: (i + 1) * chunk_size]
                if chunk:
                    rms = (sum(s * s for s in chunk) / len(chunk)) ** 0.5
                    bars.append(rms / max_val)
                else:
                    bars.append(0.1)

            max_bar = max(bars) if max(bars) > 0 else 1.0
            self._bars = [b / max_bar for b in bars]
            self.update()

        except Exception as e:
            print(f"[WAVEFORM] Ошибка анализа: {e}")
            self._generate_placeholder_bars()

    def set_progress(self, progress: float):
        self._progress = max(0.0, min(1.0, progress))
        self.update()

    def set_playing(self, playing: bool):
        self._is_playing = playing
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)

        from app.theme import get_theme
        t = get_theme()

        if self.is_mine:
            color_played   = QColor(255, 255, 255, 220)
            color_unplayed = QColor(255, 255, 255, 70)
        else:
            accent = QColor(t.get("accent", "#6c748a"))
            color_played   = QColor(accent.red(), accent.green(), accent.blue(), 220)
            color_unplayed = QColor(accent.red(), accent.green(), accent.blue(), 80)

        w = self.width()
        h = self.height()
        center_y = h / 2
        progress_x = self._progress * w

        for i, amplitude in enumerate(self._bars):
            x = i * (self.BAR_WIDTH + self.BAR_GAP)
            bar_h = max(self.BAR_MIN_H, int(amplitude * self.BAR_MAX_H))
            y = center_y - bar_h / 2
            color = color_played if (
                x + self.BAR_WIDTH <= progress_x or x < progress_x
            ) else color_unplayed
            painter.setBrush(color)
            painter.drawRoundedRect(
                int(x), int(y), self.BAR_WIDTH, bar_h, 1.5, 1.5
            )

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            progress = event.position().x() / self.width()
            progress = max(0.0, min(1.0, progress))
            self._progress = progress
            self.update()
            self.seek_requested.emit(progress)
        super().mousePressEvent(event)


# ============================================================================
# IMAGE SKELETON
# ============================================================================

class _ImageSkeleton(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(320, 200)
        self.setFocusPolicy(Qt.NoFocus)
        self._alpha = 40
        self._direction = 1

        from PySide6.QtCore import QTimer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._pulse)
        self._timer.start(40)

    def _pulse(self):
        self._alpha += self._direction * 4
        if self._alpha >= 80:
            self._alpha = 80
            self._direction = -1
        elif self._alpha <= 20:
            self._alpha = 20
            self._direction = 1
        self.update()

    def stop(self):
        self._timer.stop()

    def paintEvent(self, event):
        from app.theme import get_theme
        t = get_theme()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)

        base = QColor(t.get("bg_panel_2", "#161920"))
        painter.setBrush(base)
        painter.drawRoundedRect(0, 0, self.width(), self.height(), 8, 8)

        shimmer = QColor(t.get("text_dim", "#777e8e"))
        shimmer.setAlpha(self._alpha)
        painter.setBrush(shimmer)
        painter.drawRoundedRect(
            12, self.height() // 2 - 6,
            self.width() - 24, 12, 6, 6
        )

        icon_color = QColor(t.get("text_dim", "#777e8e"))
        icon_color.setAlpha(self._alpha + 20)
        painter.setBrush(icon_color)
        cx = self.width() // 2
        cy = self.height() // 2 - 20
        painter.drawEllipse(cx - 16, cy - 16, 32, 32)


# ============================================================================
# CLICKABLE IMAGE LABEL
# ============================================================================

class _ClickableImageLabel(QLabel):
    clicked = Signal(QPixmap)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.NoFocus)
        self._pixmap_original = None

    def set_pixmap_original(self, pixmap: QPixmap):
        self._pixmap_original = pixmap

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self._pixmap_original:
            self.clicked.emit(self._pixmap_original)
        super().mousePressEvent(event)


# ============================================================================
# MESSAGE BUBBLE
# ============================================================================

class MessageBubble(QFrame):
    reply_requested = Signal(str, str, str)
    delete_requested = Signal(str)
    voice_play_requested = Signal(object, object)
    voice_seek_requested = Signal(object, float)
    scroll_to_msg_requested = Signal(str)
    image_view_requested = Signal(QPixmap)

    def __init__(
            self,
            text: str,
            is_mine: bool = True,
            timestamp: str = None,
            is_read: bool = False,
            reply_to_text: str = None,
            reply_to_sender: str = None,
            reply_to_msg_id: str = None,
            voice_data: bytes = None,
            voice_duration: float = None,
            caption: str = None,
    ):
        super().__init__()

        self.is_mine = is_mine
        self.is_read = is_read
        self.msg_id = None
        self._text = text
        self._sender = None
        self._voice_data = voice_data
        self._voice_duration = voice_duration or 0
        self._is_playing = False
        self._reply_to_msg_id = reply_to_msg_id
        self._caption = caption
        self._skeleton = None

        self.setFocusPolicy(Qt.NoFocus)
        self.setObjectName("MessageBubbleRow")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 3, 0, 3)

        self.bubble = QFrame()
        self.bubble.setFocusPolicy(Qt.NoFocus)
        self.bubble.setObjectName("BubbleOut" if is_mine else "BubbleIn")
        self.bubble.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)

        self.bubble_layout = QVBoxLayout(self.bubble)
        self.bubble_layout.setContentsMargins(10, 6, 10, 6)
        self.bubble_layout.setSpacing(4)

        # --- Reply блок ---
        self.reply_frame = None
        if reply_to_text or reply_to_sender:
            self._create_reply_block(reply_to_text, reply_to_sender)

        # --- Skeleton ---
        self._skeleton = _ImageSkeleton()
        self._skeleton.setVisible(False)
        self.bubble_layout.addWidget(self._skeleton)

        # --- Картинка ---
        self.image_label = _ClickableImageLabel()
        self.image_label.setVisible(False)
        self.image_label.clicked.connect(self._on_image_clicked)
        self.bubble_layout.addWidget(self.image_label)

        # --- Caption ---
        self.caption_label = QLabel()
        self.caption_label.setObjectName("BubbleCaption")
        self.caption_label.setWordWrap(True)
        self.caption_label.setFocusPolicy(Qt.NoFocus)
        self.caption_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.caption_label.setVisible(False)
        self.bubble_layout.addWidget(self.caption_label)

        # --- Голосовой плеер ---
        self.voice_frame = None
        self.play_btn = None
        self.waveform = None
        self.duration_label = None

        if voice_data is not None or voice_duration:
            self._create_voice_player(voice_duration or 0)
            if voice_data and self.waveform:
                self.waveform.load_waveform_from_wav(voice_data)

        # --- Текст ---
        self.msg_label = QLabel(text)
        self.msg_label.setObjectName("BubbleText")
        self.msg_label.setWordWrap(True)
        self.msg_label.setFocusPolicy(Qt.NoFocus)
        self.msg_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        if not text or voice_data is not None or voice_duration:
            self.msg_label.setVisible(False)
        else:
            font = self.msg_label.font()
            font.setPixelSize(14)
            self.msg_label.setFont(font)
            metrics = QFontMetrics(font)
            rect = metrics.boundingRect(
                QRect(0, 0, 420, 10000), Qt.TextWordWrap, text
            )
            self.msg_label.setFixedWidth(min(rect.width() + 8, 460))

        # --- Мета-строка ---
        self.meta_layout = QHBoxLayout()
        self.meta_layout.setContentsMargins(0, 2, 0, 0)
        self.meta_layout.setSpacing(4)
        self.meta_layout.setAlignment(Qt.AlignRight | Qt.AlignBottom)

        if not timestamp:
            time_str = datetime.now().strftime("%H:%M")
        else:
            try:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime("%H:%M")
            except ValueError:
                time_str = timestamp[-5:] if len(timestamp) >= 5 else "00:00"

        self.time_label = QLabel(time_str)
        self.time_label.setObjectName("BubbleTime")
        self.time_label.setFocusPolicy(Qt.NoFocus)
        self.meta_layout.addWidget(self.time_label)

        if self.is_mine:
            self.status_label = QLabel("✓✓")
            self.status_label.setObjectName("BubbleStatus")
            self.status_label.setFocusPolicy(Qt.NoFocus)
            self.status_label.setProperty("read", self.is_read)
            self.meta_layout.addWidget(self.status_label)

        self.bubble_layout.addWidget(self.msg_label)
        self.bubble_layout.addLayout(self.meta_layout)

        if is_mine:
            layout.addStretch()
            layout.addWidget(self.bubble)
        else:
            layout.addWidget(self.bubble)
            layout.addStretch()

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    # ------------------------------------------------------------------
    # Skeleton
    # ------------------------------------------------------------------

    def show_skeleton(self):
        if self._skeleton:
            self._skeleton.setVisible(True)
            self.msg_label.setVisible(False)
            self.bubble.setMinimumWidth(340)

    def hide_skeleton(self):
        if self._skeleton:
            self._skeleton.stop()
            self._skeleton.setVisible(False)

    def _on_image_clicked(self, pixmap: QPixmap):
        self.image_view_requested.emit(pixmap)

    # ------------------------------------------------------------------
    # Построение UI
    # ------------------------------------------------------------------

    def _create_reply_block(self, reply_text: str, reply_sender: str):
        display_text = reply_text or ""
        if display_text.startswith("[IMAGE_META]"):
            display_text = "Фото"
        elif display_text.startswith("[VOICE_META]"):
            display_text = "Голосовое"

        self.reply_frame = QFrame()
        self.reply_frame.setObjectName("ReplyBlock")
        self.reply_frame.setCursor(Qt.PointingHandCursor)

        reply_layout = QHBoxLayout(self.reply_frame)
        reply_layout.setContentsMargins(8, 6, 8, 6)
        reply_layout.setSpacing(8)

        # ✅ Используем общий SVG рендерер
        from app.theme import get_theme
        t = get_theme()

        icon_label = QLabel()
        icon_label.setObjectName("ReplyBlockIcon")
        icon_label.setFixedSize(14, 14)
        icon_label.setFocusPolicy(Qt.NoFocus)

        icon = _render_svg(
            "reply_small.svg",
            t.get("text_main"),
            14
        )
        icon_label.setPixmap(icon.pixmap(14, 14))

        # Текст
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        text_layout.setContentsMargins(0, 0, 0, 0)

        if reply_sender:
            sender_label = QLabel(f"@{reply_sender}")
            sender_label.setObjectName("ReplySender")
            text_layout.addWidget(sender_label)

        preview = display_text[:50] + "..." if len(display_text) > 50 else display_text
        text_label = QLabel(preview)
        text_label.setObjectName("ReplyText")
        text_layout.addWidget(text_label)

        reply_layout.addWidget(icon_label, 0, Qt.AlignVCenter)
        reply_layout.addLayout(text_layout)
        reply_layout.addStretch()

        self.bubble_layout.insertWidget(0, self.reply_frame)
        self.reply_frame.mousePressEvent = self._on_reply_block_clicked

    def _create_voice_player(self, duration: float):
        self.voice_frame = QFrame()
        self.voice_frame.setObjectName("VoicePlayer")

        voice_layout = QHBoxLayout(self.voice_frame)
        voice_layout.setContentsMargins(4, 4, 4, 4)
        voice_layout.setSpacing(8)

        self.play_btn = _VoicePlayButton(is_mine=self.is_mine)
        self.play_btn.clicked.connect(self._on_play_clicked)

        self.waveform = VoiceWaveform(duration, self.is_mine)
        self.waveform.seek_requested.connect(self._on_seek)

        duration_str = (
            f"{int(duration // 60)}:{int(duration % 60):02d}"
            if duration else "0:00"
        )
        self.duration_label = QLabel(duration_str)
        self.duration_label.setObjectName("VoiceDuration")
        self.duration_label.setFocusPolicy(Qt.NoFocus)

        voice_layout.addWidget(self.play_btn)
        voice_layout.addWidget(self.waveform)
        voice_layout.addWidget(self.duration_label)

        insert_pos = 1 if self.reply_frame else 0
        self.bubble_layout.insertWidget(insert_pos, self.voice_frame)
        self.bubble.setMinimumWidth(260)

    # ------------------------------------------------------------------
    # Слоты плеера
    # ------------------------------------------------------------------

    def _on_play_clicked(self):
        if self._voice_data:
            self.voice_play_requested.emit(self, self._voice_data)
        else:
            print(f"[VOICE] Нет данных (msg_id={self.msg_id})")

    def _on_seek(self, progress: float):
        self.voice_seek_requested.emit(self, progress)

    def set_playing(self, is_playing: bool):
        self._is_playing = is_playing
        try:
            if self.play_btn and isinstance(self.play_btn, _VoicePlayButton):
                self.play_btn.set_playing(is_playing)
            if self.waveform:
                self.waveform.set_playing(is_playing)
            if not is_playing and self.waveform:
                self.waveform.set_progress(0.0)
        except RuntimeError:
            pass

    def update_playback_progress(self, progress: float):
        try:
            if self.waveform:
                self.waveform.set_progress(progress)
            if self.duration_label and self._voice_duration > 0:
                elapsed = progress * self._voice_duration
                remaining = self._voice_duration - elapsed
                m = int(remaining // 60)
                s = int(remaining % 60)
                self.duration_label.setText(f"{m}:{s:02d}")
        except RuntimeError:
            pass

    # ------------------------------------------------------------------
    # Данные голосового
    # ------------------------------------------------------------------

    def set_voice_data(self, data: bytes):
        self._voice_data = data
        if self.waveform:
            self.waveform.load_waveform_from_wav(data)

    def set_voice_data_from_file(self, file_path):
        path = Path(file_path)
        if path.exists():
            self.set_voice_data(path.read_bytes())
        else:
            print(f"[BUBBLE] Файл кэша не найден: {path}")

    # ------------------------------------------------------------------
    # Контекстное меню — SVG иконки
    # ------------------------------------------------------------------

    def _show_context_menu(self, pos):
        from app.theme import get_theme
        t = get_theme()
        color_main = t.get("text_main", "#f8fafb")
        color_danger = t.get("danger", "#ff7b8d")

        menu = QMenu(self)
        menu.setObjectName("BubbleContextMenu")
        menu.setAttribute(Qt.WA_TranslucentBackground, True)
        menu.setAttribute(Qt.WA_NoSystemBackground, True)  # ← добавляем
        menu.setWindowFlags(
            Qt.Popup | Qt.FramelessWindowHint | Qt.NoDropShadowWindowHint
        )

        reply_action = menu.addAction(
            _render_svg("reply.svg", color_main, 16), "Ответить"
        )
        reply_action.triggered.connect(self._on_reply_clicked)

        if self._text and not self._voice_data:
            copy_action = menu.addAction(
                _render_svg("copy.svg", color_main, 16), "Копировать"
            )
            copy_action.triggered.connect(self._copy_text)

        menu.addSeparator()

        delete_action = menu.addAction(
            _render_svg("trash.svg", color_danger, 16), "Удалить"
        )
        delete_action.triggered.connect(self._on_delete_clicked)

        menu.exec(QCursor.pos())

    def _on_reply_clicked(self):
        if self.msg_id:
            sender = self._sender if not self.is_mine else "Вы"
            text = self._text or ("Голосовое" if self._voice_data else "Фото")
            self.reply_requested.emit(self.msg_id, text, sender)

    def _on_delete_clicked(self):
        if self.msg_id:
            self.delete_requested.emit(self.msg_id)

    def _copy_text(self):
        from PySide6.QtWidgets import QApplication
        if self._text:
            QApplication.clipboard().setText(self._text)

    # ------------------------------------------------------------------
    # Утилиты
    # ------------------------------------------------------------------

    def set_sender(self, sender: str):
        self._sender = sender

    def set_image(self, image_bytes: bytes, caption: str = None):
        self.hide_skeleton()

        pixmap = QPixmap()
        if pixmap.loadFromData(image_bytes):
            self.image_label.set_pixmap_original(
                pixmap.scaledToWidth(
                    min(pixmap.width(), 1200), Qt.SmoothTransformation
                )
            )

            scaled = pixmap.scaledToWidth(320, Qt.SmoothTransformation)
            rounded = QPixmap(scaled.size())
            rounded.fill(Qt.transparent)

            painter = QPainter(rounded)
            painter.setRenderHint(QPainter.Antialiasing)
            painter.setRenderHint(QPainter.SmoothPixmapTransform)
            path = QPainterPath()
            path.addRoundedRect(
                0, 0, scaled.width(), scaled.height(), 8, 8
            )
            painter.setClipPath(path)
            painter.drawPixmap(0, 0, scaled)
            painter.end()

            self.image_label.setPixmap(rounded)
            self.image_label.setVisible(True)
            self.msg_label.setVisible(False)
            self.bubble.setMaximumWidth(350)

            effective_caption = caption or self._caption
            if effective_caption and effective_caption.strip():
                self.caption_label.setText(effective_caption.strip())
                self.caption_label.setVisible(True)
                self.caption_label.setMaximumWidth(320)
            else:
                self.caption_label.setVisible(False)

    def mark_as_read(self):
        if self.is_mine and not self.is_read:
            self.is_read = True
            if hasattr(self, 'status_label'):
                self.status_label.setProperty("read", True)
                self.status_label.style().unpolish(self.status_label)
                self.status_label.style().polish(self.status_label)

    def apply_theme(self):
        self.bubble.setObjectName("BubbleOut" if self.is_mine else "BubbleIn")
        self.bubble.style().unpolish(self.bubble)
        self.bubble.style().polish(self.bubble)

        if hasattr(self, 'status_label'):
            self.status_label.style().unpolish(self.status_label)
            self.status_label.style().polish(self.status_label)

        if self.play_btn and isinstance(self.play_btn, _VoicePlayButton):
            self.play_btn.refresh_theme()

        # Перерисовываем иконку reply при смене темы
        if self.reply_frame:
            from app.theme import get_theme
            t = get_theme()

            layout = self.reply_frame.layout()
            if layout and layout.count() > 0:
                item = layout.itemAt(0)
                if item and item.widget() and isinstance(item.widget(), QLabel):
                    icon_label = item.widget()

                    # ✅ Всегда берём актуальный цвет темы
                    color = t.get("text_main")

                    icon = _render_svg("reply_small.svg", color, 14)
                    icon_label.setPixmap(icon.pixmap(14, 14))

    def _on_reply_block_clicked(self, event):
        if event.button() == Qt.LeftButton and self._reply_to_msg_id:
            self.scroll_to_msg_requested.emit(self._reply_to_msg_id)

    def set_reply_to_msg_id(self, msg_id: str):
        self._reply_to_msg_id = msg_id