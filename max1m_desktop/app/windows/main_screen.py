import time
import math
import threading
import random
try:
    import pyaudio
except ImportError:
    try:
        import pyaudiowpatch as pyaudio
    except ImportError:
        pyaudio = None
import wave
import io
import json
import uuid
import hashlib
import struct
from nacl.encoding import Base64Encoder
from PySide6.QtCore import (
    Qt, QTimer, Signal, QSize, QPropertyAnimation,
    QEasingCurve, QRect, QPoint, QObject, QMetaObject
)
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QVBoxLayout, QLabel,
    QPushButton, QLineEdit, QListWidget, QScrollArea,
    QStackedWidget, QListWidgetItem, QMessageBox, QFileDialog, QInputDialog,
    QGraphicsDropShadowEffect, QGraphicsOpacityEffect,
    QSlider, QMenu, QSizePolicy, QWidget
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtGui import QPainter, QIcon, QPixmap, QFontMetrics, QCursor, QColor, QImage, QRadialGradient, QBrush, QPainterPath, QGuiApplication
from pathlib import Path
from datetime import datetime

from app.bounded_cache import BoundedBytesCache
from app import outbox, attachment_outbox
from app.outbox_policy import verify_queued_recipient, OutboxRecipientError
from app.incoming_identity import verify_incoming, IncomingIdentityError
from app.call_policy import resolve_call_peer, call_context_valid
from app.contact_keys import fingerprint_public_key, device_key_map, newly_advertised_devices
from app.recipient_context import RecipientContext, capture_recipient, recipient_still_trusted, recipient_is_verified, verification_scope, is_active_recipient
from app.state import state
from app.crypto_box import crypto
from app.group_crypto import (
    SERVER_GROUP_NAME_PLACEHOLDER,
    group_crypto,
    lookup_member_sender_key,
    store_member_sender_key,
)
from app.workers import (
    FindUserWorker, SendMessageWorker, ReliableSendWorker, ReliableUploadFileWorker, DownloadFileWorker,
    CreateGroupWorker, SendGroupMessageWorker, SyncGroupMessagesWorker,
    DistributeGroupSenderKeyWorker, InviteGroupMemberWorker,
    AcknowledgeGroupMessagesWorker, FetchGroupMembersWorker,
    FetchGroupsWorker, FetchGroupSenderKeysWorker,
    DeleteGroupWorker, LeaveGroupWorker, GrantFileAccessWorker, HistoryPageWorker,
    CancelUploadReservationWorker
)
from app.windows.widgets.message_bubble import MessageBubble
from app.windows.widgets.smart_input import SmartInput
from app.secure_storage import storage
from app.webrtc_manager import rtc, SCREEN_QUALITY_PRESETS
from app.voice_cache import voice_cache, message_scope, asset_scope
from app.media_queue import MediaQueue
from app.media_identity import valid_file_id, valid_file_key
from app.history_paging import searchable_text, PAGE_SIZE
from app.delivery import MAX_READ_ACK_IDS
from app.voice_playback import VoicePlayback
from app.theme import get_theme

ICONS_PATH = Path(__file__).parent.parent / "assets" / "icons"

# Protected Group E2EE v2 (ratcheted SenderKeys + epoch rotation + Ed25519 verification)
GROUP_CHAT_SEND_ENABLED = True
MAX_IMAGE_FILE_BYTES = 20 * 1024 * 1024

# ============================================================================
# SVG RENDER
# ============================================================================

def _render_svg_icon(svg_name: str, color: str, size: int = 16) -> QIcon:
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
# THEMED ICON BUTTON
# ============================================================================

class ThemedIconButton(QPushButton):
    def __init__(self, svg_path: str, button_size: int = 48,
                 icon_size: int = 22, parent=None):
        super().__init__(parent)
        self.svg_path = Path(svg_path)
        self.icon_size = icon_size
        self.setFixedSize(button_size, button_size)
        self.setFocusPolicy(Qt.NoFocus)
        self._update_icon()

    def _update_icon(self, custom_color: str = None):
        from app.theme import get_theme
        t = get_theme()
        if not self.svg_path.exists():
            return
        svg_content = self.svg_path.read_text(encoding="utf-8")
        color = custom_color if custom_color else t["text_main"]
        svg_colored = svg_content.replace("currentColor", color)
        renderer = QSvgRenderer(svg_colored.encode("utf-8"))
        pixmap = QPixmap(self.icon_size, self.icon_size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)
        renderer.render(painter)
        painter.end()
        self.setIcon(QIcon(pixmap))
        self.setIconSize(pixmap.size())

    def refresh_theme(self):
        self._update_icon()

    def set_icon_path(self, new_path: str):
        self.svg_path = Path(new_path)
        self._update_icon()


# ============================================================================
# ALLY LIST WIDGETS
# ============================================================================

class AllyListItem(QListWidgetItem):
    def __init__(self, username: str):
        super().__init__()
        self.setData(Qt.UserRole, username)
        self.last_activity = 0.0

    def __lt__(self, other):
        return getattr(self, "last_activity", 0.0) < getattr(other, "last_activity", 0.0)


class AllyCardWidget(QFrame):
    def __init__(self, username: str, parent=None):
        super().__init__(parent)
        self.username = username
        self.setObjectName("AllyCard")
        self.setFocusPolicy(Qt.NoFocus)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(16)

        self.avatar = QLabel(username[0].upper())
        self.avatar.setObjectName("AllyAvatar")
        self.avatar.setFixedSize(44, 44)
        self.avatar.setAlignment(Qt.AlignCenter)

        middle_layout = QVBoxLayout()
        middle_layout.setSpacing(4)
        middle_layout.setAlignment(Qt.AlignVCenter)
        self.name_label = QLabel(username)
        self.name_label.setObjectName("AllyName")
        self.msg_preview = QLabel("Нет сообщений")
        self.msg_preview.setObjectName("AllyLastMessage")
        middle_layout.addWidget(self.name_label)
        middle_layout.addWidget(self.msg_preview)

        self.badge = QLabel("0")
        self.badge.setObjectName("AllyUnreadBadge")
        self.badge.setFixedSize(22, 22)
        self.badge.setAlignment(Qt.AlignCenter)
        self.badge.setVisible(False)

        layout.addWidget(self.avatar)
        layout.addLayout(middle_layout)
        layout.addStretch()
        layout.addWidget(self.badge)
        self.unread_count = 0

    def update_preview(self, text: str):
        flat_text = text.replace("\n", " ")
        metrics = QFontMetrics(self.msg_preview.font())
        elided = metrics.elidedText(flat_text, Qt.ElideRight, 160)
        self.msg_preview.setText(elided)

    def increment_unread(self):
        self.unread_count += 1
        self.badge.setText(str(self.unread_count))
        self.badge.setVisible(True)

    def reset_unread(self):
        self.unread_count = 0
        self.badge.setVisible(False)


# ============================================================================
# GROUP LIST WIDGETS
# ============================================================================

class GroupListItem(QListWidgetItem):
    def __init__(self, group_id: str):
        super().__init__()
        self.setData(Qt.UserRole, group_id)
        self.last_activity = 0.0


class GroupCardWidget(QFrame):
    def __init__(self, name: str, parent=None):
        super().__init__(parent)
        self.setObjectName("AllyCard")
        self.setFocusPolicy(Qt.NoFocus)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(16)

        self.avatar = QLabel(name[0].upper() if name else "G")
        self.avatar.setObjectName("GroupAvatar")
        self.avatar.setFixedSize(44, 44)
        self.avatar.setAlignment(Qt.AlignCenter)

        middle_layout = QVBoxLayout()
        middle_layout.setSpacing(4)
        middle_layout.setAlignment(Qt.AlignVCenter)

        self.name_label = QLabel(name)
        self.name_label.setObjectName("AllyName")

        self.msg_preview = QLabel("Нет сообщений")
        self.msg_preview.setObjectName("AllyLastMessage")

        middle_layout.addWidget(self.name_label)
        middle_layout.addWidget(self.msg_preview)

        self.badge = QLabel("0")
        self.badge.setObjectName("AllyUnreadBadge")
        self.badge.setFixedSize(22, 22)
        self.badge.setAlignment(Qt.AlignCenter)
        self.badge.setVisible(False)

        layout.addWidget(self.avatar)
        layout.addLayout(middle_layout)
        layout.addStretch()
        layout.addWidget(self.badge)
        self.unread_count = 0

    def update_preview(self, text: str):
        flat_text = text.replace("\n", " ")
        metrics = QFontMetrics(self.msg_preview.font())
        elided = metrics.elidedText(flat_text, Qt.ElideRight, 160)
        self.msg_preview.setText(elided)

    def increment_unread(self):
        self.unread_count += 1
        self.badge.setText(str(self.unread_count))
        self.badge.setVisible(True)

    def reset_unread(self):
        self.unread_count = 0
        self.badge.setVisible(False)


# ============================================================================
# CREATE GROUP PANEL
# ============================================================================

class CreateGroupPanel(QFrame):
    create_requested = Signal(str, list)
    cancel_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("CreateGroupPanel")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(10)

        header = QHBoxLayout()
        title = QLabel("НОВАЯ ГРУППА")
        title.setObjectName("SectionHeader")

        close_btn = ThemedIconButton(str(ICONS_PATH / "close_small.svg"), 24, 12)
        close_btn.setObjectName("RecordCancelBtn")
        close_btn.setFocusPolicy(Qt.NoFocus)
        close_btn.clicked.connect(self.cancel_requested.emit)

        header.addWidget(title)
        header.addStretch()
        header.addWidget(close_btn)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Название группы...")
        self.name_input.setObjectName("AllyInput")
        self.name_input.setFocusPolicy(Qt.StrongFocus)

        members_label = QLabel("ВЫБЕРИТЕ УЧАСТНИКОВ")
        members_label.setObjectName("SectionHeader")

        self.members_list = QListWidget()
        self.members_list.setObjectName("AlliesList")
        self.members_list.setSelectionMode(QListWidget.MultiSelection)
        self.members_list.setFocusPolicy(Qt.NoFocus)

        self.create_btn = QPushButton("Создать Союз")
        self.create_btn.setObjectName("PrimaryButton")
        self.create_btn.setFixedHeight(44)
        self.create_btn.setFocusPolicy(Qt.NoFocus)
        self.create_btn.clicked.connect(self._on_create)

        layout.addLayout(header)
        layout.addWidget(self.name_input)
        layout.addWidget(members_label)
        layout.addWidget(self.members_list)
        layout.addWidget(self.create_btn)

    def refresh_allies(self, allies_dict: dict):
        self.members_list.clear()
        for username in allies_dict.keys():
            item = QListWidgetItem(f"@{username}")
            item.setData(Qt.UserRole, username)
            self.members_list.addItem(item)

    def _on_create(self):
        name = self.name_input.text().strip()
        selected = [
            self.members_list.item(i).data(Qt.UserRole)
            for i in range(self.members_list.count())
            if self.members_list.item(i).isSelected()
        ]
        if not name or not selected:
            return
        self.create_requested.emit(name, selected)


# ============================================================================
# LIVE WAVEFORM
# ============================================================================

class _LiveWaveform(QWidget):
    BAR_WIDTH = 3
    BAR_GAP   = 2
    BAR_MAX_H = 22

    def __init__(self, parent=None):
        super().__init__(parent)
        self._levels = []
        self.setMinimumHeight(self.BAR_MAX_H + 4)
        self.setMaximumHeight(self.BAR_MAX_H + 4)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFocusPolicy(Qt.NoFocus)

    def _bar_count(self) -> int:
        return max(1, self.width() // (self.BAR_WIDTH + self.BAR_GAP))

    def push_level(self, rms: float):
        count = self._bar_count()
        self._levels.append(max(0.0, min(1.0, rms)))
        if len(self._levels) > count:
            self._levels = self._levels[-count:]
        self.update()

    def paintEvent(self, event):
        from app.theme import get_theme
        t = get_theme()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)

        danger_color = QColor(t.get("danger", "#ff7b8d"))
        w = self.width()
        h = self.height()
        center_y = h / 2
        step = self.BAR_WIDTH + self.BAR_GAP

        line_color = QColor(danger_color.red(), danger_color.green(),
                            danger_color.blue(), 35)
        painter.setBrush(line_color)
        painter.drawRoundedRect(0, int(center_y) - 1, w, 2, 1, 1)

        for i, level in enumerate(self._levels):
            if level < 0.03:
                continue
            x = i * step
            bar_h = max(4, int(level * self.BAR_MAX_H))
            y = center_y - bar_h / 2
            alpha = int(80 + 170 * (i / max(len(self._levels), 1)))
            color = QColor(danger_color.red(), danger_color.green(),
                           danger_color.blue(), alpha)
            painter.setBrush(color)
            painter.drawRoundedRect(int(x), int(y), self.BAR_WIDTH, bar_h, 1.5, 1.5)


class _RecordingDot(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(12, 12)
        self.setFocusPolicy(Qt.NoFocus)

    def paintEvent(self, event):
        from app.theme import get_theme
        t = get_theme()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(t.get("danger", "#ff7b8d")))
        painter.drawEllipse(1, 1, 10, 10)


# ============================================================================
# VOICE RECORDING BAR
# ============================================================================

class VoiceRecordingBar(QFrame):
    cancel_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("VoiceRecordingBar")
        self.setFixedHeight(76)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(32, 16, 32, 16)
        layout.setSpacing(12)

        self._dot_widget = _RecordingDot()
        self._timer_label = QLabel("0:00")
        self._timer_label.setObjectName("RecordingTimer")
        self._rec_label = QLabel("Запись...")
        self._rec_label.setObjectName("RecordingLabel")
        self._waveform = _LiveWaveform()

        self._cancel_btn = ThemedIconButton(
            str(ICONS_PATH / "close_small.svg"), 36, 14
        )
        self._cancel_btn.setObjectName("RecordCancelBtn")
        self._cancel_btn.setFocusPolicy(Qt.NoFocus)
        self._cancel_btn.clicked.connect(self.cancel_requested.emit)

        layout.addWidget(self._dot_widget)
        layout.addWidget(self._timer_label)
        layout.addWidget(self._rec_label)
        layout.addSpacing(8)
        layout.addWidget(self._waveform, 1)
        layout.addSpacing(8)
        layout.addWidget(self._cancel_btn)

        self._dot_effect = QGraphicsOpacityEffect(self._dot_widget)
        self._dot_widget.setGraphicsEffect(self._dot_effect)
        self._dot_anim = QPropertyAnimation(self._dot_effect, b"opacity")
        self._dot_anim.setDuration(800)
        self._dot_anim.setStartValue(1.0)
        self._dot_anim.setEndValue(0.2)
        self._dot_anim.setEasingCurve(QEasingCurve.InOutSine)
        self._dot_anim.setLoopCount(-1)

        self._elapsed_seconds = 0
        self._sec_timer = QTimer(self)
        self._sec_timer.setInterval(1000)
        self._sec_timer.timeout.connect(self._tick)

    def start(self):
        self._elapsed_seconds = 0
        self._rec_label.setText("Запись...")
        self._timer_label.setText("0:00")
        self._sec_timer.start()
        self._dot_anim.start()

    def stop(self):
        self._sec_timer.stop()
        self._dot_anim.stop()
        self._dot_effect.setOpacity(1.0)

    def push_level(self, rms: float):
        self._waveform.push_level(rms)

    def _tick(self):
        self._elapsed_seconds += 1
        m = self._elapsed_seconds // 60
        s = self._elapsed_seconds % 60
        self._timer_label.setText(f"{m}:{s:02d}")


# ============================================================================
# SCREEN SHARE WIDGET
# ============================================================================

class ScreenShareWidget(QFrame):
    stop_requested = Signal()

    def __init__(self, parent=None, is_mine=False):
        super().__init__(parent)
        self.setObjectName("ScreenShareContainer")
        self.setFixedHeight(280)
        self.is_mine = is_mine

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header = QHBoxLayout()
        self.status_label = QLabel(
            "Вы демонстрируете экран" if is_mine
            else "Собеседник демонстрирует экран"
        )
        self.status_label.setObjectName("ScreenShareLabel")

        if is_mine:
            self.stop_btn = QPushButton("Остановить")
            self.stop_btn.setObjectName("ScreenShareStopBtn")
            self.stop_btn.setFixedSize(100, 28)
            self.stop_btn.clicked.connect(self.stop_requested.emit)
            header.addWidget(self.status_label)
            header.addStretch()
            header.addWidget(self.stop_btn)
        else:
            header.addWidget(self.status_label)
            header.addStretch()

        self.video_label = QLabel()
        self.video_label.setObjectName("ScreenShareVideo")
        self.video_label.setAlignment(Qt.AlignCenter)
        self.video_label.setMinimumHeight(200)
        self.video_label.setText("Ожидание видео...")

        layout.addLayout(header)
        layout.addWidget(self.video_label)
        self._current_pixmap = None

    def update_frame(self, image):
        if not isinstance(image, QImage) or image.isNull():
            return
        self._current_pixmap = QPixmap.fromImage(image)
        scaled = self._current_pixmap.scaled(
            self.video_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        self.video_label.setPixmap(scaled)


# ============================================================================
# IMAGE PREVIEW PANEL
# ============================================================================

class ImagePreviewPanel(QFrame):
    send_requested   = Signal(bytes, str)
    cancel_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ImagePreviewPanel")
        self._file_data: bytes = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 12, 32, 12)
        layout.setSpacing(8)

        top_row = QHBoxLayout()
        top_row.setSpacing(12)

        self._thumb = QLabel()
        self._thumb.setObjectName("ImagePreviewThumb")
        self._thumb.setFixedHeight(200)
        self._thumb.setAlignment(Qt.AlignCenter)
        self._thumb.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self._cancel_btn = ThemedIconButton(
            str(ICONS_PATH / "close_small.svg"), 32, 14
        )
        self._cancel_btn.setObjectName("ImagePreviewCancelBtn")
        self._cancel_btn.setFocusPolicy(Qt.NoFocus)
        self._cancel_btn.clicked.connect(self.cancel_requested.emit)

        top_row.addWidget(self._thumb)
        top_row.addWidget(self._cancel_btn, 0, Qt.AlignTop)

        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(8)

        self._caption_input = QLineEdit()
        self._caption_input.setObjectName("ImageCaptionInput")
        self._caption_input.setPlaceholderText("Добавить подпись...")
        self._caption_input.setFocusPolicy(Qt.StrongFocus)
        self._caption_input.returnPressed.connect(self._on_send)

        self._send_btn = QPushButton("Отправить")
        self._send_btn.setObjectName("ImagePreviewSendBtn")
        self._send_btn.setFocusPolicy(Qt.NoFocus)
        self._send_btn.clicked.connect(self._on_send)

        bottom_row.addWidget(self._caption_input)
        bottom_row.addWidget(self._send_btn)

        layout.addLayout(top_row)
        layout.addLayout(bottom_row)

    def set_image(self, file_data: bytes):
        self._file_data = file_data
        pixmap = QPixmap()
        if pixmap.loadFromData(file_data):
            scaled = pixmap.scaled(500, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self._thumb.setPixmap(scaled)
        self._caption_input.clear()
        self._caption_input.setFocus()

    def _on_send(self):
        if self._file_data:
            self.send_requested.emit(self._file_data, self._caption_input.text().strip())

    def clear(self):
        self._file_data = None
        self._thumb.clear()
        self._caption_input.clear()

# ============================================================================
# MAIN SCREEN
# ============================================================================

class MainScreen(QFrame):
    incoming_message_processed = Signal(dict)
    contact_verification_changed = Signal()
    logout_requested = Signal()
    rtc_state_changed          = Signal(str)
    _voice_playback_finished   = Signal(object)
    _voice_progress_update     = Signal(object, float)
    _voice_level_signal        = Signal(int, float)
    _voice_recording_error     = Signal(int, str)
    _voice_recording_limit     = Signal(int)
    _group_voice_speaking_sig  = Signal(str, bool)
    _group_voice_screen_sig    = Signal(str, object, str)

    def __init__(self):
        super().__init__()
        self.setObjectName("MainScreenFrame")

        # ── Базовое состояние ─────────────────────────────────────
        self.find_worker     = None
        self._net_workers    = []
        self._outbox_worker = None
        self._outbox_warning_shown = False
        self._incoming_identity_notice_shown = False
        self._outbox_identity_warning_shown = False
        self._outbox_management_active = False
        self._outbox_skipped = set()
        self._attachment_worker = None
        self._attachment_skipped = set()
        self._attachment_retry_after = {}
        self._attachment_warning_shown = False
        self._outbox_timer = QTimer(self)
        self._outbox_timer.setInterval(15000)
        self._outbox_timer.timeout.connect(self._try_outbox)
        self._outbox_timer.timeout.connect(self._try_attachment_outbox)
        self._outbox_timer.start()
        self._image_cache    = BoundedBytesCache(32 * 1024 * 1024)
        self._media_queue = MediaQueue(self._start_media_download, self._media_download_failed)
        self._history_offset = 0
        self._history_query = None
        self._history_total = 0
        self._history_available = False
        self._history_worker = None
        self._history_pending = None
        self._history_serial = 0
        self._history_reveal_callback = None
        self.settings_screen = None

        # ── Звонки ────────────────────────────────────────────────
        self.active_call_username   = None
        self._active_call_device_id = None
        self._active_call_id = None
        self._active_call_context = None
        self._call_signal_authorized = False
        self._call_direction = None
        self._call_identity_timer = QTimer(self)
        self._call_identity_timer.setInterval(2000)
        self._call_identity_timer.timeout.connect(self._check_call_identity)
        self._call_identity_timer.start()

        # ── Mute / Deafen ─────────────────────────────────────────
        self.is_mic_muted  = False
        self.is_deafened   = False

        # ── Screen share ──────────────────────────────────────────
        self.is_screen_sharing = False
        self.screen_share_widget = None
        self.current_quality_profile = "balanced"

        # ── Reply ─────────────────────────────────────────────────
        self._reply_to_msg_id  = None
        self._reply_to_text    = None
        self._reply_to_sender  = None

        # ── Голосовые ─────────────────────────────────────────────
        self._is_recording            = False
        self._voice_frames            = []
        self._voice_stream            = None
        self._voice_thread            = None
        self._voice_cancelled         = False
        self._voice_recording_generation = 0
        self._current_playing_bubble  = None
        self._voice_playback = VoicePlayback(
            lambda: (rtc.pa, rtc.output_device_index),
            lambda generation, progress: self._voice_progress_update.emit(generation, progress),
            lambda generation: self._voice_playback_finished.emit(generation),
        )
        self._voice_playback_generation = 0
        self._voice_request_serial    = 0

        # ── Layout ────────────────────────────────────────────────
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ==================== SIDEBAR ====================
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(340)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(24, 28, 24, 24)
        sidebar_layout.setSpacing(12)

        add_ally_layout = QHBoxLayout()
        add_ally_layout.setSpacing(10)
        self.ally_input = QLineEdit()
        self.ally_input.setObjectName("AllyInput")
        self.ally_input.setPlaceholderText("@user_tag")
        self.add_ally_btn = ThemedIconButton(str(ICONS_PATH / "plus.svg"), 48, 20)
        self.add_ally_btn.setObjectName("IconBtn")
        self.ally_input.returnPressed.connect(self._on_add_ally)
        self.add_ally_btn.clicked.connect(self._on_add_ally)
        add_ally_layout.addWidget(self.ally_input)
        add_ally_layout.addWidget(self.add_ally_btn)

        self.search_status = QLabel("")
        self.search_status.setObjectName("SearchStatusError")
        self.search_status.setVisible(False)

        sidebar_layout.addWidget(QLabel("ДОБАВИТЬ СОЮЗНИКА", objectName="SectionHeader"))
        sidebar_layout.addLayout(add_ally_layout)
        sidebar_layout.addWidget(self.search_status)

        tabs_layout = QHBoxLayout()
        tabs_layout.setSpacing(4)
        tabs_layout.setContentsMargins(0, 4, 0, 0)

        self.tab_allies_btn = QPushButton("Союзники")
        self.tab_allies_btn.setObjectName("SidebarTabBtn")
        self.tab_allies_btn.setFocusPolicy(Qt.NoFocus)
        self.tab_allies_btn.setCheckable(True)
        self.tab_allies_btn.setChecked(True)
        self.tab_allies_btn.clicked.connect(lambda: self._switch_sidebar_tab("allies"))

        self.tab_groups_btn = QPushButton("Группы")
        self.tab_groups_btn.setObjectName("SidebarTabBtn")
        self.tab_groups_btn.setFocusPolicy(Qt.NoFocus)
        self.tab_groups_btn.setCheckable(True)
        self.tab_groups_btn.setChecked(False)
        self.tab_groups_btn.clicked.connect(lambda: self._switch_sidebar_tab("groups"))

        tabs_layout.addWidget(self.tab_allies_btn)
        tabs_layout.addWidget(self.tab_groups_btn)
        sidebar_layout.addLayout(tabs_layout)

        self.sidebar_stack = QStackedWidget()
        self.sidebar_stack.setFocusPolicy(Qt.NoFocus)

        # Вкладка 0: Союзники
        allies_tab = QFrame()
        allies_tab.setObjectName("SidebarTab")
        allies_tab_layout = QVBoxLayout(allies_tab)
        allies_tab_layout.setContentsMargins(0, 8, 0, 0)
        allies_tab_layout.setSpacing(8)

        conn_row = QHBoxLayout()
        conn_row.setSpacing(6)
        conn_row.setContentsMargins(0, 0, 0, 0)

        self._conn_dot = ThemedIconButton(
            str(ICONS_PATH / "dot_connected.svg"), 12, 8
        )
        self._conn_dot.setObjectName("ConnDotBtn")
        self._conn_dot.setEnabled(False)
        self._conn_dot._update_icon(custom_color="#54caa0")

        self.conn_status = QLabel("Подключено")
        self.conn_status.setObjectName("ConnectionStatus")
        self.conn_status.setProperty("status", "connected")

        conn_row.addWidget(self._conn_dot)
        conn_row.addWidget(self.conn_status)
        conn_row.addStretch()

        self.allies_list = QListWidget()
        self.allies_list.setObjectName("AlliesList")
        self.allies_list.setFocusPolicy(Qt.NoFocus)
        self.allies_list.itemClicked.connect(self._on_ally_selected)

        allies_tab_layout.addLayout(conn_row)
        allies_tab_layout.addWidget(self.allies_list)

        # Вкладка 1: Группы
        groups_tab = QFrame()
        groups_tab.setObjectName("SidebarTab")
        groups_tab_layout = QVBoxLayout(groups_tab)
        groups_tab_layout.setContentsMargins(0, 8, 0, 0)
        groups_tab_layout.setSpacing(8)

        self.add_group_btn = QPushButton("+ Создать группу")
        self.add_group_btn.setObjectName("CreateGroupBtn")
        self.add_group_btn.setFocusPolicy(Qt.NoFocus)
        self.add_group_btn.clicked.connect(self._show_create_group_panel)

        self.groups_list = QListWidget()
        self.groups_list.setObjectName("AlliesList")
        self.groups_list.setFocusPolicy(Qt.NoFocus)
        self.groups_list.itemClicked.connect(self._on_group_selected)

        self.create_group_panel = CreateGroupPanel()
        self.create_group_panel.setVisible(False)
        self.create_group_panel.cancel_requested.connect(self._hide_create_group_panel)
        self.create_group_panel.create_requested.connect(self._do_create_group)

        groups_tab_layout.addWidget(self.add_group_btn)
        groups_tab_layout.addWidget(self.groups_list)
        groups_tab_layout.addWidget(self.create_group_panel)

        self.sidebar_stack.addWidget(allies_tab)
        self.sidebar_stack.addWidget(groups_tab)
        self.sidebar_stack.setCurrentIndex(0)

        sidebar_layout.addWidget(self.sidebar_stack)

        # ==================== RIGHT STACK ====================
        self.right_stack = QStackedWidget()

        self.empty_state = QFrame()
        self.empty_state.setObjectName("EmptyState")
        empty_layout = QVBoxLayout(self.empty_state)
        empty_text = QLabel("Выберите союзника\nдля начала защищенного общения")
        empty_text.setObjectName("EmptyStateText")
        empty_text.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(empty_text)

        # ==================== CHAT AREA ====================
        self.chat_area = QFrame()
        self.chat_area.setObjectName("ChatArea")
        chat_layout = QVBoxLayout(self.chat_area)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.setSpacing(0)

        # Header
        self.chat_header = QFrame()
        self.chat_header.setObjectName("ChatHeader")
        self.chat_header.setFixedHeight(76)
        header_layout = QHBoxLayout(self.chat_header)
        header_layout.setContentsMargins(32, 0, 32, 0)

        self.chat_title = QLabel("Выберите союзника")
        self.chat_title.setObjectName("ChatTitle")
        header_layout.addWidget(self.chat_title)
        self.identity_status = QLabel()
        self.identity_status.setToolTip("Статус текущих устройств. Сообщения, полученные до проверки ключей, не подтверждаются задним числом.")
        self.identity_status.setVisible(False)
        header_layout.addWidget(self.identity_status)
        header_layout.addStretch()

        self.search_btn = ThemedIconButton(str(ICONS_PATH / "search.svg"), 40, 18)
        self.search_btn.setObjectName("HeaderIconBtn")
        self.search_btn.setVisible(False)
        self.search_btn.clicked.connect(self._toggle_search)
        header_layout.addWidget(self.search_btn)

        self.chat_menu_btn = ThemedIconButton(str(ICONS_PATH / "more.svg"), 40, 18)
        self.chat_menu_btn.setObjectName("HeaderIconBtn")
        self.chat_menu_btn.setVisible(False)
        self.chat_menu_btn.clicked.connect(self._show_chat_menu)
        header_layout.addWidget(self.chat_menu_btn)

        self.call_btn = ThemedIconButton(str(ICONS_PATH / "phone.svg"), 40, 18)
        self.call_btn.setObjectName("HeaderIconBtn")
        self.call_btn.setVisible(False)
        self.call_btn.clicked.connect(self._on_start_call)
        header_layout.addWidget(self.call_btn)

        self.group_voice_btn = ThemedIconButton(str(ICONS_PATH / "headset_on.svg"), 40, 18)
        self.group_voice_btn.setObjectName("HeaderIconBtn")
        self.group_voice_btn.setToolTip("Голосовая комната группы (2–8 чел.)")
        self.group_voice_btn.setVisible(False)
        self.group_voice_btn.clicked.connect(self._on_toggle_group_voice_btn)
        header_layout.addWidget(self.group_voice_btn)

        # Messages
        self.messages_scroll = QScrollArea()
        self.messages_scroll.setObjectName("MessagesScroll")
        self.messages_scroll.setWidgetResizable(True)
        self.messages_container = QFrame()
        self.messages_container.setObjectName("MessagesContainer")
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.setContentsMargins(32, 24, 32, 24)
        self.messages_layout.addStretch()
        self.messages_scroll.setWidget(self.messages_container)

        # The page controls never delete history: only a small window is rendered.
        self.history_nav = QFrame()
        nav_layout = QHBoxLayout(self.history_nav)
        nav_layout.setContentsMargins(32, 4, 32, 4)
        self.history_older = QPushButton("← Старые")
        self.history_newer = QPushButton("Новые →")
        self.history_range = QLabel("")
        self.history_older.clicked.connect(lambda: self._change_history_page(PAGE_SIZE))
        self.history_newer.clicked.connect(lambda: self._change_history_page(-PAGE_SIZE))
        nav_layout.addWidget(self.history_older)
        nav_layout.addWidget(self.history_range, 1, Qt.AlignCenter)
        nav_layout.addWidget(self.history_newer)
        self.history_nav.setVisible(False)

        # Search bar
        self.search_bar = QFrame()
        self.search_bar.setObjectName("SearchBar")
        self.search_bar.setFixedHeight(50)
        self.search_bar.setVisible(False)
        search_layout = QHBoxLayout(self.search_bar)
        search_layout.setContentsMargins(32, 8, 32, 8)
        search_layout.setSpacing(12)
        self.search_input = QLineEdit()
        self.search_input.setObjectName("SearchInput")
        self.search_input.setPlaceholderText("Поиск сообщений...")
        self.search_input.returnPressed.connect(self._do_search)
        self.search_close_btn = ThemedIconButton(
            str(ICONS_PATH / "close_small.svg"), 30, 12
        )
        self.search_close_btn.setObjectName("SearchCloseBtn")
        self.search_close_btn.clicked.connect(self._close_search)
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.search_close_btn)

        # Typing
        self.typing_label = QLabel("")
        self.typing_label.setObjectName("TypingIndicator")
        self.typing_label.setVisible(False)
        self.typing_label.setFixedHeight(20)
        self._typing_timer = QTimer()
        self._typing_timer.setSingleShot(True)
        self._typing_timer.timeout.connect(lambda: self.typing_label.setVisible(False))
        self._my_typing_timer = QTimer()
        self._my_typing_timer.setSingleShot(True)

        # Reply preview
        self.reply_preview = QFrame()
        self.reply_preview.setObjectName("ReplyPreview")
        self.reply_preview.setFixedHeight(50)
        self.reply_preview.setVisible(False)
        reply_preview_layout = QHBoxLayout(self.reply_preview)
        reply_preview_layout.setContentsMargins(32, 8, 32, 8)
        reply_preview_layout.setSpacing(12)

        _t = get_theme()
        _reply_icon_lbl = QLabel()
        _reply_icon_lbl.setFixedSize(14, 14)
        _reply_icon_lbl.setFocusPolicy(Qt.NoFocus)
        svg_path = ICONS_PATH / "reply_small.svg"
        if svg_path.exists():
            svg_content = svg_path.read_text(encoding="utf-8")
            svg_colored = svg_content.replace(
                "currentColor", _t.get("accent_start", "#6c748a")
            )
            _renderer = QSvgRenderer(svg_colored.encode("utf-8"))
            _pix = QPixmap(14, 14)
            _pix.fill(Qt.transparent)
            _p = QPainter(_pix)
            _p.setRenderHint(QPainter.Antialiasing)
            _renderer.render(_p)
            _p.end()
            _reply_icon_lbl.setPixmap(_pix)
        reply_preview_layout.addWidget(_reply_icon_lbl)

        reply_info_layout = QVBoxLayout()
        reply_info_layout.setSpacing(2)
        self.reply_preview_sender = QLabel()
        self.reply_preview_sender.setObjectName("ReplyPreviewSender")
        self.reply_preview_text = QLabel()
        self.reply_preview_text.setObjectName("ReplyPreviewText")
        reply_info_layout.addWidget(self.reply_preview_sender)
        reply_info_layout.addWidget(self.reply_preview_text)

        self.reply_cancel_btn = ThemedIconButton(
            str(ICONS_PATH / "close_small.svg"), 30, 12
        )
        self.reply_cancel_btn.setObjectName("ReplyCancelBtn")
        self.reply_cancel_btn.clicked.connect(self._cancel_reply)
        reply_preview_layout.addLayout(reply_info_layout, 1)
        reply_preview_layout.addWidget(self.reply_cancel_btn)

        # Image preview
        self.image_preview_panel = ImagePreviewPanel()
        self.image_preview_panel.setVisible(False)
        self.image_preview_panel.send_requested.connect(self._on_image_preview_send)
        self.image_preview_panel.cancel_requested.connect(self._on_image_preview_cancel)

        # Voice recording bar
        self.voice_recording_bar = VoiceRecordingBar()
        self.voice_recording_bar.setVisible(False)
        self.voice_recording_bar.cancel_requested.connect(self._cancel_voice_recording)

        # Input area
        self.input_area = QFrame()
        self.input_area.setObjectName("InputArea")
        input_layout = QHBoxLayout(self.input_area)
        input_layout.setContentsMargins(32, 16, 32, 28)
        input_layout.setSpacing(12)

        self.attach_btn = ThemedIconButton(str(ICONS_PATH / "attach.svg"), 44, 20)
        self.attach_btn.setObjectName("HeaderIconBtn")
        self.attach_btn.setEnabled(False)
        self.attach_btn.clicked.connect(self._on_attach_file)

        self.msg_input = SmartInput()
        self.msg_input.setObjectName("MessageInput")
        self.msg_input.setEnabled(False)
        self.msg_input.returnPressed.connect(self._on_send_message)
        self.msg_input.imagePasted.connect(self._on_image_pasted)
        if hasattr(self.msg_input, "filesDroppedOrPasted"):
            self.msg_input.filesDroppedOrPasted.connect(self._on_files_dropped_or_pasted)
        self.msg_input.textChanged.connect(self._on_typing)
        self.setAcceptDrops(True)

        self._action_btn_stack = QStackedWidget()
        self._action_btn_stack.setFixedSize(44, 44)
        self._action_btn_stack.setFocusPolicy(Qt.NoFocus)
        self._action_btn_stack.setObjectName("ActionBtnStack")

        self.mic_input_btn = ThemedIconButton(str(ICONS_PATH / "mic_on.svg"), 44, 20)
        self.mic_input_btn.setObjectName("HeaderIconBtn")
        self.mic_input_btn.setEnabled(False)
        self.mic_input_btn.pressed.connect(self._start_voice_recording)
        self.mic_input_btn.released.connect(self._stop_voice_recording)

        self.send_btn = ThemedIconButton(str(ICONS_PATH / "send.svg"), 44, 20)
        self.send_btn.setObjectName("HeaderIconBtn")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self._on_send_message)

        self._action_btn_stack.addWidget(self.mic_input_btn)
        self._action_btn_stack.addWidget(self.send_btn)
        self._action_btn_stack.setCurrentIndex(0)

        self._mic_opacity  = QGraphicsOpacityEffect(self.mic_input_btn)
        self._send_opacity = QGraphicsOpacityEffect(self.send_btn)
        self._mic_opacity.setOpacity(1.0)
        self._send_opacity.setOpacity(0.0)
        self.mic_input_btn.setGraphicsEffect(self._mic_opacity)
        self.send_btn.setGraphicsEffect(self._send_opacity)

        self._fade_to_send_anim = QPropertyAnimation(self._send_opacity, b"opacity")
        self._fade_to_send_anim.setDuration(150)
        self._fade_to_send_anim.setStartValue(0.0)
        self._fade_to_send_anim.setEndValue(1.0)
        self._fade_to_send_anim.setEasingCurve(QEasingCurve.InOutQuad)

        self._fade_to_mic_anim = QPropertyAnimation(self._mic_opacity, b"opacity")
        self._fade_to_mic_anim.setDuration(150)
        self._fade_to_mic_anim.setStartValue(0.0)
        self._fade_to_mic_anim.setEndValue(1.0)
        self._fade_to_mic_anim.setEasingCurve(QEasingCurve.InOutQuad)

        self._fade_mic_out_anim = QPropertyAnimation(self._mic_opacity, b"opacity")
        self._fade_mic_out_anim.setDuration(150)
        self._fade_mic_out_anim.setStartValue(1.0)
        self._fade_mic_out_anim.setEndValue(0.0)
        self._fade_mic_out_anim.setEasingCurve(QEasingCurve.InOutQuad)

        self._fade_send_out_anim = QPropertyAnimation(self._send_opacity, b"opacity")
        self._fade_send_out_anim.setDuration(150)
        self._fade_send_out_anim.setStartValue(1.0)
        self._fade_send_out_anim.setEndValue(0.0)
        self._fade_send_out_anim.setEasingCurve(QEasingCurve.InOutQuad)

        self._showing_send_btn = False
        self._editing_msg_id = None

        input_layout.addWidget(self.attach_btn, 0, Qt.AlignBottom)
        input_layout.addWidget(self.msg_input)
        input_layout.addWidget(self._action_btn_stack, 0, Qt.AlignBottom)

        self._init_group_voice_ui()
        self._init_pinned_banner_ui()

        chat_layout.addWidget(self.chat_header)
        chat_layout.addWidget(self.pinned_banner)
        chat_layout.addWidget(self.group_voice_bar)
        chat_layout.addWidget(self.search_bar)
        chat_layout.addWidget(self.history_nav)
        chat_layout.addWidget(self.messages_scroll, 1)
        chat_layout.addWidget(self.typing_label)
        chat_layout.addWidget(self.reply_preview)
        chat_layout.addWidget(self.image_preview_panel)
        chat_layout.addWidget(self.voice_recording_bar)
        chat_layout.addWidget(self.input_area, 0)

        self.right_stack.addWidget(self.empty_state)
        self.right_stack.addWidget(self.chat_area)

        layout.addWidget(self.sidebar)
        layout.addWidget(self.right_stack)

        self._init_call_ui()

        from app.windows.widgets.screen_share_overlay import ScreenShareOverlay, ScreenShareViewer
        self.screen_share_overlay = ScreenShareOverlay(self)
        self.screen_share_overlay.monitor_selected.connect(self._on_monitor_selected)
        self.screen_share_overlay.quality_selected.connect(self._set_screen_share_quality)
        self.screen_share_overlay.cancelled.connect(self._on_screen_share_cancelled)
        self.screen_share_viewer = ScreenShareViewer(self)
        self.screen_share_viewer.close_requested.connect(self._stop_remote_screen_share)
        self.screen_share_viewer.maximize_requested.connect(self._toggle_screen_share_maximize)
        self.screen_share_viewer.setVisible(False)

        chat_layout.addWidget(self.screen_share_viewer, 1)

        self._voice_playback_finished.connect(self._on_voice_playback_finished)
        self._voice_progress_update.connect(self._on_voice_progress_update)
        self._voice_level_signal.connect(self._on_voice_level_update)
        self._voice_recording_error.connect(self._on_voice_recording_error, Qt.QueuedConnection)
        self._voice_recording_limit.connect(self._on_voice_recording_limit, Qt.QueuedConnection)

        # ── Animated background timer ──
        self._bg_timer = QTimer(self)
        self._bg_timer.timeout.connect(self._tick_bg_animation)
        self._bg_timer.start(50)

        # ── Animated background widget inside chat_area ──
        self._bg_frame = QFrame(self.chat_area)
        self._bg_frame.setObjectName("AnimatedBgFrame")
        self._bg_frame.setStyleSheet("background: transparent;")
        self._bg_particles = []
        self._bg_waves = []
        self._bg_tick_count = 0
        self._bg_initialized = False

        # Override paintEvent для bg_frame
        def bg_paintEvent(event):
            painter = QPainter(self._bg_frame)
            painter.setRenderHint(QPainter.Antialiasing, True)
            w, h = self._bg_frame.width(), self._bg_frame.height()
            if w <= 0 or h <= 0:
                painter.end()
                return
            has_content = self._bg_particles or self._bg_waves
            if not has_content:
                painter.end()
                return
            from app.theme import get_theme_name
            theme = get_theme_name()
            if theme == "obsidian":
                for p in self._bg_particles:
                    p["x"] += p["vx"]; p["y"] += p["vy"]
                    if p["y"] - p["r"] > h: p["y"] = -10; p["x"] = random.uniform(0, w)
                    if p["x"] < -20: p["x"] = w + 5
                    elif p["x"] > w + 20: p["x"] = -5
                    grad = QRadialGradient(p["x"], p["y"], p["r"] * 2.5)
                    grad.setColorAt(0.0, QColor(180, 190, 220, p["a"]))
                    grad.setColorAt(1.0, QColor(0, 0, 0, 0))
                    painter.setPen(Qt.NoPen); painter.setBrush(QBrush(grad))
                    painter.drawEllipse(QPoint(int(p["x"]), int(p["y"])), int(p["r"]), int(p["r"]))
            elif theme == "frost":
                import math
                for wave in self._bg_waves:
                    wave["phase"] += wave["speed"] * 0.02
                    path = QPainterPath()
                    for x_pos in range(0, w + 1, 4):
                        y_pos = wave["y_offset"] + wave["amplitude"] * math.sin(wave["phase"] + x_pos * 0.005)
                        if x_pos == 0: path.moveTo(x_pos, y_pos)
                        else: path.lineTo(x_pos, y_pos)
                    pen = QPen(QColor(95, 135, 255, wave["alpha"]))
                    pen.setWidthF(wave["width"])
                    painter.setPen(pen); painter.setBrush(Qt.NoBrush)
                    painter.drawPath(path)
            elif theme == "rose":
                for p in self._bg_particles:
                    p["x"] += p["vx"]; p["y"] += p["vy"]
                    if p["y"] - p["r"] > h: p["y"] = -10; p["x"] = random.uniform(0, w)
                    if p["x"] < -20: p["x"] = w + 5
                    elif p["x"] > w + 20: p["x"] = -5
                    grad = QRadialGradient(p["x"], p["y"], p["r"] * 2.5)
                    grad.setColorAt(0.0, QColor(211, 139, 179, p["a"]))
                    grad.setColorAt(1.0, QColor(0, 0, 0, 0))
                    painter.setPen(Qt.NoPen); painter.setBrush(QBrush(grad))
                    painter.drawEllipse(QPoint(int(p["x"]), int(p["y"])), int(p["r"]), int(p["r"]))
            painter.end()

        self._bg_frame.paintEvent = bg_paintEvent

        self._load_allies_from_storage()

    def process_incoming_message(self, data: dict, is_sync: bool = False) -> bool:
        """Never acknowledge an unknown, unverified or unsaved message."""
        account = (state.username, state.server_url, state.device_id, getattr(state, "token", None))
        try:
            owner_key = crypto.get_public_key_b64()
            context, decrypted = verify_incoming(state, crypto, data)
        except IncomingIdentityError:
            if not self._incoming_identity_notice_shown:
                self._incoming_identity_notice_shown = True
                window = self.window()
                if hasattr(window, "show_notification"):
                    window.show_notification("Проверка устройств", "Некоторые входящие сообщения ожидают проверки ключа или не прошли проверку. Они не подтверждены серверу.")
            return False
        except Exception as exc:
            print(f"[PROCESS] Не удалось проверить локальный ключ: {type(exc).__name__}")
            return False
        try:
            from app.recipient_context import recipient_is_verified
            def context_valid():
                return (account == (state.username, state.server_url, state.device_id, getattr(state, "token", None))
                        and crypto.get_public_key_b64() == owner_key
                        and recipient_is_verified(state, context))
            if not context_valid():
                return False
            if not self._handle_decrypted_payload(context.username, decrypted, data["signature"], is_sync,
                                                  session_guard=context_valid, sender_context=context,
                                                  account_context=account):
                return False
            if not context_valid():
                return False
            raw_blob = data.get("encrypted_blob") if isinstance(data, dict) else None
            srv_id = data.get("id") if isinstance(data, dict) else None
            if isinstance(raw_blob, str) and raw_blob.startswith("TTFEUjAx") and isinstance(srv_id, str) and srv_id:
                try:
                    from app.double_ratchet import RatchetStore
                    RatchetStore(state.username).mark_delivery_persisted(srv_id)
                except Exception:
                    pass
            self.incoming_message_processed.emit(data)
            return True
        except Exception as e:
            print(f"[PROCESS] Ошибка сохранения или обработки: {type(e).__name__}")
            return False

    def showEvent(self, event):
        super().showEvent(event)
        self._init_bg_particles()

    def _init_bg_particles(self):
        from app.theme import get_theme_name
        theme = get_theme_name()
        w, h = self.chat_area.width(), self.chat_area.height() if hasattr(self, 'chat_area') and self.chat_area.width() > 0 else self.width()
        if w <= 0 or h <= 0:
            return
        self._bg_particles = []
        self._bg_waves = []

        if theme == "obsidian":
            for _ in range(25):
                self._bg_particles.append({
                    "x": random.uniform(0, w), "y": random.uniform(0, h),
                    "vx": random.uniform(-0.03, 0.03), "vy": random.uniform(0.05, 0.2),
                    "r": random.uniform(1.0, 3.0), "a": random.randint(30, 80),
                })
        elif theme == "frost":
            for i in range(5):
                self._bg_waves.append({
                    "y_offset": h * (0.2 + i * 0.15),
                    "amplitude": random.uniform(10, 20),
                    "speed": random.uniform(0.4, 0.8),
                    "phase": random.uniform(0, 6.28),
                    "alpha": random.randint(18, 40),
                    "width": random.uniform(1.5, 3.0),
                })
        elif theme == "rose":
            for _ in range(18):
                self._bg_particles.append({
                    "x": random.uniform(0, w), "y": random.uniform(0, h),
                    "vx": random.uniform(-0.02, 0.02), "vy": random.uniform(0.04, 0.15),
                    "r": random.uniform(1.5, 4.0), "a": random.randint(15, 50),
                })
        self._bg_tick_count = 0

    def _tick_bg_animation(self):
        if not hasattr(self, '_bg_frame') or not self._bg_frame:
            return
        if not self._bg_initialized:
            self._init_bg_particles()
            self._bg_initialized = True
        ca = self.chat_area
        if ca and ca.width() > 0 and ca.height() > 0:
            self._bg_frame.setGeometry(0, 0, ca.width(), ca.height())
            self._bg_frame.lower()
            self._bg_frame.update()

    def paintEvent(self, event):
        super().paintEvent(event)

    def process_sync_messages(self, messages: list):
        for data in messages:
            self.process_incoming_message(data, is_sync=True)

    def _handle_decrypted_payload(self, sender_username: str, decrypted_text: str,
                                   signature: str, is_sync: bool = False, *,
                                   session_guard=None, sender_context=None, account_context=None):
        def current_session():
            return session_guard is None or session_guard()

        def send_read_receipt(msg_id):
            payload = {"type": "read_ack", "msg_ids": [msg_id]}
            if sender_context is None:
                return self._send_system_payload(sender_username, payload)
            return self._send_system_payload(sender_username, payload, context=sender_context,
                                             account_context=account_context)

        if not current_session():
            return False
        if not isinstance(decrypted_text, str) or len(decrypted_text) > 1024 * 1024:
            return False
        def _reject_non_finite_constant(constant):
            raise ValueError(constant)
        try:
            payload = json.loads(decrypted_text, parse_constant=_reject_non_finite_constant)
        except json.JSONDecodeError:
            if len(decrypted_text) > 256 * 1024:
                return False
            payload = {"type": "text", "text": decrypted_text, "msg_id": signature}
        except (ValueError, RecursionError):
            return False

        if not isinstance(payload, dict):
            return False
        _depth_stack = [(payload, 0)]
        while _depth_stack:
            _cur, _depth = _depth_stack.pop()
            if _depth > 16:
                return False
            if isinstance(_cur, dict):
                for _k, _v in _cur.items():
                    if not isinstance(_k, str) or len(_k) > 128:
                        return False
                    if isinstance(_v, (dict, list)):
                        _depth_stack.append((_v, _depth + 1))
            elif isinstance(_cur, list):
                for _item in _cur:
                    if isinstance(_item, (dict, list)):
                        _depth_stack.append((_item, _depth + 1))
        msg_type = payload.get("type", "text")
        if not isinstance(msg_type, str):
            return False
        # Reject malformed fields before any history mutation. These are still
        # untrusted even after signature verification by a trusted contact.
        if msg_type in {"text", "image", "voice", "file"}:
            reply = payload.get("reply_to")
            if reply is not None:
                if not isinstance(reply, dict):
                    return False
                for field in ("msg_id", "text", "sender"):
                    value = reply.get(field)
                    if value is not None and not isinstance(value, str):
                        return False
                if isinstance(reply.get("msg_id"), str) and len(reply["msg_id"]) > 256:
                    return False
                if isinstance(reply.get("text"), str) and len(reply["text"]) > 4096:
                    return False
                if isinstance(reply.get("sender"), str) and len(reply["sender"]) > 64:
                    return False
            if msg_type == "text":
                text_val = payload.get("text", "")
                if not isinstance(text_val, str) or len(text_val) > 256 * 1024:
                    return False
            if msg_type in {"image", "file"}:
                caption_val = payload.get("caption", "")
                if not isinstance(caption_val, str) or len(caption_val) > 8192:
                    return False
            if msg_type == "file":
                fn_val = payload.get("filename")
                sz_val = payload.get("size_bytes")
                if (not isinstance(fn_val, str) or not 1 <= len(fn_val) <= 255
                        or isinstance(sz_val, bool) or not isinstance(sz_val, int)
                        or not 0 <= sz_val <= 20 * 1024 * 1024):
                    return False
            raw_ttl_check = payload.get("ttl_seconds")
            if raw_ttl_check is not None:
                if isinstance(raw_ttl_check, bool) or not isinstance(raw_ttl_check, int) or not (5 <= raw_ttl_check <= 30 * 86400):
                    return False
        if msg_type == "dr_already_processed":
            return True
        if msg_type.startswith("webrtc_"):
            return True

        if msg_type == "typing":
            if state.current_chat_username == sender_username:
                self.typing_label.setText(f"@{sender_username} печатает...")
                self.typing_label.setVisible(True)
                self._typing_timer.start(4000)
            return True

        if msg_type == "read_ack":
            ack_ids = payload.get("msg_ids", [])
            if (not isinstance(ack_ids, list) or len(ack_ids) > MAX_READ_ACK_IDS
                    or any(not isinstance(item, str) or not item or len(item) > 256 for item in ack_ids)):
                return False
            changed = storage.mark_messages_as_read(state.username, sender_username, ack_ids, only_mine=True)
            if not current_session():
                return False
            if changed:
                if state.current_chat_username == sender_username:
                    for i in range(self.messages_layout.count() - 1):
                        widget = self.messages_layout.itemAt(i).widget()
                        if (hasattr(widget, "msg_id") and widget.msg_id in ack_ids
                                and getattr(widget, "is_mine", False)):
                            widget.mark_as_read()
            return True

        if msg_type == "delete_msg":
            deleted_msg_id = payload.get("msg_id")
            if not isinstance(deleted_msg_id, str) or not deleted_msg_id or len(deleted_msg_id) > 256:
                return False
            if deleted_msg_id:
                if not storage.delete_incoming_message(state.username, sender_username, deleted_msg_id):
                    return False
                if not current_session():
                    return False
                voice_cache.delete_group(message_scope(state.username, state.server_url, sender_username, deleted_msg_id))
                if state.current_chat_username == sender_username:
                    self._render_history_page()
            return True

        if msg_type == "edit_msg":
            edit_id = payload.get("msg_id")
            new_text = payload.get("new_text")
            if (
                not isinstance(edit_id, str)
                or not 1 <= len(edit_id) <= 256
                or not isinstance(new_text, str)
                or not 1 <= len(new_text) <= 256 * 1024
                or new_text.startswith(("[IMAGE_META]|", "[VOICE_META]|", "[FILE_META]|"))
            ):
                return False
            edit_fn = getattr(storage, "edit_message", None)
            if not callable(edit_fn) or not edit_fn(
                state.username, sender_username, edit_id, new_text, only_incoming=True
            ):
                return False
            if not current_session():
                return False
            if state.current_chat_username == sender_username and hasattr(self, "_render_history_page"):
                self._render_history_page()
            return True

        if msg_type == "pin_msg":
            pin_id = payload.get("msg_id", "")
            pin_preview = payload.get("preview", "")
            if not isinstance(pin_id, str) or len(pin_id) > 256 or not isinstance(pin_preview, str) or len(pin_preview) > 1024:
                return False
            set_pin_fn = getattr(storage, "set_pinned_message", None)
            if callable(set_pin_fn):
                pin_obj = {"msg_id": pin_id, "preview": pin_preview} if pin_id else None
                set_pin_fn(state.username, sender_username, pin_obj)
            if state.current_chat_username == sender_username and hasattr(self, "_refresh_pinned_banner"):
                self._refresh_pinned_banner()
            return True

        msg_id           = payload.get("msg_id") or signature
        if not isinstance(msg_id, str) or not msg_id or len(msg_id) > 256:
            return False
        extra_ttl_kw = {}
        raw_ttl = payload.get("ttl_seconds")
        if raw_ttl is not None:
            import time as _time
            extra_ttl_kw["expires_at"] = int(_time.time() + raw_ttl)
        is_window_active = self.window().isActiveWindow()
        is_chat_open     = (state.current_chat_username == sender_username)
        show_live        = is_chat_open and self._history_available and self._history_offset == 0 and self._history_query is None
        is_read_now      = (show_live and is_window_active and self.isVisible()
                            and self.right_stack.currentWidget() is self.chat_area)
        should_notify    = not is_window_active

        if msg_type == "text":
            text            = payload.get("text", "")
            reply_to        = payload.get("reply_to")
            reply_to_msg_id = reply_to.get("msg_id")   if reply_to else None
            reply_to_text   = reply_to.get("text")     if reply_to else None
            reply_to_sender = reply_to.get("sender")   if reply_to else None

            is_new = storage.save_message(
                state.username, sender_username, text,
                is_mine=False, msg_id=msg_id, is_read=is_read_now,
                reply_to_msg_id=reply_to_msg_id,
                reply_to_text=reply_to_text,
                reply_to_sender=reply_to_sender,
                **extra_ttl_kw,
            )
            if not current_session():
                return False
            if is_new:
                card = self._get_ally_card(sender_username)
                if card:
                    card.update_preview(text)
                ally_item = self._get_ally_item(sender_username)
                if ally_item:
                    ally_item.last_activity = time.time()
                    self.allies_list.sortItems(Qt.DescendingOrder)

            if show_live and is_new:
                if is_read_now:
                    send_read_receipt(msg_id)
                already_exists = any(
                    hasattr(self.messages_layout.itemAt(i).widget(), "msg_id") and
                    self.messages_layout.itemAt(i).widget().msg_id == msg_id
                    for i in range(self.messages_layout.count() - 1)
                )
                if not already_exists:
                    bubble = MessageBubble(
                        text, is_mine=False, is_read=is_read_now,
                        reply_to_text=reply_to_text,
                        reply_to_sender=reply_to_sender,
                        reply_to_msg_id=reply_to_msg_id,
                    )
                    bubble.msg_id = msg_id
                    self._connect_bubble_signals(bubble, sender_username)
                    self.messages_layout.insertWidget(
                        self.messages_layout.count() - 1, bubble
                    )
                    QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
                        self.messages_scroll.verticalScrollBar().maximum()
                    ))
            if not is_read_now and is_new:
                card = self._get_ally_card(sender_username)
                if card:
                    card.increment_unread()
            if should_notify and is_new:
                main_window = self.window()
                if hasattr(main_window, "show_notification"):
                    preview = text[:80] + ("..." if len(text) > 80 else "")
                    main_window.show_notification(f"@{sender_username}", preview)

        elif msg_type == "image":
            file_id    = payload.get("file_id")
            secret_key = payload.get("secret_key")
            caption    = payload.get("caption", "")
            if not valid_file_id(file_id) or not valid_file_key(secret_key):
                return False
            reply_to        = payload.get("reply_to")
            reply_to_msg_id = reply_to.get("msg_id")  if reply_to else None
            reply_to_text   = reply_to.get("text")    if reply_to else None
            reply_to_sender = reply_to.get("sender")  if reply_to else None

            special_text = f"[IMAGE_META]|{file_id}|{secret_key}|{caption}"
            is_new = storage.save_message(
                state.username, sender_username, special_text,
                is_mine=False, msg_id=msg_id, is_read=is_read_now,
                reply_to_msg_id=reply_to_msg_id,
                reply_to_text=reply_to_text,
                reply_to_sender=reply_to_sender,
                **extra_ttl_kw,
            )
            if not current_session():
                return False
            if is_new:
                card = self._get_ally_card(sender_username)
                if card:
                    card.update_preview("Фото")
                ally_item = self._get_ally_item(sender_username)
                if ally_item:
                    ally_item.last_activity = time.time()
                    self.allies_list.sortItems(Qt.DescendingOrder)
                if show_live:
                    if is_read_now:
                        send_read_receipt(msg_id)
                    bubble = MessageBubble(
                        "", is_mine=False, is_read=is_read_now,
                        reply_to_text=reply_to_text,
                        reply_to_sender=reply_to_sender,
                        reply_to_msg_id=reply_to_msg_id,
                    )
                    bubble.show_skeleton()
                    bubble.msg_id = msg_id
                    self._connect_bubble_signals(bubble, sender_username)
                    self.messages_layout.insertWidget(
                        self.messages_layout.count() - 1, bubble
                    )
                    QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
                        self.messages_scroll.verticalScrollBar().maximum()
                    ))
                    worker = DownloadFileWorker(state.server_url, state.token, file_id)
                    worker.secret_key = secret_key
                    worker.bubble     = bubble
                    worker.caption    = caption
                    worker.finished.connect(
                        lambda w=worker: self._on_download_finished(*w.result, w),
                        Qt.QueuedConnection
                    )
                    worker.file_id_cache = self._media_asset_key(file_id, secret_key)
                    self._queue_media_download(worker)
                if not is_read_now and card:
                    card.increment_unread()
                if should_notify:
                    main_window = self.window()
                    if hasattr(main_window, "show_notification"):
                        main_window.show_notification(f"@{sender_username}", "Фото")

        elif msg_type == "voice":
            file_id    = payload.get("file_id")
            secret_key = payload.get("secret_key")
            duration   = payload.get("duration", 0)
            if (not valid_file_id(file_id) or not valid_file_key(secret_key)
                    or isinstance(duration, bool) or not isinstance(duration, (int, float))
                    or not 0 <= duration <= 86400 or not math.isfinite(duration)):
                return False
            duration = max(duration, 0.1)
            reply_to        = payload.get("reply_to")
            reply_to_msg_id = reply_to.get("msg_id")  if reply_to else None
            reply_to_text   = reply_to.get("text")    if reply_to else None
            reply_to_sender = reply_to.get("sender")  if reply_to else None

            special_text = f"[VOICE_META]|{file_id}|{secret_key}|{duration:.1f}"
            is_new = storage.save_message(
                state.username, sender_username, special_text,
                is_mine=False, msg_id=msg_id, is_read=is_read_now,
                reply_to_msg_id=reply_to_msg_id,
                reply_to_text=reply_to_text,
                reply_to_sender=reply_to_sender,
                **extra_ttl_kw,
            )
            if not current_session():
                return False
            if is_new:
                card = self._get_ally_card(sender_username)
                if card:
                    card.update_preview("Голосовое")
                ally_item = self._get_ally_item(sender_username)
                if ally_item:
                    ally_item.last_activity = time.time()
                    self.allies_list.sortItems(Qt.DescendingOrder)
                if show_live:
                    if is_read_now:
                        send_read_receipt(msg_id)
                    bubble = MessageBubble(
                        "", is_mine=False, is_read=is_read_now,
                        voice_duration=duration,
                        reply_to_text=reply_to_text,
                        reply_to_sender=reply_to_sender,
                        reply_to_msg_id=reply_to_msg_id,
                    )
                    bubble.msg_id = msg_id
                    self._connect_bubble_signals(bubble, sender_username)
                    self.messages_layout.insertWidget(
                        self.messages_layout.count() - 1, bubble
                    )
                    QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
                        self.messages_scroll.verticalScrollBar().maximum()
                    ))
                    self._prepare_voice_bubble(bubble, file_id, secret_key, msg_id)
                if not is_read_now and card:
                    card.increment_unread()
                if should_notify:
                    main_window = self.window()
                    if hasattr(main_window, "show_notification"):
                        main_window.show_notification(
                            f"@{sender_username}", "Голосовое сообщение"
                        )

        elif msg_type == "file":
            from app.media_identity import build_file_meta, sanitize_attachment_filename
            file_id    = payload.get("file_id")
            secret_key = payload.get("secret_key")
            raw_fname  = payload.get("filename", "document.bin")
            size_bytes = payload.get("size_bytes", 0)
            caption    = payload.get("caption", "")
            if not valid_file_id(file_id) or not valid_file_key(secret_key):
                return False
            safe_fname = sanitize_attachment_filename(raw_fname)
            try:
                special_text = build_file_meta(file_id, secret_key, safe_fname, size_bytes, caption)
            except ValueError:
                return False
            reply_to        = payload.get("reply_to")
            reply_to_msg_id = reply_to.get("msg_id")  if reply_to else None
            reply_to_text   = reply_to.get("text")    if reply_to else None
            reply_to_sender = reply_to.get("sender")  if reply_to else None

            is_new = storage.save_message(
                state.username, sender_username, special_text,
                is_mine=False, msg_id=msg_id, is_read=is_read_now,
                reply_to_msg_id=reply_to_msg_id,
                reply_to_text=reply_to_text,
                reply_to_sender=reply_to_sender,
                **extra_ttl_kw,
            )
            if not current_session():
                return False
            if is_new:
                card = self._get_ally_card(sender_username)
                if card:
                    card.update_preview(f"📄 {safe_fname}")
                ally_item = self._get_ally_item(sender_username)
                if ally_item:
                    import time as _time
                    ally_item.last_activity = _time.time()
                    self.allies_list.sortItems(Qt.DescendingOrder)
                if show_live:
                    if is_read_now:
                        send_read_receipt(msg_id)
                    bubble = MessageBubble(
                        "", is_mine=False, is_read=is_read_now,
                        reply_to_text=reply_to_text,
                        reply_to_sender=reply_to_sender,
                        reply_to_msg_id=reply_to_msg_id,
                    )
                    bubble.msg_id = msg_id
                    bubble.set_document(file_id, secret_key, safe_fname, size_bytes, caption=caption)
                    self._connect_bubble_signals(bubble, sender_username)
                    self.messages_layout.insertWidget(
                        self.messages_layout.count() - 1, bubble
                    )
                    QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
                        self.messages_scroll.verticalScrollBar().maximum()
                    ))
                if not is_read_now and card:
                    card.increment_unread()
                if should_notify:
                    main_window = self.window()
                    if hasattr(main_window, "show_notification"):
                        main_window.show_notification(f"@{sender_username}", f"📄 {safe_fname}")

        if msg_type in {"text", "image", "voice", "file"} and is_new and is_chat_open:
            if show_live:
                self._history_total += 1
                self._trim_live_history()
            elif self._history_query is None and self._history_available:
                self._history_offset += 1
                self._history_total += 1
                self._update_history_navigation()
            elif getattr(self, "_history_worker", None) is not None:
                if self._history_query is None and self._history_offset > 0:
                    self._history_offset += 1
                request = self._history_pending or self._history_worker.history_request
                if len(request) < 4:
                    self._render_history_page()
            worker = getattr(self, "_history_worker", None)
            if worker is not None:
                request = self._history_pending or worker.history_request
                current_account_chat = (state.username, state.server_url, state.device_id, state.token,
                                        state.current_chat_type, state.current_chat_username, state.current_group_id)
                if len(request) > 3 and request[1][:7] == current_account_chat:
                    # Keep reply navigation pointed at the same message as offsets shift.
                    self._request_history_target(request[3])
        return msg_type in {"text", "image", "voice", "file"}

    def _show_create_group_panel(self):
        self.groups_list.setVisible(False)
        self.add_group_btn.setVisible(False)
        self.create_group_panel.refresh_allies(state.allies)
        self.create_group_panel.name_input.clear()
        self.create_group_panel.setVisible(True)

    def _hide_create_group_panel(self):
        self.create_group_panel.setVisible(False)
        self.groups_list.setVisible(True)
        self.add_group_btn.setVisible(True)

    def _add_ally_card(self, username: str):
        item = AllyListItem(username)
        item.setSizeHint(QSize(0, 72))
        self.allies_list.addItem(item)
        card = AllyCardWidget(username)
        try:
            page = storage.load_history_page(state.username, username, page_size=1)
        except Exception as exc:
            print(f"[HISTORY] История контакта недоступна: {type(exc).__name__}")
            page = None
            card.update_preview("История недоступна")
        if page and page.messages:
            last_msg = page.messages[-1]
            raw_text = last_msg.get("text", "")
            if raw_text.startswith("[IMAGE_META]"):
                card.update_preview("Фото")
            elif raw_text.startswith("[VOICE_META]"):
                card.update_preview("Голосовое")
            else:
                card.update_preview(raw_text)
            if page.unread:
                card.unread_count = page.unread
                card.badge.setText(str(card.unread_count))
                card.badge.setVisible(True)
            ts_str = last_msg.get("timestamp")
            if ts_str:
                try:
                    item.last_activity = datetime.fromisoformat(ts_str).timestamp()
                except ValueError:
                    item.last_activity = 0.0
        self.allies_list.setItemWidget(item, card)

    def _get_ally_item(self, username: str):
        for i in range(self.allies_list.count()):
            item = self.allies_list.item(i)
            if item.data(Qt.UserRole) == username:
                return item
        return None

    def _get_ally_card(self, username: str):
        item = self._get_ally_item(username)
        return self.allies_list.itemWidget(item) if item else None

    def _load_allies_from_storage(self):
        if not state.username:
            state.username = storage.load_local_state().get("username")
        if not state.username:
            return
        try:
            saved_allies = storage.load_allies(state.username)
        except Exception:
            saved_allies = {}
            QMessageBox.warning(self, "Ошибка контактов", "Файл контактов повреждён или недоступен. Он не будет перезаписан; восстановите его из резервной копии.")
        # Never retain another account's contacts if this profile has none or
        # its local contact file cannot be read.
        state.allies = saved_allies if isinstance(saved_allies, dict) else {}
        self.allies_list.clear()
        for username in state.allies.keys():
            self._add_ally_card(username)
        self.allies_list.sortItems(Qt.DescendingOrder)

    def _persist_groups_index(self):
        if not state.username:
            return
        snapshot = {
            gid: {
                "name": g.get("name", ""),
                "created_by_device_id": g.get("created_by_device_id", ""),
                "archived": bool(g.get("archived", False)),
            }
            for gid, g in state.groups.items()
            if isinstance(gid, str) and isinstance(g, dict)
        }
        try:
            storage.save_groups_index(state.username, snapshot)
        except Exception as exc:
            print(f"[GROUPS] Не удалось сохранить индекс групп: {type(exc).__name__}")

    def _load_groups_from_storage(self):
        if not state.username:
            return
        state.groups = {}
        self.groups_list.clear()
        try:
            saved_groups = storage.load_groups_index(state.username)
        except Exception as exc:
            print(f"[GROUPS] Индекс групп недоступен: {type(exc).__name__}")
            saved_groups = {}
            QMessageBox.warning(
                self,
                "Ошибка списка групп",
                "Локальный список групп повреждён или недоступен. "
                "Он не будет перезаписан; восстановите профиль и ключ из резервной копии.",
            )
        try:
            local_ids = storage.list_local_group_ids(state.username)
        except Exception as exc:
            print(f"[GROUPS] Не удалось перечислить локальные истории групп: {type(exc).__name__}")
            local_ids = []

        all_ids = list(saved_groups.keys())
        for gid in local_ids:
            if gid not in saved_groups:
                all_ids.append(gid)

        for gid in all_ids:
            meta = saved_groups.get(gid) or {}
            name = meta.get("name") or f"Группа {gid[:8]}"
            # Treat locally restored groups as archived until the server confirms
            # active membership; local histories remain readable offline/after leave.
            state.groups[gid] = {
                "name": name,
                "created_by_device_id": meta.get("created_by_device_id", ""),
                "members": [],
                "archived": True,
                "my_sender_key": None,
                "sender_keys": {},
            }
            self._add_group_card(gid, name)

    def _save_allies_to_storage(self):
        storage.save_allies(state.username, state.allies)

    def _on_add_ally(self):
        target = self.ally_input.text().strip()
        if not target:
            return
        self.add_ally_btn.setEnabled(False)
        self.ally_input.setEnabled(False)
        self.search_status.setVisible(False)
        self.find_worker = FindUserWorker(state.server_url, state.token, target)
        self.find_worker.account_context = (state.username, state.server_url, state.device_id, state.token)
        self.find_worker.requested_username = target.lstrip("@")
        worker = self.find_worker
        worker.finished.connect(lambda ok, result, w=worker: self._on_search_finished(ok, result, w), Qt.QueuedConnection)
        worker.start()

    def _on_search_finished(self, success: bool, data, worker):
        if worker is not self.find_worker:
            return
        self.add_ally_btn.setEnabled(True)
        self.ally_input.setEnabled(True)
        if (not self.find_worker or self.find_worker.account_context !=
                (state.username, state.server_url, state.device_id, state.token)):
            self.search_status.setText("Учётная запись изменилась; результат поиска отклонён.")
            self.search_status.setVisible(True)
            return
        if success:
            try:
                ally_username = data.get("username")
                if (not isinstance(ally_username, str) or not ally_username or not data.get("user_id")
                        or ally_username != self.find_worker.requested_username):
                    raise ValueError("Invalid contact")
                device_key_map(data)  # Validate actual public keys, not server fingerprints.
                existing = state.allies.get(ally_username)
                if existing:
                    additions = newly_advertised_devices(existing, data, state.allies, ally_username)
                    if not additions:
                        self.search_status.setText("Уже в списке.")
                        self.search_status.setVisible(True)
                        return
                    snapshot = device_key_map(existing)
                    original_user_id = existing.get("user_id")
                    account = (state.username, state.server_url, state.device_id, state.token)
                    response = QMessageBox.question(
                        self, "Новые устройства контакта",
                        f"Для @{ally_username} найдено новых устройств: {len(additions)}. "
                        "Добавить их как непроверенные? Сообщения с них останутся на сервере до ручной сверки каждого ключа.",
                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                    if response != QMessageBox.Yes:
                        return
                    current = state.allies.get(ally_username)
                    if (account != (state.username, state.server_url, state.device_id, state.token)
                            or not current or current.get("user_id") != original_user_id
                            or device_key_map(current) != snapshot):
                        QMessageBox.warning(self, "Контакт изменился", "Поиск нужно повторить: учётная запись или ключи изменились.")
                        return
                    # Revalidate after the modal dialog; never accept a device
                    # that has meanwhile been assigned to another contact.
                    additions = newly_advertised_devices(current, data, state.allies, ally_username)
                    updated = {**current, "devices": [*current["devices"], *additions]}
                    candidate = {**state.allies, ally_username: updated}
                    try:
                        storage.save_allies(state.username, candidate)
                    except Exception:
                        QMessageBox.warning(self, "Ошибка сохранения", "Устройства не добавлены: не удалось сохранить контакт.")
                        return
                    state.allies[ally_username] = updated
                    self.search_status.setText("Устройства добавлены без доверия. Сверьте их ключи через меню чата.")
                    self.search_status.setVisible(True)
                    self._update_contact_identity_status()
                    return
                # Never map one server device to two local contacts.
                known_ids = {dev.get("device_id") for ally in state.allies.values() for dev in ally.get("devices", [])}
                if known_ids.intersection(device_key_map(data)):
                    raise ValueError("Device belongs to another contact")
                # Verification is a local user decision, never a server claim.
                data = {**data, "devices": [
                    {key: value for key, value in device.items() if key not in {"verified_fingerprint", "verified_scope"}}
                    for device in data["devices"]
                ]}
                state.allies[ally_username] = data
                try:
                    self._save_allies_to_storage()
                except Exception:
                    state.allies.pop(ally_username, None)
                    QMessageBox.warning(self, "Ошибка сохранения", "Не удалось сохранить контакт; он не был добавлен.")
                    return
                self._add_ally_card(ally_username)
                self.ally_input.clear()
                self.search_status.setVisible(False)
                new_item = self._get_ally_item(ally_username)
                if new_item:
                    new_item.last_activity = time.time()
                    self.allies_list.sortItems(Qt.DescendingOrder)
            except (ValueError, TypeError, AttributeError):
                self.search_status.setText("Ключи или устройства изменились либо некорректны; сохранённые данные не заменены.")
                self.search_status.setVisible(True)
        else:
            self.search_status.setText(str(data))
            self.search_status.setVisible(True)

    def _verify_call_contact(self, username: str, device_id: str) -> bool:
        contact = state.allies.get(username, {})
        device = next((d for d in contact.get("devices", []) if d.get("device_id") == device_id), None)
        if not device:
            return False
        account = (state.username, state.device_id, state.server_url, state.token)
        contact_user_id = contact.get("user_id")
        public_key = device.get("public_key")
        try:
            fingerprint = fingerprint_public_key(device.get("public_key"))
        except (ValueError, TypeError):
            QMessageBox.warning(self, "Некорректный ключ", "Ключ устройства контакта повреждён.")
            return False
        context = RecipientContext(username, device_id, public_key, state.username, state.device_id,
                                   state.server_url.rstrip("/"))
        if not recipient_still_trusted(state, context):
            QMessageBox.warning(self, "Проверка отменена", "Устройство контакта неоднозначно или недоступно.")
            return False
        if recipient_is_verified(state, context):
            return True
        prompt_text = self._format_key_verification_prompt(username, public_key, fingerprint)
        answer = QMessageBox.question(
            self, "Проверьте ключ контакта",
            prompt_text,
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return False
        current = next((d for d in state.allies.get(username, {}).get("devices", [])
                        if d.get("device_id") == device_id), None)
        if ((state.username, state.device_id, state.server_url, state.token) != account or current is not device
                or state.allies.get(username, {}).get("user_id") != contact_user_id
                or not recipient_still_trusted(state, context)):
            QMessageBox.warning(self, "Проверка отменена", "Учётная запись или ключ контакта изменились во время проверки.")
            return False
        previous = {k: device[k] for k in ("verified_fingerprint", "verified_scope") if k in device}
        device["verified_fingerprint"] = fingerprint
        device["verified_scope"] = verification_scope(context)
        try:
            self._save_allies_to_storage()
        except Exception:
            device.pop("verified_fingerprint", None)
            device.pop("verified_scope", None)
            device.update(previous)
            QMessageBox.warning(self, "Ошибка сохранения", "Не удалось сохранить проверку ключа.")
            return False
        self._incoming_identity_notice_shown = False
        self._update_contact_identity_status()
        self.contact_verification_changed.emit()
        return True

    def _resolve_preferred_contact_device_id(self, username: str, ally_data: dict = None):
        ally_data = ally_data if isinstance(ally_data, dict) else state.allies.get(username, {})
        if not isinstance(ally_data, dict):
            return None
        raw_devices = ally_data.get("devices")
        if not isinstance(raw_devices, list) or not raw_devices:
            return None
        valid_devices = [
            d for d in raw_devices
            if isinstance(d, dict) and isinstance(d.get("device_id"), str) and d.get("device_id")
        ]
        if not valid_devices:
            return None

        valid_ids = {d["device_id"] for d in valid_devices}
        preferred = ally_data.get("preferred_device_id")
        if not isinstance(preferred, str) or preferred not in valid_ids:
            preferred = None

        verified_ids = []
        owner_user = getattr(state, "username", None)
        owner_dev = getattr(state, "device_id", None)
        srv = getattr(state, "server_url", None)
        if all(isinstance(v, str) and v for v in (owner_user, owner_dev, srv)):
            clean_srv = srv.rstrip("/")
            for dev in valid_devices:
                pub = dev.get("public_key")
                if not isinstance(pub, str) or not pub:
                    continue
                ctx = RecipientContext(
                    username, dev["device_id"], pub, owner_user, owner_dev, clean_srv
                )
                try:
                    if recipient_is_verified(state, ctx):
                        verified_ids.append(dev["device_id"])
                except Exception:
                    continue

        if preferred and preferred in verified_ids:
            return preferred
        if verified_ids:
            return verified_ids[-1]
        if preferred:
            return preferred
        return valid_devices[-1]["device_id"]

    def _persist_preferred_contact_device(self, username: str, device_id: str) -> bool:
        ally_data = state.allies.get(username)
        if not isinstance(ally_data, dict):
            return False
        devices = ally_data.get("devices")
        if not isinstance(devices, list):
            return False
        chosen = next((d for d in devices if isinstance(d, dict) and d.get("device_id") == device_id), None)
        if chosen is None:
            return False

        owner_user = getattr(state, "username", None)
        owner_dev = getattr(state, "device_id", None)
        srv = getattr(state, "server_url", None)
        chosen_verified = False
        any_verified = False
        if all(isinstance(v, str) and v for v in (owner_user, owner_dev, srv)):
            clean_srv = srv.rstrip("/")
            for dev in devices:
                if not isinstance(dev, dict) or not dev.get("device_id") or not dev.get("public_key"):
                    continue
                ctx = RecipientContext(
                    username, dev["device_id"], dev["public_key"], owner_user, owner_dev, clean_srv
                )
                if recipient_is_verified(state, ctx):
                    any_verified = True
                    if dev["device_id"] == device_id:
                        chosen_verified = True

        # Never overwrite a verified preferred target on disk with an unverified device.
        if any_verified and not chosen_verified:
            return False

        had_prev = "preferred_device_id" in ally_data
        prev_val = ally_data.get("preferred_device_id")
        if prev_val == device_id:
            return True
        ally_data["preferred_device_id"] = device_id
        try:
            self._save_allies_to_storage()
            return True
        except Exception:
            if had_prev:
                ally_data["preferred_device_id"] = prev_val
            else:
                ally_data.pop("preferred_device_id", None)
            return False

    def _update_contact_identity_status(self):
        if state.current_chat_type != "ally" or not state.current_chat_username:
            self.identity_status.setVisible(False)
            return
        name = state.current_chat_username
        devices = state.allies.get(name, {}).get("devices", [])
        verified = 0
        active_id = getattr(state, "current_chat_device_id", None)
        active_name = None
        active_verified = False
        active_context = None
        srv = (getattr(state, "server_url", "") or "").rstrip("/")
        for device in devices:
            dev_id = device.get("device_id")
            context = RecipientContext(name, dev_id, device.get("public_key"),
                                       state.username, state.device_id, srv)
            is_ver = recipient_is_verified(state, context)
            if is_ver:
                verified += 1
            if (active_id and dev_id == active_id) or (not active_id and active_context is None and is_ver):
                active_name = device.get("device_name") or dev_id
                active_verified = is_ver
                active_context = context
        status_text = f"Устройства проверены: {verified}/{len(devices)}"
        if len(devices) > 1 and active_name:
            badge = "проверено" if active_verified else "не проверено"
            status_text = f"{status_text} • Активно: {active_name} ({badge})"
        if active_verified and active_context is not None:
            try:
                from app.double_ratchet import RatchetStore
                if RatchetStore(state.username).has_active_session(active_context.device_id, active_context.public_key):
                    status_text = f"{status_text} • X3DH + Double Ratchet"
                elif hasattr(self, "_ensure_peer_ratchet_session"):
                    self._ensure_peer_ratchet_session(active_context)
            except Exception:
                pass
        self.identity_status.setText(status_text)
        self.identity_status.setVisible(True)

    def _on_group_selected(self, item):
        group_id = item.data(Qt.UserRole)
        group_data = state.groups.get(group_id)
        if not group_data:
            return

        state.current_chat_type = "group"
        state.current_group_id = group_id
        state.current_chat_username = None
        state.current_chat_device_id = None

        card = self.groups_list.itemWidget(item)
        if isinstance(card, GroupCardWidget):
            card.reset_unread()

        is_archived = bool(group_data.get("archived"))
        self.chat_title.setText(group_data["name"] + (" (неактивна)" if is_archived else ""))
        self.identity_status.setVisible(False)
        self._set_chat_header_icon("group")
        self.call_btn.setVisible(False)
        if hasattr(self, "group_voice_btn"):
            self.group_voice_btn.setVisible(not is_archived)
        self.search_btn.setVisible(True)
        self.chat_menu_btn.setVisible(True)
        self.right_stack.setCurrentWidget(self.chat_area)
        if not is_archived and hasattr(self, "_fetch_group_voice_state"):
            self._fetch_group_voice_state(group_id)
        if hasattr(self, "_refresh_group_voice_bar"):
            self._refresh_group_voice_bar()
        self.msg_input.setEnabled(not is_archived)
        # Group v2 supports E2EE text, images, documents, and voice messages.
        self.attach_btn.setEnabled(GROUP_CHAT_SEND_ENABLED and not is_archived)
        self.mic_input_btn.setEnabled(GROUP_CHAT_SEND_ENABLED and not is_archived)
        self.send_btn.setEnabled(GROUP_CHAT_SEND_ENABLED and not is_archived)
        if is_archived:
            self.msg_input.setPlaceholderText("Группа неактивна — доступна только локальная история")
        elif GROUP_CHAT_SEND_ENABLED:
            self.ensure_my_group_sender_key(group_id)
            self.msg_input.setPlaceholderText(f"Сообщение в {group_data['name']} (E2EE)...")
        else:
            self.msg_input.setPlaceholderText("Групповая отправка временно недоступна")
        if not is_archived:
            self.msg_input.setFocus()
        self._history_offset = 0
        self._history_query = None
        self._render_history_page()

    def _on_ally_selected(self, item):
        selected_username = item.data(Qt.UserRole)
        ally_data = state.allies.get(selected_username)
        if not ally_data:
            return
        card = self.allies_list.itemWidget(item)
        target_device_id = self._resolve_preferred_contact_device_id(selected_username, ally_data)
        has_target = target_device_id is not None
        state.current_chat_type      = "ally"
        state.current_group_id       = None
        state.current_chat_username  = selected_username
        state.current_chat_device_id = target_device_id

        self.chat_title.setText(f"@{selected_username}")
        self._update_contact_identity_status()
        self._set_chat_header_icon("ally")
        self.call_btn.setVisible(has_target)
        if hasattr(self, "group_voice_btn"):
            self.group_voice_btn.setVisible(False)
        self.search_btn.setVisible(True)
        self.chat_menu_btn.setVisible(True)
        self.right_stack.setCurrentWidget(self.chat_area)
        if hasattr(self, "_refresh_group_voice_bar"):
            self._refresh_group_voice_bar()
        self.msg_input.setEnabled(has_target)
        self.attach_btn.setEnabled(has_target)
        self.mic_input_btn.setEnabled(has_target)
        self.send_btn.setEnabled(has_target)
        if has_target:
            self.msg_input.setPlaceholderText(f"Сообщение для {selected_username}...")
            self.msg_input.setFocus()
        else:
            self.msg_input.setPlaceholderText("У собеседника нет доступных устройств")
        self._history_offset = 0
        self._history_query = None
        self._render_history_page()

    def open_chat_by_username(self, username: str):
        item = self._get_ally_item(username)
        if item:
            self._on_ally_selected(item)
            self.allies_list.setCurrentItem(item)

    def clear_messages(self):
        self._media_queue.reset()
        self._stop_voice_playback()
        for i in reversed(range(self.messages_layout.count() - 1)):
            item = self.messages_layout.itemAt(i)
            if item.widget():
                widget = item.widget()
                widget.setParent(None)
                widget.deleteLater()

    def _update_history_navigation(self):
        end = max(0, self._history_total - self._history_offset)
        start = max(0, end - PAGE_SIZE)
        self.history_range.setText(f"{start + 1 if end else 0}–{end} из {self._history_total}")
        self.history_older.setEnabled(start > 0)
        self.history_newer.setEnabled(self._history_offset > 0)
        self.history_nav.setVisible(self._history_total > PAGE_SIZE or self._history_offset > 0)

    def _change_history_page(self, delta):
        if not self._history_available:
            return
        self._history_offset = max(0, self._history_offset + delta)
        self._render_history_page()

    def _render_history_page(self, *, _page=None, _context=None, _revision=None, _target=None):
        if state.current_chat_type == "group" and state.current_group_id:
            chat_key = f"group_{state.current_group_id}"
        elif state.current_chat_type == "ally" and state.current_chat_username:
            chat_key = state.current_chat_username
        else:
            return
        context = (state.username, state.server_url, state.device_id, state.token,
                   state.current_chat_type, state.current_chat_username, state.current_group_id,
                   self._history_offset, self._history_query)
        if _context is not None and context != _context:
            return
        try:
            background = (_page is None and getattr(storage, "history_background_enabled", lambda *args: False)(state.username, chat_key))
        except Exception:
            background = False  # The normal load below will report the error.
        if background:
            self.clear_messages()
            self._history_available = False
            self.history_nav.setVisible(False)
            self._history_serial += 1
            request = (self._history_serial, context, chat_key)
            if self._history_worker is not None:
                self._history_pending = request
                self._history_worker.cancel()
            else:
                self._start_history_worker(request)
            return
        self.clear_messages()
        self._history_available = False
        self.history_nav.setVisible(False)
        try:
            page = _page if _page is not None else storage.load_history_page(
                state.username, chat_key, self._history_offset, query=self._history_query)
        except Exception as exc:
            current = (state.username, state.server_url, state.device_id, state.token,
                       state.current_chat_type, state.current_chat_username, state.current_group_id,
                       self._history_offset, self._history_query)
            if current != context:
                return
            # Never present an inaccessible encrypted history as an empty chat.
            print(f"[HISTORY] Не удалось открыть историю: {type(exc).__name__}")
            label = QLabel("История недоступна. Проверьте хранилище и системный keyring; файлы не удалены.")
            label.setWordWrap(True)
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, label)
            return
        current = (state.username, state.server_url, state.device_id, state.token,
                   state.current_chat_type, state.current_chat_username, state.current_group_id,
                   self._history_offset, self._history_query)
        if current != context:
            return
        self._history_offset = page.offset
        self._history_total = page.total
        self._history_available = True
        self._update_history_navigation()

        try:
            if self._history_query is not None:
                pending_msg_ids, _ = self._pending_outgoing_snapshot()
                for msg in page.messages:
                    bubble = MessageBubble(text=searchable_text(msg), is_mine=msg.get("is_mine", False),
                                           timestamp=msg.get("timestamp"), is_read=msg.get("is_read", False))
                    bubble.msg_id = msg.get("msg_id")
                    if bubble.is_mine and bubble.msg_id in pending_msg_ids and hasattr(bubble, "set_pending"):
                        bubble.set_pending()
                    self._connect_bubble_signals(bubble, chat_key)
                    self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)
                if not page.messages:
                    label = QLabel("По запросу ничего не найдено")
                    label.setAlignment(Qt.AlignCenter)
                    self.messages_layout.insertWidget(self.messages_layout.count() - 1, label)
            elif state.current_chat_type == "group":
                self._load_group_message_history(state.current_group_id, page.messages)
            else:
                self._load_message_history(chat_key, page.messages)
            if hasattr(self, "_refresh_pinned_banner"):
                self._refresh_pinned_banner()

        except Exception as exc:
            print(f"[HISTORY] Не удалось показать историю: {type(exc).__name__}")
            self.clear_messages()
            self._history_available = False
            self.history_nav.setVisible(False)
            label = QLabel("Не удалось отобразить историю. Файлы не удалены.")
            label.setWordWrap(True)
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, label)
            return

        # Only acknowledge incoming messages that are actually displayed, and
        # only after persisting the read state. Searching does not mark them read.
        if state.current_chat_type == "ally":
            unread_count = page.unread
            visible = [m for m in page.messages if m.get("is_mine") is False and not m.get("is_read") and m.get("msg_id")]
            ids = ([m["msg_id"] for m in visible] if self._history_query is None
                   and self.window().isActiveWindow() and self.isVisible()
                   and self.right_stack.currentWidget() is self.chat_area else [])
            if ids:
                read_context = (state.username, state.server_url, state.device_id, state.token,
                                state.current_chat_type, state.current_chat_username, state.current_group_id,
                                self._history_offset, self._history_query)
                try:
                    if _revision is None:
                        changed = storage.mark_messages_as_read(state.username, chat_key, ids)
                    else:
                        changed = storage.mark_messages_as_read_if_revision(state.username, chat_key, ids, _revision)
                        if changed is None:
                            if _target is None:
                                self._render_history_page()
                            else:
                                self._request_history_target(_target)
                            return
                except Exception as exc:
                    print(f"[HISTORY] Не удалось отметить прочтение: {type(exc).__name__}")
                    QMessageBox.warning(self, "История недоступна", "Не удалось подтвердить сохранение отметок о прочтении. Проверьте хранилище.")
                    changed = False
                current = (state.username, state.server_url, state.device_id, state.token,
                           state.current_chat_type, state.current_chat_username, state.current_group_id,
                           self._history_offset, self._history_query)
                if current != read_context or not self._history_available:
                    return
                if changed:
                    unread_count = max(0, unread_count - len(ids))
                    for msg in visible:
                        msg["is_read"] = True
                    # The bubbles were created before the storage update. Keep
                    # their in-memory flags consistent without recreating media.
                    marked = set(ids)
                    for i in range(self.messages_layout.count() - 1):
                        widget = self.messages_layout.itemAt(i).widget()
                        if (widget and getattr(widget, "is_mine", None) is False
                                and getattr(widget, "msg_id", None) in marked):
                            widget.is_read = True
                    try:
                        self._send_system_payload(chat_key, {"type": "read_ack", "msg_ids": ids})
                    except Exception as exc:
                        # Read state is already persisted; do not claim otherwise.
                        print(f"[HISTORY] Не удалось отправить подтверждение прочтения: {type(exc).__name__}")
            card = self._get_ally_card(chat_key)
            if card:
                card.unread_count = unread_count
                card.badge.setText(str(card.unread_count))
                card.badge.setVisible(card.unread_count > 0)


    def _start_history_worker(self, request):
        serial, context, chat_key = request[:3]
        target = request[3] if len(request) > 3 else None
        if target is None:
            load_fn = storage.load_history_page_background
        else:
            def load_fn(owner, chat, offset, *, page_size, query, cancel):
                return storage.load_history_page_background(owner, chat, offset, page_size=page_size,
                                                            query=query, cancel=cancel, target_id=target)
        worker = HistoryPageWorker(context[0], chat_key, context[7], query=context[8],
                                   load_fn=load_fn)
        worker.history_request = request
        self._history_worker = worker
        worker.finished.connect(lambda w=worker: self._on_history_worker_finished(w), Qt.QueuedConnection)
        worker.start()

    def _on_history_worker_finished(self, worker):
        worker.wait()
        if worker is not self._history_worker:
            return
        self._history_worker = None
        pending, self._history_pending = self._history_pending, None
        current = (state.username, state.server_url, state.device_id, state.token,
                   state.current_chat_type, state.current_chat_username, state.current_group_id,
                   self._history_offset, self._history_query)
        if pending is not None:
            if pending[1] == current:
                self._start_history_worker(pending)
            return
        serial, context, chat_key = worker.history_request[:3]
        target = worker.history_request[3] if len(worker.history_request) > 3 else None
        if context != current or serial != self._history_serial:
            return
        status, result = worker.result or ("error", "NoResult")
        if status == "cancelled" and target is not None:
            return
        if status == "cancelled":
            label = QLabel("Чтение истории отменено. Откройте чат снова, чтобы повторить.")
            label.setWordWrap(True)
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, label)
            return
        if status == "error" and result == "HistoryStale":
            QTimer.singleShot(100, lambda: self._retry_history_scan(serial, context, target))
            return
        if status != "ok" and target is not None:
            QMessageBox.information(self, "Сообщение недоступно", "Не удалось найти сообщение в истории.")
            return
        if status != "ok":
            print(f"[HISTORY] Не удалось открыть историю: {result}")
            label = QLabel("История недоступна. Проверьте хранилище и системный keyring; файлы не удалены.")
            label.setWordWrap(True)
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, label)
            return
        page, revision = result
        if storage.history_revision(context[0]) != revision or revision[1]:
            QTimer.singleShot(100, lambda: self._retry_history_scan(serial, context, target))
            return
        if target is not None:
            if page is None:
                QMessageBox.information(self, "Сообщение недоступно", "Не удалось найти сообщение в истории.")
                return
            self._history_offset = page.offset
            self._history_query = None
            context = (state.username, state.server_url, state.device_id, state.token,
                       state.current_chat_type, state.current_chat_username, state.current_group_id,
                       self._history_offset, self._history_query)
            self._history_reveal_callback = lambda: self._reveal_history_message(target, context)
        self._render_history_page(_page=page, _context=context, _revision=revision, _target=target)
        if self._history_worker is None and self._history_available:
            callback, self._history_reveal_callback = self._history_reveal_callback, None
            if callback is not None:
                QTimer.singleShot(0, callback)

    def _retry_history_scan(self, serial, context, target=None):
        current = (state.username, state.server_url, state.device_id, state.token,
                   state.current_chat_type, state.current_chat_username, state.current_group_id,
                   self._history_offset, self._history_query)
        if (serial == self._history_serial and context == current
                and self._history_worker is None):
            if target is None:
                self._render_history_page()
            else:
                self._request_history_target(target)

    def _mark_visible_history_read(self):
        """On window activation, mark the current page without rebuilding it."""
        if (not self.window().isActiveWindow() or not self._history_available
                or self._history_query is not None or state.current_chat_type != "ally"
                or not state.current_chat_username or self.right_stack.currentWidget() is not self.chat_area):
            return
        context = (state.username, state.server_url, state.device_id, state.token,
                   state.current_chat_type, state.current_chat_username, state.current_group_id,
                   self._history_offset, self._history_query)
        widgets = []
        for i in range(self.messages_layout.count() - 1):
            widget = self.messages_layout.itemAt(i).widget()
            if (widget and getattr(widget, "is_mine", None) is False
                    and not getattr(widget, "is_read", True)
                    and isinstance(getattr(widget, "msg_id", None), str) and widget.msg_id):
                widgets.append(widget)
        ids = list(dict.fromkeys(widget.msg_id for widget in widgets))
        if not ids:
            return
        try:
            changed = storage.mark_messages_as_read(context[0], context[5], ids)
        except Exception as exc:
            print(f"[HISTORY] Не удалось отметить прочтение: {type(exc).__name__}")
            QMessageBox.warning(self, "История недоступна", "Не удалось подтвердить сохранение отметок о прочтении. Проверьте хранилище.")
            return
        # The write can block or open a keyring prompt. Do not touch a new
        # account, chat or replacement page after control returns.
        current = (state.username, state.server_url, state.device_id, state.token,
                   state.current_chat_type, state.current_chat_username, state.current_group_id,
                   self._history_offset, self._history_query)
        if (not changed or context != current or not self._history_available
                or not self.window().isActiveWindow() or self.right_stack.currentWidget() is not self.chat_area):
            return
        current_widgets = [self.messages_layout.itemAt(i).widget()
                           for i in range(self.messages_layout.count() - 1)]
        if not all(any(widget is current_widget for current_widget in current_widgets) for widget in widgets):
            return
        for widget in widgets:
            widget.is_read = True
        card = self._get_ally_card(context[5])
        if card:
            card.unread_count = max(0, card.unread_count - len(ids))
            card.badge.setText(str(card.unread_count))
            card.badge.setVisible(card.unread_count > 0)
        try:
            self._send_system_payload(context[5], {"type": "read_ack", "msg_ids": ids})
        except Exception as exc:
            print(f"[HISTORY] Не удалось отправить подтверждение прочтения: {type(exc).__name__}")

    def _trim_live_history(self):
        while self.messages_layout.count() - 1 > PAGE_SIZE:
            widget = self.messages_layout.itemAt(0).widget()
            if not widget:
                break
            if widget is self._current_playing_bubble:
                self._stop_voice_playback()
            widget.setParent(None)
            widget.deleteLater()
        self._update_history_navigation()

    def _return_to_latest_for_send(self):
        if self._history_offset or self._history_query is not None or not self._history_available:
            self._history_offset = 0
            self._history_query = None
            self._render_history_page()
            return True
        return False

    def _pending_outgoing_snapshot(self):
        username = getattr(state, "username", None)
        server_url = getattr(state, "server_url", None)
        device_id = getattr(state, "device_id", None)
        if not username or not server_url or not device_id:
            return set(), set()
        try:
            queued_msgs = outbox.pending_local_msg_ids(username, server_url, device_id)
        except Exception:
            queued_msgs = set()
        try:
            attach_msgs, attach_files = attachment_outbox.pending_local_index(
                username, server_url, device_id
            )
        except Exception:
            attach_msgs, attach_files = set(), {}
        return queued_msgs | attach_msgs, set(attach_files.keys())

    def _load_message_history(self, ally_username: str, messages):
        pending_msg_ids, pending_attachment_ids = self._pending_outgoing_snapshot()

        for msg in messages:
            raw_text = msg.get("text", "")
            is_mine = msg.get("is_mine", False)
            msg_id = msg.get("msg_id")
            is_read = msg.get("is_read", False)
            reply_to_text = msg.get("reply_to_text")
            reply_to_sender = msg.get("reply_to_sender")
            reply_to_msg_id = msg.get("reply_to_msg_id")
            is_pending_local = bool(is_mine and msg_id and msg_id in pending_msg_ids)

            # ── Голосовое ─────────────────────────────────────────────
            if raw_text.startswith("[VOICE_META]|"):
                parts = raw_text.split("|")
                if len(parts) >= 4:
                    file_id, secret_key, duration_str = parts[1], parts[2], parts[3]

                    try:
                        duration = float(duration_str)
                        if not math.isfinite(duration) or not 0 <= duration <= 86400:
                            raise ValueError("invalid duration")
                        duration = max(duration, 0.1)
                    except (ValueError, OverflowError):
                        duration = 0.1

                    bubble = MessageBubble(
                        "",
                        is_mine=is_mine,
                        timestamp=msg.get("timestamp"),
                        is_read=is_read,
                        voice_duration=duration,
                        reply_to_text=reply_to_text,
                        reply_to_sender=reply_to_sender,
                        reply_to_msg_id=reply_to_msg_id,
                    )
                    bubble.msg_id = msg_id
                    if is_pending_local and hasattr(bubble, "set_pending"):
                        bubble.set_pending("В очереди: загрузка или отправка ещё не подтверждена")

                    if reply_to_msg_id:
                        bubble.set_reply_to_msg_id(reply_to_msg_id)

                    self._connect_bubble_signals(bubble, ally_username)
                    self.messages_layout.insertWidget(
                        self.messages_layout.count() - 1,
                        bubble
                    )

                    self._prepare_voice_bubble(bubble, file_id, secret_key, msg_id)
                    continue

            # ── Картинка ──────────────────────────────────────────────
            if raw_text.startswith("[IMAGE_META]|"):
                parts = raw_text.split("|", 3)
                if len(parts) >= 3:
                    file_id = parts[1]
                    secret_key = parts[2]
                    saved_caption = parts[3] if len(parts) >= 4 else ""

                    bubble = MessageBubble(
                        "",
                        is_mine=is_mine,
                        timestamp=msg.get("timestamp"),
                        is_read=is_read,
                        reply_to_text=reply_to_text,
                        reply_to_sender=reply_to_sender,
                        reply_to_msg_id=reply_to_msg_id,
                        caption=saved_caption,
                    )
                    bubble.show_skeleton()
                    bubble.msg_id = msg_id
                    if is_pending_local and hasattr(bubble, "set_pending"):
                        bubble.set_pending("В очереди: загрузка или отправка ещё не подтверждена")

                    if reply_to_msg_id:
                        bubble.set_reply_to_msg_id(reply_to_msg_id)

                    self._connect_bubble_signals(bubble, ally_username)
                    self.messages_layout.insertWidget(
                        self.messages_layout.count() - 1,
                        bubble
                    )

                    cache_key = self._media_asset_key(file_id, secret_key)
                    if cache_key in self._image_cache:
                        bubble.set_image(
                            self._image_cache[cache_key],
                            caption=saved_caption
                        )
                    elif is_mine and file_id in pending_attachment_ids:
                        local_bytes = attachment_outbox.load_pending_plaintext(
                            getattr(state, "username", None),
                            getattr(state, "server_url", None),
                            getattr(state, "device_id", None),
                            file_id,
                            secret_key,
                        )
                        if local_bytes is not None:
                            self._image_cache[cache_key] = local_bytes
                            bubble.set_image(local_bytes, caption=saved_caption)
                        else:
                            worker = DownloadFileWorker(
                                state.server_url,
                                state.token,
                                file_id
                            )
                            worker.secret_key = secret_key
                            worker.bubble = bubble
                            worker.file_id_cache = cache_key
                            worker.caption = saved_caption
                            worker.finished.connect(
                                lambda w=worker:
                                self._on_download_finished(*w.result, w),
                                Qt.QueuedConnection
                            )
                            self._queue_media_download(worker)
                    else:
                        worker = DownloadFileWorker(
                            state.server_url,
                            state.token,
                            file_id
                        )
                        worker.secret_key = secret_key
                        worker.bubble = bubble
                        worker.file_id_cache = cache_key
                        worker.caption = saved_caption

                        worker.finished.connect(
                            lambda w=worker:
                            self._on_download_finished(*w.result, w),
                            Qt.QueuedConnection
                        )

                        self._queue_media_download(worker)
                    continue

            # ── Рабочий файл / Документ ──────────────────────────────
            if raw_text.startswith("[FILE_META]|"):
                from app.media_identity import parse_file_meta
                fmeta = parse_file_meta(raw_text)
                if fmeta is not None:
                    bubble = MessageBubble(
                        "",
                        is_mine=is_mine,
                        timestamp=msg.get("timestamp"),
                        is_read=is_read,
                        reply_to_text=reply_to_text,
                        reply_to_sender=reply_to_sender,
                        reply_to_msg_id=reply_to_msg_id,
                    )
                    bubble.msg_id = msg_id
                    if not is_mine and msg.get("sender_name"):
                        bubble.set_sender(msg["sender_name"])
                    bubble.set_document(
                        fmeta["file_id"],
                        fmeta["secret_key"],
                        fmeta["filename"],
                        fmeta["size_bytes"],
                        caption=fmeta["caption"],
                    )
                    if is_pending_local and hasattr(bubble, "set_pending"):
                        bubble.set_pending("В очереди: загрузка или отправка ещё не подтверждена")
                    if reply_to_msg_id:
                        bubble.set_reply_to_msg_id(reply_to_msg_id)
                    self._connect_bubble_signals(bubble, msg.get("sender_name") or ally_username)
                    self.messages_layout.insertWidget(
                        self.messages_layout.count() - 1,
                        bubble
                    )
                    continue

            # ── Обычный текст ────────────────────────────────────────
            bubble = MessageBubble(
                text=raw_text,
                is_mine=is_mine,
                timestamp=msg.get("timestamp"),
                is_read=is_read,
                reply_to_text=reply_to_text,
                reply_to_sender=reply_to_sender,
                reply_to_msg_id=reply_to_msg_id,
            )
            bubble.msg_id = msg_id
            if msg.get("edited") and hasattr(bubble, "set_edited_text"):
                bubble.set_edited_text(raw_text)
            if is_pending_local and hasattr(bubble, "set_pending"):
                bubble.set_pending()

            if reply_to_msg_id:
                bubble.set_reply_to_msg_id(reply_to_msg_id)

            sender_lbl = msg.get("sender_name") if (not is_mine and msg.get("sender_name")) else ally_username
            self._connect_bubble_signals(bubble, sender_lbl)
            self.messages_layout.insertWidget(
                self.messages_layout.count() - 1,
                bubble
            )

        if messages:
            QTimer.singleShot(
                50,
                lambda: self.messages_scroll.verticalScrollBar().setValue(
                    self.messages_scroll.verticalScrollBar().maximum()
                )
            )

    def _on_send_message(self):
        text = self.msg_input.toPlainText().strip()
        if not text:
            return
        if getattr(self, "_editing_msg_id", None):
            self._submit_message_edit(text)
            return
        if getattr(state, "current_chat_type", "ally") == "group":
            self._send_group_text_message(text)
        else:
            self._send_ally_text_message(text)

    def _send_ally_text_message(self, text: str):
        if len(text) > 512 * 1024 or len(text.encode("utf-8")) > 512 * 1024:
            QMessageBox.warning(self, "Сообщение слишком большое", "Максимум 512 KiB текста.")
            return
        try:
            context = capture_recipient(state)
        except ValueError as e:
            QMessageBox.warning(self, "Сообщение не отправлено", str(e))
            return
        if not self._verify_call_contact(context.username, context.device_id):
            return
        # The verification dialog runs an event loop; never send if its chat,
        # account or key changed while the user was checking the fingerprint.
        if not is_active_recipient(state, context):
            QMessageBox.warning(self, "Отправка отменена", "Чат или ключ контакта изменился во время проверки.")
            return
        msg_id = f"msg_{uuid.uuid4().hex}"
        payload = {"type": "text", "text": text, "msg_id": msg_id}
        history = {
            "ally_username": context.username, "text": text, "msg_id": msg_id,
            "timestamp": datetime.now().isoformat(),
            "reply_to_msg_id": self._reply_to_msg_id,
            "reply_to_text": self._reply_to_text,
            "reply_to_sender": self._reply_to_sender,
        }
        _ttl_fn = getattr(globals().get("storage"), "get_chat_ttl", None)
        _ttl_val = _ttl_fn(context.owner_username, context.username) if callable(_ttl_fn) else None
        _save_ttl_kw = {}
        if isinstance(_ttl_val, int) and not isinstance(_ttl_val, bool) and _ttl_val >= 5:
            import time as _time
            _exp_ts = int(_time.time() + _ttl_val)
            payload["ttl_seconds"] = _ttl_val
            history["expires_at"] = _exp_ts
            _save_ttl_kw["expires_at"] = _exp_ts
        if self._reply_to_msg_id:
            payload["reply_to"] = {"msg_id": self._reply_to_msg_id,
                                   "text": self._reply_to_text, "sender": self._reply_to_sender}
        if not self._send_system_payload(context.username, payload, context, history):
            return
        # After a successful queue write, the text is recoverable even if
        # writing chat history fails or the process terminates immediately.
        self.msg_input.clear()
        try:
            storage.save_message(
                context.owner_username, context.username, text, is_mine=True,
                timestamp=history["timestamp"], msg_id=msg_id, is_read=False,
                reply_to_msg_id=history["reply_to_msg_id"],
                reply_to_text=history["reply_to_text"], reply_to_sender=history["reply_to_sender"],
                **_save_ttl_kw,
            )
        except Exception:
            QMessageBox.warning(self, "Сообщение в очереди", "Сообщение сохранено в очередь, но историю не удалось обновить. Отправка повторится после восстановления хранилища.")
            return

        if not is_active_recipient(state, context):
            self._cancel_reply()
            return
        if self._return_to_latest_for_send():
            card = self._get_ally_card(context.username)
            if card:
                card.update_preview(text)
            self._cancel_reply()
            self.msg_input.setFocus()
            return
        bubble = MessageBubble(text, is_mine=True, is_read=False,
                               reply_to_text=self._reply_to_text,
                               reply_to_sender=self._reply_to_sender,
                               reply_to_msg_id=self._reply_to_msg_id)
        bubble.msg_id = msg_id
        pending_msg_ids, _ = self._pending_outgoing_snapshot()
        if msg_id in pending_msg_ids and hasattr(bubble, "set_pending"):
            bubble.set_pending()
        self._connect_bubble_signals(bubble, state.username)
        self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)
        QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
            self.messages_scroll.verticalScrollBar().maximum()))
        card = self._get_ally_card(context.username)
        if card:
            card.update_preview(text)
        ally_item = self._get_ally_item(context.username)
        if ally_item:
            ally_item.last_activity = time.time()
            self.allies_list.sortItems(Qt.DescendingOrder)
        self._history_total += 1
        self._trim_live_history()
        self._cancel_reply()
        self.msg_input.setFocus()

    def _save_group_keys_safe(self):
        if not state.username:
            return
        save_fn = getattr(storage, "save_group_keys", None)
        if callable(save_fn):
            try:
                save_fn(state.username, state.groups)
            except Exception as exc:
                print(f"[GROUP] Не удалось сохранить ключи групп: {type(exc).__name__}")

    def restore_persisted_group_keys(self):
        if not state.username:
            return
        load_fn = getattr(storage, "load_group_keys", None)
        if not callable(load_fn):
            return
        try:
            persisted = load_fn(state.username)
        except Exception as exc:
            print(f"[GROUP] Не удалось загрузить ключи групп: {type(exc).__name__}")
            return
        for gid, gstate in persisted.items():
            if gid not in state.groups or state.groups[gid].get("archived"):
                continue
            target = state.groups[gid]
            srv_epoch = int(target.get("epoch", 1) or 1)
            loc_epoch = int(gstate.get("epoch", 1) or 1)
            target["epoch"] = max(srv_epoch, loc_epoch)
            if isinstance(gstate.get("sender_keys"), dict):
                for sdev, kmap in gstate["sender_keys"].items():
                    if isinstance(kmap, dict):
                        if "key_id" in kmap:
                            store_member_sender_key(target, sdev, kmap)
                        else:
                            for _kid, sk_obj in kmap.items():
                                if isinstance(sk_obj, dict) and "key_id" in sk_obj:
                                    store_member_sender_key(target, sdev, sk_obj)
            my_sk = gstate.get("my_sender_key")
            if isinstance(my_sk, dict) and int(my_sk.get("epoch", 0) or 0) == target["epoch"]:
                target["my_sender_key"] = my_sk
                target["distributed_epoch"] = int(gstate.get("distributed_epoch", 0) or 0)

    def _resolve_group_member_pub_and_name(self, group_id: str, device_id: str):
        """Return (public_key, sender_label) for a group member device, failing closed
        if a pinned contact device has a conflicting or ambiguous key."""
        ally_matches = []
        for uname, info in state.allies.items():
            for dev in info.get("devices", []):
                if dev.get("device_id") == device_id:
                    ally_matches.append((uname, dev))
        if len(ally_matches) > 1:
            return None, ""
        group_data = state.groups.get(group_id) or {}
        member_pub = None
        member_label = ""
        for m in group_data.get("members", []):
            if isinstance(m, dict) and m.get("device_id") == device_id:
                member_pub = m.get("public_key")
                member_label = m.get("device_name") or device_id[:8]
                break
        if len(ally_matches) == 1:
            uname, dev = ally_matches[0]
            pinned_pub = dev.get("public_key")
            if not pinned_pub:
                return None, f"@{uname}"
            if member_pub and member_pub != pinned_pub:
                # Server reported a different key than our local pinned trust store -> fail closed!
                return None, f"@{uname}"
            return pinned_pub, f"@{uname}"
        return member_pub, member_label

    def ensure_my_group_sender_key(
        self,
        group_id: str,
        *,
        force_rotate: bool = False,
        target_epoch: int = None,
    ) -> bool:
        group_data = state.groups.get(group_id)
        if not group_data or group_data.get("archived") or not state.token:
            return False

        epoch = max(1, int(target_epoch or group_data.get("epoch", 1) or 1))
        group_data["epoch"] = epoch
        my_sk = group_data.get("my_sender_key")
        need_new = (
            force_rotate
            or not isinstance(my_sk, dict)
            or int(my_sk.get("epoch", 0) or 0) != epoch
            or my_sk.get("group_id") not in ("", group_id)
        )
        if need_new:
            my_sk = group_crypto.generate_sender_key(group_id=group_id, epoch=epoch)
            group_data["my_sender_key"] = my_sk
            group_data["distributed_epoch"] = 0
            self._save_group_keys_safe()
        else:
            my_sk["group_id"] = group_id

        if int(group_data.get("distributed_epoch", 0) or 0) >= epoch and not force_rotate:
            return True

        members = group_data.get("members") or []
        other_devs = []
        for m in members:
            dev_id = m.get("device_id") if isinstance(m, dict) else (m if isinstance(m, str) else None)
            if dev_id and dev_id != state.device_id:
                other_devs.append(dev_id)

        if not other_devs:
            group_data["distributed_epoch"] = epoch
            self._save_group_keys_safe()
            return True

        entries = []
        for dev_id in other_devs:
            pub_key, _label = self._resolve_group_member_pub_and_name(group_id, dev_id)
            if not pub_key:
                # Member list lacks public_keys (e.g. WS event had IDs only) -> fetch full member info first.
                self._fetch_group_members_and_rotate(group_id, force_rotate=force_rotate, target_epoch=epoch)
                return False
            enc_blob, sig = group_crypto.encrypt_sender_key_for_member(
                my_sk,
                pub_key,
                group_id=group_id,
                sender_device_id=state.device_id,
                recipient_device_id=dev_id,
                group_name=group_data.get("name", ""),
            )
            entries.append(
                {
                    "sender_device_id": state.device_id,
                    "recipient_device_id": dev_id,
                    "encrypted_sender_key": enc_blob,
                    "sender_key_signature": sig,
                }
            )

        req_ctx = (state.username, state.server_url, state.device_id, state.token)
        worker = DistributeGroupSenderKeyWorker(
            state.server_url,
            state.token,
            group_id,
            {"epoch": epoch, "sender_keys": entries},
        )
        worker.account_context = req_ctx
        worker.distributed_epoch = epoch
        worker.finished.connect(
            lambda ok, res, gid, w=worker: self._on_group_key_distributed(ok, res, gid, w),
            Qt.QueuedConnection,
        )
        self._net_workers.append(worker)
        worker.start()
        return True

    def _fetch_group_members_and_rotate(
        self, group_id: str, *, force_rotate: bool = False, target_epoch: int = None
    ):
        if not state.token:
            return
        req_ctx = (state.username, state.server_url, state.device_id, state.token)
        worker = FetchGroupMembersWorker(state.server_url, state.token, group_id)
        worker.account_context = req_ctx
        worker._force_rotate = force_rotate
        worker._target_epoch = target_epoch
        worker.finished.connect(
            lambda ok, members, gid, w=worker: self._on_group_members_loaded(ok, members, gid, w),
            Qt.QueuedConnection,
        )
        self._net_workers.append(worker)
        worker.start()

    def _on_group_members_loaded(self, success: bool, members, group_id: str, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if getattr(worker, "account_context", None) != (
            state.username, state.server_url, state.device_id, state.token
        ):
            return
        if not success or not isinstance(members, list) or group_id not in state.groups:
            return
        state.groups[group_id]["members"] = members
        self.ensure_my_group_sender_key(
            group_id,
            force_rotate=bool(getattr(worker, "_force_rotate", False)),
            target_epoch=getattr(worker, "_target_epoch", None),
        )
        self._drain_deferred_group_messages(group_id)

    def _on_group_key_distributed(self, success: bool, data, group_id: str, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if getattr(worker, "account_context", None) != (
            state.username, state.server_url, state.device_id, state.token
        ):
            return
        if group_id not in state.groups:
            return
        if success and isinstance(data, dict):
            eff_epoch = int(data.get("epoch", getattr(worker, "distributed_epoch", 1)) or 1)
            state.groups[group_id]["epoch"] = eff_epoch
            state.groups[group_id]["distributed_epoch"] = eff_epoch
            self._save_group_keys_safe()
        elif isinstance(data, str) and "409" in data:
            # Server epoch advanced -> refresh group list & members and rotate to latest epoch.
            win = self.window()
            if hasattr(win, "_refresh_groups_from_server"):
                win._refresh_groups_from_server()

    def _send_group_text_message(self, text: str):
        if not GROUP_CHAT_SEND_ENABLED:
            QMessageBox.warning(
                self, "Групповой чат временно недоступна",
                "Отправка приостановлена."
            )
            return
        group_id = state.current_group_id
        if not group_id:
            return
        group_data = state.groups.get(group_id)
        if not group_data or group_data.get("archived"):
            return

        epoch = int(group_data.get("epoch", 1) or 1)
        my_sender_key = group_data.get("my_sender_key")
        if not isinstance(my_sender_key, dict) or int(my_sender_key.get("epoch", 0) or 0) != epoch:
            if not self.ensure_my_group_sender_key(group_id, target_epoch=epoch):
                QMessageBox.information(
                    self,
                    "Синхронизация ключей группы",
                    "Ключи участников синхронизируются. Повторите отправку через секунду.",
                )
                return
            my_sender_key = group_data.get("my_sender_key")
        elif int(group_data.get("distributed_epoch", 0) or 0) < epoch:
            self.ensure_my_group_sender_key(group_id, target_epoch=epoch)

        _ttl_fn = getattr(globals().get("storage"), "get_chat_ttl", None)
        _ttl_val = _ttl_fn(state.username, f"group_{group_id}") if callable(_ttl_fn) else None
        _enc_ttl_kw = {}
        _save_ttl_kw = {}
        if isinstance(_ttl_val, int) and not isinstance(_ttl_val, bool) and _ttl_val >= 5:
            import time as _time
            _enc_ttl_kw["ttl_seconds"] = _ttl_val
            _save_ttl_kw["expires_at"] = int(_time.time() + _ttl_val)

        msg_id = f"gmsg_{uuid.uuid4().hex[:16]}"
        try:
            enc_result = group_crypto.encrypt_group_message(
                text,
                my_sender_key,
                group_id=group_id,
                sender_device_id=state.device_id,
                msg_id=msg_id,
                **_enc_ttl_kw,
            )
            self._save_group_keys_safe()
        except Exception as e:
            print(f"[GROUP] Ошибка шифрования: {type(e).__name__}")
            QMessageBox.warning(self, "Ошибка шифрования", "Не удалось зашифровать групповое сообщение.")
            return

        self.msg_input.clear()

        bubble = MessageBubble(text, is_mine=True, is_read=False)
        bubble.msg_id = msg_id
        self._connect_bubble_signals(bubble, state.username)
        self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)
        QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
            self.messages_scroll.verticalScrollBar().maximum()
        ))

        storage.save_message(
            state.username, f"group_{group_id}", text,
            is_mine=True, msg_id=msg_id, is_read=True,
            **_save_ttl_kw,
        )

        card = self._get_group_card(group_id)
        if card:
            card.update_preview(text)

        server_payload = {
            "group_id":       group_id,
            "encrypted_blob": enc_result["blob"],
            "signature":      enc_result["signature"],
            "sender_key_id":  enc_result["key_id"],
            "epoch":          enc_result["epoch"],
            "chain_index":    enc_result["chain_index"],
        }
        req_ctx = (state.username, state.server_url, state.device_id, state.token)
        worker = SendGroupMessageWorker(state.server_url, state.token, server_payload)
        worker.account_context = req_ctx
        worker.group_id = group_id
        worker.finished.connect(
            lambda s, d, w=worker: self._on_group_send_finished(s, d, w),
            Qt.QueuedConnection
        )
        self._net_workers.append(worker)
        worker.start()

    def _on_group_send_finished(self, success: bool, data, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if not success:
            print(f"[GROUP] Ошибка отправки: {data}")
            if isinstance(data, str) and "409" in data:
                gid = getattr(worker, "group_id", "")
                if gid:
                    self._fetch_group_members_and_rotate(gid, force_rotate=True)

    def _on_attach_file(self):
        is_group = (state.current_chat_type == "group" and bool(state.current_group_id))
        context = None
        group_id = state.current_group_id if is_group else None
        if not is_group:
            if not state.current_chat_username:
                return
            try:
                context = capture_recipient(state)
            except ValueError as e:
                QMessageBox.warning(self, "Отправка недоступна", str(e))
                return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите файл или изображение (до 20 МБ)",
            "",
            "Все файлы (*.*);;Изображения (*.png *.jpg *.jpeg *.webp);;Документы (*.pdf *.docx *.xlsx *.zip *.txt *.csv)",
        )
        if not file_path:
            return
        self._process_selected_local_file(file_path, context=context, group_id=group_id)

    def _on_image_pasted(self, file_data: bytes):
        if len(file_data) > MAX_IMAGE_FILE_BYTES:
            QMessageBox.warning(self, "Файл слишком большой", "Размер изображения не должен превышать 20 МБ.")
            return
        if state.current_chat_type == "group" and state.current_group_id:
            self._show_image_preview(file_data, context=("group_image", state.current_group_id))
            return
        if not state.current_chat_username:
            return
        self._show_image_preview(file_data)

    def _prepare_file_for_upload(self, file_data: bytes, caption: str = "", context=None):
        if not context or not is_active_recipient(state, context):
            QMessageBox.warning(self, "Отправка отменена", "Чат или ключ контакта изменился. Выберите файл заново.")
            return
        self._queue_attachment(file_data, context, "image", caption=caption)

    def _queue_attachment(self, raw_data, context, kind, caption="", duration=0, filename=""):
        if not is_active_recipient(state, context):
            QMessageBox.warning(self, "Отправка отменена", "Чат или ключ контакта изменился.")
            return
        if not self._verify_call_contact(context.username, context.device_id):
            return
        if not is_active_recipient(state, context):
            QMessageBox.warning(self, "Отправка отменена", "Чат или ключ контакта изменился во время проверки.")
            return
        try:
            file_id, message_id = str(uuid.uuid4()), str(uuid.uuid4())
            msg_id = f"msg_{uuid.uuid4().hex}"
            secret_key = crypto.generate_file_key()
            encrypted_file = crypto.encrypt_file(raw_data, secret_key)
            safe_doc_name = ""
            if kind == "image":
                text = f"[IMAGE_META]|{file_id}|{secret_key}|{caption}"
                message = {"type": kind, "file_id": file_id, "secret_key": secret_key,
                           "caption": caption, "msg_id": msg_id}
            elif kind == "voice":
                text = f"[VOICE_META]|{file_id}|{secret_key}|{duration:.1f}"
                message = {"type": kind, "file_id": file_id, "secret_key": secret_key,
                           "duration": duration, "msg_id": msg_id}
            elif kind == "file":
                from app.media_identity import build_file_meta, sanitize_attachment_filename
                safe_doc_name = sanitize_attachment_filename(filename or "document.bin")
                text = build_file_meta(file_id, secret_key, safe_doc_name, len(raw_data), caption)
                message = {
                    "type": "file",
                    "file_id": file_id,
                    "secret_key": secret_key,
                    "filename": safe_doc_name,
                    "size_bytes": len(raw_data),
                    "caption": caption,
                    "msg_id": msg_id,
                }
            else:
                raise ValueError("Invalid attachment type")
            _ttl_fn = getattr(globals().get("storage"), "get_chat_ttl", None)
            _ttl_val = _ttl_fn(context.owner_username, context.username) if callable(_ttl_fn) else None
            history = {"ally_username": context.username, "text": text, "msg_id": msg_id,
                       "timestamp": datetime.now().isoformat()}
            if isinstance(_ttl_val, int) and not isinstance(_ttl_val, bool) and _ttl_val >= 5:
                import time as _time
                message["ttl_seconds"] = _ttl_val
                history["expires_at"] = int(_time.time() + _ttl_val)
            _enc_att_fn = getattr(self, "_encrypt_attachment_personal", None)
            if callable(_enc_att_fn):
                encrypted_message = _enc_att_fn(context, message, kind, file_id, secret_key, msg_id)
            else:
                encrypted_message = crypto.encrypt_message(json.dumps(message, ensure_ascii=False), context.public_key)
            payload = {"receiver_device_id": context.device_id,
                       "encrypted_blob": encrypted_message["encrypted_blob"],
                       "signature": encrypted_message["signature"]}
            attachment_outbox.enqueue(context, encrypted_file, file_id, message_id, payload, history)
        except Exception as e:
            print(f"[ATTACHMENT] Не удалось создать очередь: {type(e).__name__}")
            QMessageBox.warning(self, "Вложение не отправлено", "Не удалось сохранить вложение в очередь.")
            return
        # The attachment is now durable; never tell the user to resend it on a
        # subsequent history or network error (that would create duplicates).
        try:
            outbox.prepare_network_payload(context.owner_username, {"_local_history": history})
        except Exception:
            QMessageBox.warning(self, "Вложение в очереди", "История временно недоступна; отправка повторится после восстановления хранилища.")
            return
        if is_active_recipient(state, context) and not self._return_to_latest_for_send():
            if kind == "image":
                bubble = MessageBubble("", is_mine=True, is_read=False, caption=caption)
                bubble.set_image(raw_data, caption=caption)
            elif kind == "file":
                bubble = MessageBubble("", is_mine=True, is_read=False, caption=caption)
                bubble.set_document(file_id, secret_key, safe_doc_name, len(raw_data), caption=caption)
            else:
                bubble = MessageBubble("", is_mine=True, is_read=False,
                                       voice_data=raw_data, voice_duration=duration)
            bubble.msg_id = msg_id
            bubble.status_label.setText("⏳")
            bubble.status_label.setToolTip("В очереди: загрузка и отправка ещё не подтверждены")
            self._connect_bubble_signals(bubble, context.owner_username)
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)
            QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
                self.messages_scroll.verticalScrollBar().maximum()))
            self._history_total += 1
            self._trim_live_history()
        card = self._get_ally_card(context.username)
        if card:
            if kind == "file":
                card.update_preview(f"📄 {safe_doc_name}")
            else:
                card.update_preview("Фото" if kind == "image" else "Голосовое")
        self._try_attachment_outbox()

    def _try_attachment_outbox(self):
        if not state.username or not state.device_id or not state.server_url or not state.token:
            return
        if self._attachment_worker is not None or self._outbox_management_active:
            return
        account = (state.username, state.server_url, state.device_id, state.token)
        try:
            now = time.monotonic()
            self._attachment_retry_after = {name: deadline for name, deadline in self._attachment_retry_after.items()
                                             if deadline > now}
            excluded = self._attachment_skipped | set(self._attachment_retry_after)
            item = attachment_outbox.next_job(account[0], account[1], account[2], excluded)
            if item is None:
                self._attachment_skipped.clear()
                return
            if account != (state.username, state.server_url, state.device_id, state.token):
                return
            path, blob_path, job = item
            context = RecipientContext(**job["context"])
            if not recipient_is_verified(state, context):
                raise ValueError("Контакт или учётная запись изменились, либо ключ не проверен")
            envelope = {**job["payload"], "_local_history": job["history"]}
            if verify_queued_recipient(state, crypto, envelope, attachment_file_id=job["file_id"]) != context:
                raise ValueError("Attachment recipient does not match queued envelope")
            outbox.prepare_network_payload(context.owner_username, {"_local_history": job["history"]})
            if account != (state.username, state.server_url, state.device_id, state.token):
                return
            verified, file_key = verify_queued_recipient(state, crypto, envelope,
                attachment_file_id=job["file_id"], return_attachment_key=True)
            if verified != context:
                raise ValueError("Attachment recipient changed during preparation")
            if account != (state.username, state.server_url, state.device_id, state.token):
                return
            worker = ReliableUploadFileWorker(context.server_url, account[3], job["file_id"], blob_path,
                                              job["size"], job["sha256"], file_key)
            worker.recipient_context, worker.queue_item, worker.account_context = context, item, account
            self._attachment_worker = worker
            self._net_workers.append(worker)
            worker.finished.connect(lambda ok, data, w=worker: self._on_queued_upload_finished(ok, data, w),
                                    Qt.QueuedConnection)
            worker.start()
        except outbox.QueueRecordError as e:
            self._attachment_skipped.add(e.path.name)
            self._attachment_retry_after[e.path.name] = time.monotonic() + 300
            if not self._attachment_warning_shown:
                self._attachment_warning_shown = True
                QMessageBox.warning(self, "Ошибка очереди", "Запись вложения не прочитана и осталась в очереди. Остальные будут обработаны; проверьте ключ и резервную копию.")
            QTimer.singleShot(250, self._try_attachment_outbox)
        except Exception as e:
            if 'worker' in locals() and not worker.isRunning():
                if worker in self._net_workers:
                    self._net_workers.remove(worker)
                self._attachment_worker = None
            print(f"[ATTACHMENT] Очередь ожидает: {type(e).__name__}")
            if 'item' in locals() and item is not None:
                self._attachment_skipped.add(item[0].name)
                self._attachment_retry_after[item[0].name] = time.monotonic() + 300
            if not self._attachment_warning_shown:
                self._attachment_warning_shown = True
                QMessageBox.warning(self, "Вложение в очереди", "Не удалось обработать очередь или ключ контакта не проверен. Данные сохранены. Сверьте отпечаток контакта при отправке текста или звонке.")
            if 'item' in locals() and item is not None and self._attachment_worker is None:
                QTimer.singleShot(250, self._try_attachment_outbox)

    def _attachment_failure(self, item, detail):
        self._attachment_skipped.add(item[0].name)
        # Avoid exhausting the server's per-IP upload limit during an outage.
        self._attachment_retry_after[item[0].name] = time.monotonic() + 300
        print(f"[ATTACHMENT] Ожидает повтора: {detail}")
        if not self._attachment_warning_shown:
            self._attachment_warning_shown = True
            if detail == "ATTACHMENT_INVALID":
                message = "Вложение не прошло проверку ключа или целостности. Задание сохранено; проверьте резервную копию."
            elif detail == "ATTACHMENT_TOO_LARGE":
                message = "Вложение превышает лимит клиента 21 MiB. Задание сохранено; проверьте резервную копию."
            elif isinstance(detail, str) and detail.startswith("HTTP 429:"):
                message = "Сервер временно не принимает загрузки. Вложение сохранено; повтор будет позже. При длительной проблеме обратитесь к администратору сервера."
            elif isinstance(detail, str) and detail.startswith("HTTP 503:"):
                message = "Сервер временно занят или недоступен. Вложение сохранено; повтор будет позже."
            elif isinstance(detail, str) and detail.startswith("HTTP 413:"):
                message = "Сервер отклонил загрузку по размеру. Вложение сохранено; проверьте лимиты сервера и туннеля."
            else:
                message = "Вложение сохранено и будет отправлено повторно. Убедитесь, что сервер обновлён и доступен."
            QMessageBox.warning(self, "Вложение в очереди", message)
        QTimer.singleShot(250, self._try_attachment_outbox)

    def _on_queued_upload_finished(self, success, data, worker):
        worker.wait()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if self._attachment_worker is not worker:
            return
        self._attachment_worker = None
        item, context = worker.queue_item, worker.recipient_context
        if (not success or worker.account_context != (state.username, state.server_url, state.device_id, state.token)
                or not recipient_is_verified(state, context)):
            self._attachment_failure(item, data if not success and isinstance(data, str) else "upload or identity")
            return
        try:
            grant = GrantFileAccessWorker(context.server_url, worker.account_context[3], item[2]["file_id"], context.device_id)
            grant.recipient_context, grant.queue_item, grant.account_context = context, item, worker.account_context
            self._attachment_worker = grant
            self._net_workers.append(grant)
            grant.finished.connect(lambda ok, data, w=grant: self._on_queued_grant_finished(ok, data, w),
                                   Qt.QueuedConnection)
            grant.start()
        except Exception as e:
            if 'grant' in locals() and grant in self._net_workers:
                self._net_workers.remove(grant)
            self._attachment_worker = None
            self._attachment_failure(item, type(e).__name__)

    def _on_queued_grant_finished(self, success, data, worker):
        worker.wait()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if self._attachment_worker is not worker:
            return
        self._attachment_worker = None
        item, context = worker.queue_item, worker.recipient_context
        if (not success or worker.account_context != (state.username, state.server_url, state.device_id, state.token)
                or not recipient_is_verified(state, context)):
            self._attachment_failure(item, data if not success and isinstance(data, str) else "grant or identity")
            return
        path, blob_path, job = item
        try:
            outbox.enqueue(context.owner_username, context.server_url, context.owner_device_id,
                           job["payload"], local_history=job["history"], message_id=job["message_id"])
            attachment_outbox.finish(path, blob_path, context.owner_username, context.server_url,
                                     context.owner_device_id, job["file_id"])
        except Exception as e:
            self._attachment_failure(item, type(e).__name__)
            return
        self._attachment_skipped.discard(path.name)
        self._try_outbox()
        QTimer.singleShot(250, self._try_attachment_outbox)

    def _media_context(self):
        return (state.username, state.device_id, state.server_url, state.current_chat_username)

    def _media_asset_key(self, file_id, secret_key):
        # A file ID alone is not enough: different servers or messages can
        # reuse it with a different decryption key.
        return self._media_context() + (file_id, secret_key)

    def _start_media_download(self, worker):
        if worker.media_context != self._media_context() or not worker.bubble.parent():
            raise ValueError("Attachment context changed")
        self._net_workers.append(worker)
        try:
            worker.start()
        except Exception:
            self._net_workers.remove(worker)
            raise

    def _media_download_failed(self, worker):
        try:
            worker.bubble.hide_skeleton()
            if getattr(worker, "is_voice", False):
                worker.bubble._voice_loading = False
            label = worker.bubble.msg_label
            label.setText('<a href="retry">Вложение не загружено — повторить</a>')
            label.setTextInteractionFlags(Qt.LinksAccessibleByMouse)
            if not getattr(worker, "retry_connected", False):
                label.linkActivated.connect(lambda _link, w=worker: self._retry_media_download(w))
                worker.retry_connected = True
            label.setVisible(True)
        except RuntimeError:
            pass

    def _retry_media_download(self, worker):
        try:
            if worker.media_context != self._media_context() or not worker.bubble.parent():
                return
            worker.bubble.msg_label.setVisible(False)
            if getattr(worker, "is_voice", False):
                self._voice_request_serial += 1
                worker.voice_request_serial = self._voice_request_serial
                worker.bubble._voice_loading = True
            else:
                worker.bubble.show_skeleton()
            self._queue_media_download(worker)
        except RuntimeError:
            pass

    def _queue_media_download(self, worker):
        worker.media_context = self._media_context()
        if not self._media_queue.enqueue(worker):
            self._media_download_failed(worker)

    def _finish_media_download(self, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        return self._media_queue.complete(worker) and worker.media_context == self._media_context()

    def _on_download_finished(self, success: bool, data: bytes, worker: DownloadFileWorker):
        if not self._finish_media_download(worker):
            return
        if not success:
            self._media_download_failed(worker)
            return
        try:
            if not worker.bubble or not worker.bubble.parent():
                return
        except RuntimeError:
            return
        try:
            decrypted_bytes = crypto.decrypt_file(data, worker.secret_key)
            if hasattr(worker, "file_id_cache"):
                self._image_cache[worker.file_id_cache] = decrypted_bytes
            caption = getattr(worker, "caption", "")
            if not worker.bubble or not worker.bubble.parent():
                return
            worker.bubble.set_image(decrypted_bytes, caption=caption)
            QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
                self.messages_scroll.verticalScrollBar().maximum()
            ))
        except Exception:
            worker.bubble.msg_label.setText("❌ Ошибка расшифровки")
            worker.bubble.msg_label.setVisible(True)

    def _send_system_payload(self, receiver_username: str, payload_dict: dict,
                             context=None, local_history=None, account_context=None):
        msg_type = payload_dict.get("type")
        durable = msg_type in {"text", "image", "voice", "file", "delete_msg", "edit_msg", "pin_msg"}
        ally_data = state.allies.get(receiver_username)
        if not ally_data or not ally_data.get("devices"):
            if durable:
                QMessageBox.warning(self, "Сообщение не отправлено", "Не найдено устройство получателя. Проверьте контакт.")
            return False
        try:
            account = (state.username, state.server_url, state.device_id, state.token)
            if (not all(isinstance(value, str) and value for value in account)
                    or (account_context is not None and account_context != account)):
                return False
            owner_key = crypto.get_public_key_b64()
            context = context or capture_recipient(state)
            if context.username != receiver_username or not recipient_is_verified(state, context):
                raise ValueError("Контакт или учётная запись изменились")
            if not durable and sum(isinstance(w, SendMessageWorker) for w in self._net_workers) >= 16:
                return False
            device_id, public_key = context.device_id, context.public_key
            _enc_dur_fn = getattr(self, "_encrypt_durable_personal", None) if durable else None
            if callable(_enc_dur_fn):
                encrypted_data = _enc_dur_fn(context, payload_dict, msg_type)
            else:
                encrypted_data = crypto.encrypt_message(json.dumps(payload_dict, ensure_ascii=False), public_key)
            payload = {"receiver_device_id": device_id, "encrypted_blob": encrypted_data["encrypted_blob"],
                       "signature": encrypted_data["signature"]}
            if (account != (state.username, state.server_url, state.device_id, state.token)
                    or crypto.get_public_key_b64() != owner_key
                    or not recipient_is_verified(state, context)):
                return False
            if durable:
                if len(payload["encrypted_blob"].encode("utf-8")) + len(payload["signature"].encode("utf-8")) > 1024 * 1024:
                    QMessageBox.warning(self, "Сообщение слишком большое", "Зашифрованное сообщение превышает лимит сервера 1 MiB.")
                    return False
                outbox.enqueue(context.owner_username, context.server_url, context.owner_device_id,
                               payload, local_history=local_history)
                # History is restored from the encrypted queue before network send.
                self._try_outbox()
                return True

            worker = SendMessageWorker(account[1], account[3], payload)
            worker.finished.connect(
                lambda success, data, w=worker: self._on_send_finished(success, data, msg_type, w),
                Qt.QueuedConnection,
            )
            self._net_workers.append(worker)
            try:
                worker.start()
            except Exception:
                self._net_workers.remove(worker)
                raise
            return True
        except Exception as e:
            err_type = type(e).__name__
            print(f"[SEND] Ошибка подготовки: {err_type}")
            if durable:
                QMessageBox.warning(
                    self,
                    "Сообщение не отправлено",
                    f"Не удалось сохранить сообщение в очередь или контакт изменился. ({err_type})",
                )
            return False

    def _encrypt_durable_personal(self, context, payload_dict: dict, msg_type: str) -> dict:
        pt_json = json.dumps(payload_dict, ensure_ascii=False)
        try:
            from app.double_ratchet import encrypt_personal_envelope

            env, used_dr = encrypt_personal_envelope(
                owner_username=context.owner_username,
                owner_device_id=context.owner_device_id,
                crypto_mgr=crypto,
                recipient_device_id=context.device_id,
                recipient_pub_b64=context.public_key,
                plaintext=pt_json,
                msg_kind=msg_type,
            )
            if not used_dr:
                self._ensure_peer_ratchet_session(context)
            return env
        except Exception as dr_exc:
            print(f"[DR] Fallback to NaCl Box for {msg_type}: {type(dr_exc).__name__}")
            return crypto.encrypt_message(pt_json, context.public_key)

    def _encrypt_attachment_personal(
        self, context, message_dict: dict, kind: str, file_id: str, secret_key: str, msg_id: str
    ) -> dict:
        pt_json = json.dumps(message_dict, ensure_ascii=False)
        try:
            from app.double_ratchet import attachment_commitment, encrypt_personal_envelope

            att_commit = attachment_commitment(file_id, secret_key, msg_id)
            env, used_dr = encrypt_personal_envelope(
                owner_username=context.owner_username,
                owner_device_id=context.owner_device_id,
                crypto_mgr=crypto,
                recipient_device_id=context.device_id,
                recipient_pub_b64=context.public_key,
                plaintext=pt_json,
                msg_kind=kind,
                attachment_commit=att_commit,
            )
            if not used_dr:
                self._ensure_peer_ratchet_session(context)
            return env
        except Exception as dr_exc:
            print(f"[DR] Attachment fallback to NaCl Box for {kind}: {type(dr_exc).__name__}")
            return crypto.encrypt_message(pt_json, context.public_key)

    def sync_own_prekey_bundle(self):
        account = (state.username, state.server_url, state.device_id, state.token)
        if not all(isinstance(v, str) and v for v in account) or getattr(crypto, "private_key", None) is None:
            return
        from app.workers import PreKeyStatusWorker

        if any(isinstance(w, PreKeyStatusWorker) and w.isRunning() for w in self._net_workers):
            return
        w = PreKeyStatusWorker(account[1], account[3])
        w.account_context = account
        self._net_workers.append(w)
        w.finished.connect(
            lambda ok, res, worker=w: self._on_prekey_status_received(ok, res, worker),
            Qt.QueuedConnection,
        )
        try:
            w.start()
        except Exception:
            if w in self._net_workers:
                self._net_workers.remove(w)

    def _on_prekey_status_received(self, ok: bool, res, worker):
        worker.wait()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        account = (state.username, state.server_url, state.device_id, state.token)
        if worker.account_context != account or not ok or not isinstance(res, dict):
            return
        if getattr(crypto, "private_key", None) is None:
            return
        from app.double_ratchet import DEFAULT_OPK_BATCH, OPK_REPLENISH_THRESHOLD, RatchetStore
        from app.workers import PublishPreKeyBundleWorker

        has_bundle = bool(res.get("has_bundle"))
        avail = int(res.get("available_one_time_keys", 0) or 0)
        if has_bundle and avail >= OPK_REPLENISH_THRESHOLD:
            return
        need = max(0, DEFAULT_OPK_BATCH - avail)
        try:
            bundle_payload = RatchetStore(account[0]).prepare_publish_bundle(
                crypto.private_key,
                needed_opks=need,
                rotate_signed_prekey=not has_bundle,
            )
        except Exception as exc:
            print(f"[X3DH] Не удалось подготовить пакет prekey: {type(exc).__name__}")
            return

        pub_w = PublishPreKeyBundleWorker(account[1], account[3], bundle_payload)
        pub_w.account_context = account
        self._net_workers.append(pub_w)

        def _done_pub(_ok, _data, pw=pub_w):
            pw.wait()
            if pw in self._net_workers:
                self._net_workers.remove(pw)

        pub_w.finished.connect(_done_pub, Qt.QueuedConnection)
        try:
            pub_w.start()
        except Exception:
            if pub_w in self._net_workers:
                self._net_workers.remove(pub_w)

    def _ensure_peer_ratchet_session(self, context):
        account = (state.username, state.server_url, state.device_id, state.token)
        if (
            not all(isinstance(v, str) and v for v in account)
            or getattr(crypto, "private_key", None) is None
            or context is None
            or not recipient_is_verified(state, context)
        ):
            return
        try:
            from app.double_ratchet import RatchetStore
            from app.workers import ClaimPreKeyBundleWorker

            if RatchetStore(account[0]).has_active_session(context.device_id, context.public_key):
                return
            inflight = getattr(self, "_inflight_prekey_claims", None)
            if inflight is None:
                inflight = set()
                self._inflight_prekey_claims = inflight
            if context.device_id in inflight:
                return
            inflight.add(context.device_id)
            cw = ClaimPreKeyBundleWorker(account[1], account[3], context.device_id)
            cw.account_context = account
            cw.peer_context = context
            self._net_workers.append(cw)
            cw.finished.connect(
                lambda ok, data, dev_id, worker=cw: self._on_peer_prekey_claimed(ok, data, dev_id, worker),
                Qt.QueuedConnection,
            )
            cw.start()
        except Exception:
            if hasattr(self, "_inflight_prekey_claims"):
                self._inflight_prekey_claims.discard(context.device_id)

    def _on_peer_prekey_claimed(self, ok: bool, data, dev_id: str, worker):
        worker.wait()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if hasattr(self, "_inflight_prekey_claims"):
            self._inflight_prekey_claims.discard(dev_id)
        account = (state.username, state.server_url, state.device_id, state.token)
        ctx = getattr(worker, "peer_context", None)
        if (
            worker.account_context != account
            or not ok
            or not isinstance(data, dict)
            or ctx is None
            or getattr(crypto, "private_key", None) is None
            or not recipient_is_verified(state, ctx)
        ):
            return
        try:
            from app.double_ratchet import RatchetStore

            store = RatchetStore(account[0])
            if not store.has_active_session(ctx.device_id, ctx.public_key):
                store.init_initiator_session_from_bundle(
                    our_signing_key=crypto.private_key,
                    peer_device_id=ctx.device_id,
                    peer_verified_ik_b64=ctx.public_key,
                    claimed_bundle=data,
                )
            if state.current_chat_type == "ally" and state.current_chat_username == ctx.username:
                self._update_contact_identity_status()
        except Exception as exc:
            print(f"[X3DH] Не удалось инициализировать Double Ratchet сессию: {type(exc).__name__}")

    def _on_send_finished(self, success: bool, data, msg_type: str, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)

        if not success:
            print(f"[SEND] ❌ Ошибка отправки ({msg_type}): {data}")
            if msg_type in {"text", "image", "voice"}:
                QMessageBox.warning(
                    self, "Отправка не подтверждена",
                    "Сервер не подтвердил отправку. Сообщение сохранено локально, "
                    "но могло не дойти. При сетевом сбое оно также могло быть доставлено; "
                    "проверьте перед повторной отправкой."
                )

    def _try_outbox(self):
        if not state.username or not state.device_id or not state.server_url or not state.token:
            return
        if self._outbox_worker is not None or self._outbox_management_active:
            return
        account = (state.username, state.server_url, state.device_id, state.token)
        try:
            item = outbox.next_message(account[0], account[1], account[2], self._outbox_skipped)
            if item is None:
                # Retry failures on the next timer tick; do not spin in a loop.
                self._outbox_skipped.clear()
                return
            if account != (state.username, state.server_url, state.device_id, state.token):
                return
            path, record = item
            try:
                recipient = verify_queued_recipient(state, crypto, record)
            except OutboxRecipientError:
                self._outbox_skipped.add(path.name)
                if not self._outbox_identity_warning_shown:
                    self._outbox_identity_warning_shown = True
                    QMessageBox.warning(self, "Очередь приостановлена",
                        "Некоторые сообщения не отправлены: получатель не проверен, ключ изменился или пакет недоступен. "
                        "Данные сохранены. Сверьте ключ через меню чата; отменить сообщения можно в меню очереди. "
                        "Если ответ сервера ранее потерялся, сообщение уже могло быть доставлено.")
                QTimer.singleShot(250, self._try_outbox)
                return
            # Restore the local history before any network request. If storage
            # fails, the encrypted queue record remains untouched for retry.
            payload = outbox.prepare_network_payload(account[0], record)
            if account != (state.username, state.server_url, state.device_id, state.token):
                return
            try:
                if verify_queued_recipient(state, crypto, record) != recipient:
                    raise OutboxRecipientError("Recipient changed during queue preparation")
            except OutboxRecipientError:
                self._outbox_skipped.add(path.name)
                QTimer.singleShot(250, self._try_outbox)
                return
            if account != (state.username, state.server_url, state.device_id, state.token):
                return
            mark_fn = getattr(outbox, "mark_send_attempted", None)
            if mark_fn is not None:
                mark_fn(path, account[0], account[1], account[2])
            worker = ReliableSendWorker(account[1], account[3], payload)
            worker.expected_sender_device_id = account[2]
            worker.queue_path = path
            worker.queue_username = account[0]
            worker.queue_server = account[1]
            worker.queue_device = account[2]
            worker.local_history = record.get("_local_history")
            self._outbox_worker = worker
            worker.finished.connect(
                lambda success, data, w=worker: self._on_outbox_finished(success, data, w),
                Qt.QueuedConnection,
            )
            worker.start()
        except outbox.QueueRecordError as e:
            self._outbox_skipped.add(e.path.name)
            if not self._outbox_warning_shown:
                self._outbox_warning_shown = True
                QMessageBox.warning(self, "Ошибка очереди", "Запись сообщения не прочитана и осталась в очереди. Остальные будут обработаны; проверьте ключ и резервную копию.")
            QTimer.singleShot(250, self._try_outbox)
        except Exception as e:
            if 'worker' in locals() and not worker.isRunning() and self._outbox_worker is worker:
                self._outbox_worker = None
            print(f"[OUTBOX] Ошибка локальной очереди: {type(e).__name__}")
            if not self._outbox_warning_shown:
                self._outbox_warning_shown = True
                QMessageBox.warning(self, "Ошибка очереди", "Не удалось прочитать очередь сообщений. Данные не удалены.")
            if 'item' in locals() and item is not None and self._outbox_worker is None:
                self._outbox_skipped.add(item[0].name)
                QTimer.singleShot(250, self._try_outbox)

    def _on_outbox_finished(self, success, data, worker):
        worker.wait()
        if self._outbox_worker is not worker:
            return
        self._outbox_worker = None
        if success:
            try:
                outbox.acknowledge(worker.queue_path, worker.queue_username,
                                   worker.queue_server, worker.queue_device,
                                   worker.payload["client_message_id"])
                self._outbox_skipped.discard(worker.queue_path.name)
                history = worker.local_history or {}
                if (state.username == worker.queue_username and state.device_id == worker.queue_device
                        and state.server_url.rstrip("/") == worker.queue_server.rstrip("/")
                        and state.current_chat_type == "ally"
                        and state.current_chat_username == history.get("ally_username")):
                    for i in range(self.messages_layout.count()):
                        bubble = self.messages_layout.itemAt(i).widget()
                        if getattr(bubble, "msg_id", None) == history.get("msg_id") and hasattr(bubble, "status_label"):
                            bubble.status_label.setText("✓✓" if bubble.is_read else "✓")
                            bubble.status_label.setToolTip("Сервер принял сообщение; это не подтверждение прочтения")
                            break
            except Exception as e:
                print(f"[OUTBOX] Не удалось подтвердить локальную очередь: {type(e).__name__}")
                self._outbox_skipped.add(worker.queue_path.name)
        else:
            self._outbox_skipped.add(worker.queue_path.name)
            print(f"[OUTBOX] Сообщение сохранено для повтора: {data}")
            if isinstance(data, str) and data.startswith("HTTP 429:") and not self._outbox_warning_shown:
                self._outbox_warning_shown = True
                QMessageBox.warning(self, "Очередь получателя заполнена",
                                    "Сервер временно не принимает новые сообщения. Они остаются в очереди и будут повторены позже.")
            elif isinstance(data, str) and data.startswith("HTTP 413:") and not self._outbox_warning_shown:
                self._outbox_warning_shown = True
                QMessageBox.warning(self, "Сообщение слишком большое", "Сервер отклонил сообщение по размеру. Оно осталось в очереди; при необходимости отмените его в меню очереди.")
            elif data == "HTTP 404: Not Found" and not self._outbox_warning_shown:
                self._outbox_warning_shown = True
                QMessageBox.warning(self, "Требуется обновление сервера",
                                    "Сервер не поддерживает безопасный повтор отправки. "
                                    "Сообщения останутся в очереди до обновления сервера.")
        QTimer.singleShot(250, self._try_outbox)

    def refresh_message_bubbles(self):
        container = self.messages_container
        for i in range(container.layout().count()):
            widget = container.layout().itemAt(i).widget()
            if isinstance(widget, MessageBubble):
                widget.apply_theme()
        for btn_name in (
            "call_btn", "attach_btn", "mic_btn", "deaf_btn",
            "mic_input_btn", "send_btn", "screen_share_btn"
        ):
            btn = getattr(self, btn_name, None)
            if btn:
                btn.refresh_theme()

    def open_settings(self):
        if self.settings_screen is None:
            from app.windows.settings_screen import SettingsScreen
            self.settings_screen = SettingsScreen()
            self.settings_screen.close_requested.connect(self.close_settings)
            if hasattr(self.settings_screen, "logout_requested"):
                self.settings_screen.logout_requested.connect(self.logout_requested.emit)
            if hasattr(self.settings_screen, "call_audio_prefs_changed"):
                self.settings_screen.call_audio_prefs_changed.connect(self.on_call_audio_prefs_changed)
            self.right_stack.addWidget(self.settings_screen)
        if hasattr(self.settings_screen, "refresh"):
            self.settings_screen.refresh()
        self.right_stack.setCurrentWidget(self.settings_screen)

    def reset_session_view(self):
        gvc = getattr(self, "_group_voice_ctrl", None)
        if gvc is not None:
            gvc.leave_local_session()
        if hasattr(self, "_group_voice_rosters"):
            self._group_voice_rosters.clear()
        if hasattr(self, "_group_voice_speaking"):
            self._group_voice_speaking.clear()
        if hasattr(self, "group_voice_bar"):
            self.group_voice_bar.setVisible(False)
        try:
            from app.ice_config import clear_runtime_ice_config
            clear_runtime_ice_config()
        except Exception:
            pass
        history_worker = getattr(self, "_history_worker", None)
        if history_worker is not None:
            self._history_pending = None
            history_worker.cancel()
        if hasattr(self, "_media_queue"):
            self._media_queue.reset()
        if hasattr(self, "_image_cache"):
            self._image_cache.clear()
        for set_attr in ("_outbox_skipped", "_attachment_skipped", "_attachment_retry_after"):
            container = getattr(self, set_attr, None)
            if container is not None:
                container.clear()
        for flag_attr in (
            "_outbox_warning_shown",
            "_outbox_identity_warning_shown",
            "_attachment_warning_shown",
            "_incoming_identity_notice_shown",
        ):
            if hasattr(self, flag_attr):
                setattr(self, flag_attr, False)
        if hasattr(self, "allies_list"):
            self.allies_list.clear()
        if hasattr(self, "messages_layout"):
            while self.messages_layout.count() > 1:
                item = self.messages_layout.takeAt(0)
                widget = item.widget() if item else None
                if widget is not None:
                    widget.setParent(None)
                    widget.deleteLater()
        if hasattr(self, "msg_input"):
            self.msg_input.clear()
        if hasattr(self, "right_stack") and hasattr(self, "empty_state"):
            self.right_stack.setCurrentWidget(self.empty_state)

    def close_settings(self):
        if state.current_chat_type == "group" and state.current_group_id:
            self.right_stack.setCurrentWidget(self.chat_area)
        elif state.current_chat_username:
            self.right_stack.setCurrentWidget(self.chat_area)
        else:
            self.right_stack.setCurrentWidget(self.empty_state)
        if self.right_stack.currentWidget() is self.chat_area and self.isVisible():
            self._mark_visible_history_read()

    def _on_typing(self):
        self._on_text_changed()
        if state.current_chat_type == "group":
            return
        if not state.current_chat_username:
            return
        if self._my_typing_timer.isActive():
            return
        self._my_typing_timer.start(3000)
        self._send_system_payload(state.current_chat_username, {"type": "typing"})

    def update_connection_status(self, status: str):
        labels = {
            "connected":    "Подключено",
            "disconnected": "Отключено",
            "reconnecting": "Переподключение...",
        }
        colors = {
            "connected":    "#54caa0",
            "disconnected": "#ff7b8d",
            "reconnecting": "#ffc16a",
        }
        self.conn_status.setText(labels.get(status, status))
        self.conn_status.setProperty("status", status)
        self.conn_status.style().unpolish(self.conn_status)
        self.conn_status.style().polish(self.conn_status)
        if hasattr(self, "_conn_dot"):
            self._conn_dot._update_icon(custom_color=colors.get(status, "#777e8e"))

    def _set_reply_to(self, msg_id: str, text: str, sender: str):
        self._reply_to_msg_id  = msg_id
        self._reply_to_text    = text
        self._reply_to_sender  = sender
        self.reply_preview_sender.setText(f"Ответ для @{sender}")
        preview = text[:60] + "..." if len(text) > 60 else text
        self.reply_preview_text.setText(preview)
        self.reply_preview.setVisible(True)
        self.msg_input.setFocus()

    def _cancel_reply(self):
        self._reply_to_msg_id  = None
        self._reply_to_text    = None
        self._reply_to_sender  = None
        self._editing_msg_id   = None
        self.reply_preview.setVisible(False)

    def _connect_bubble_signals(self, bubble: MessageBubble, sender_username: str):
        bubble.set_sender(sender_username)
        bubble.reply_requested.connect(self._set_reply_to)
        bubble.delete_requested.connect(self._delete_message)
        bubble.voice_play_requested.connect(self._play_voice_message)
        bubble.voice_seek_requested.connect(self._seek_voice_message)
        bubble.scroll_to_msg_requested.connect(self._scroll_to_message)
        bubble.image_view_requested.connect(self._on_image_view_requested)
        if hasattr(bubble, "file_download_requested"):
            bubble.file_download_requested.connect(self._on_bubble_file_download_requested)
        if hasattr(bubble, "edit_requested"):
            bubble.edit_requested.connect(getattr(self, "_on_bubble_edit_requested", lambda *a: None))
        if hasattr(bubble, "pin_requested"):
            bubble.pin_requested.connect(getattr(self, "_on_bubble_pin_requested", lambda *a: None))

    def _scroll_to_message(self, target_msg_id: str):
        for i in range(self.messages_layout.count() - 1):
            widget = self.messages_layout.itemAt(i).widget()
            if hasattr(widget, "msg_id") and widget.msg_id == target_msg_id:
                self.messages_scroll.ensureWidgetVisible(widget, 0, 50)
                self._highlight_bubble(widget)
                return
        self._request_history_target(target_msg_id)

    def _request_history_target(self, target_msg_id):
        if not isinstance(target_msg_id, str) or not target_msg_id:
            return
        if state.current_chat_type == "group" and state.current_group_id:
            chat_key = f"group_{state.current_group_id}"
        elif state.current_chat_type == "ally" and state.current_chat_username:
            chat_key = state.current_chat_username
        else:
            return
        context = (state.username, state.server_url, state.device_id, state.token,
                   state.current_chat_type, state.current_chat_username, state.current_group_id,
                   self._history_offset, self._history_query)
        self._history_serial += 1
        request = (self._history_serial, context, chat_key, target_msg_id)
        if self._history_worker is not None:
            self._history_pending = request
            self._history_worker.cancel()
        else:
            self._start_history_worker(request)

    def _reveal_history_message(self, target_msg_id, context):
        current = (state.username, state.server_url, state.device_id, state.token,
                   state.current_chat_type, state.current_chat_username, state.current_group_id,
                   self._history_offset, self._history_query)
        if current != context:
            return
        for i in range(self.messages_layout.count() - 1):
            widget = self.messages_layout.itemAt(i).widget()
            if getattr(widget, "msg_id", None) == target_msg_id:
                self.messages_scroll.ensureWidgetVisible(widget, 0, 50)
                self._highlight_bubble(widget)
                return

    def _highlight_bubble(self, bubble):
        if not hasattr(bubble, "bubble"):
            return
        original_name = bubble.bubble.objectName()
        bubble.bubble.setObjectName("BubbleHighlight")
        bubble.bubble.style().unpolish(bubble.bubble)
        bubble.bubble.style().polish(bubble.bubble)

        def restore():
            if bubble and hasattr(bubble, "bubble"):
                bubble.bubble.setObjectName(original_name)
                bubble.bubble.style().unpolish(bubble.bubble)
                bubble.bubble.style().polish(bubble.bubble)

        QTimer.singleShot(800, restore)

    def _dispatch_cancel_upload_reservations(self, file_ids):
        if not file_ids:
            return
        server_url = getattr(state, "server_url", None)
        token = getattr(state, "token", None)
        if not isinstance(server_url, str) or not server_url or not isinstance(token, str) or not token:
            return
        worker_cls = globals().get("CancelUploadReservationWorker")
        if worker_cls is None:
            return
        net_workers = getattr(self, "_net_workers", None)
        if not isinstance(net_workers, list):
            return
        for fid in file_ids:
            if len(net_workers) >= 32:
                break
            w = worker_cls(server_url, token, fid)
            w.finished.connect(
                lambda _ok, _data, wrk=w: net_workers.remove(wrk) if wrk in net_workers else None,
                Qt.QueuedConnection,
            )
            net_workers.append(w)
            try:
                w.start()
            except Exception:
                if w in net_workers:
                    net_workers.remove(w)

    def _delete_message(self, msg_id: str):
        if state.current_chat_type == "group":
            group_id = state.current_group_id
            if group_id:
                storage.delete_message(state.username, f"group_{group_id}", msg_id)
                for i in range(self.messages_layout.count() - 1):
                    widget = self.messages_layout.itemAt(i).widget()
                    if hasattr(widget, "msg_id") and widget.msg_id == msg_id:
                        for sig in (
                            "reply_requested", "delete_requested",
                            "voice_play_requested", "voice_seek_requested",
                            "scroll_to_msg_requested", "image_view_requested",
                        ):
                            try:
                                getattr(widget, sig).disconnect()
                            except Exception:
                                pass
                        self.messages_layout.removeWidget(widget)
                        widget.setParent(None)
                        widget.deleteLater()
                        break
            return

        if not state.current_chat_username:
            return

        # Refuse to race an active in-flight HTTP upload/send for the same message.
        active_outbox_w = getattr(self, "_outbox_worker", None)
        if active_outbox_w is not None:
            in_flight_hist = getattr(active_outbox_w, "local_history", None)
            if isinstance(in_flight_hist, dict) and in_flight_hist.get("msg_id") == msg_id:
                QMessageBox.warning(
                    self,
                    "Сообщение отправляется",
                    "Дождитесь завершения текущей отправки этого сообщения и повторите удаление.",
                )
                return
        active_attach_w = getattr(self, "_attachment_worker", None)
        if active_attach_w is not None:
            qitem = getattr(active_attach_w, "queue_item", None)
            if isinstance(qitem, tuple) and len(qitem) == 3 and isinstance(qitem[2], dict):
                ahist = qitem[2].get("history")
                if isinstance(ahist, dict) and ahist.get("msg_id") == msg_id:
                    QMessageBox.warning(
                        self,
                        "Вложение загружается",
                        "Дождитесь завершения текущей загрузки вложения и повторите удаление.",
                    )
                    return

        cancelled_file_ids = []
        cancelled_outbox_names = []
        any_send_attempted = False
        acct = (
            getattr(state, "username", None),
            getattr(state, "server_url", None),
            getattr(state, "device_id", None),
        )
        if all(isinstance(v, str) and v for v in acct):
            attach_mod = globals().get("attachment_outbox")
            cancel_attach_fn = getattr(attach_mod, "cancel_by_local_msg_id", None) if attach_mod else None
            if cancel_attach_fn is not None:
                try:
                    cancelled_file_ids = list(cancel_attach_fn(*acct, msg_id))
                except Exception:
                    cancelled_file_ids = []
            if cancelled_file_ids:
                for fid in cancelled_file_ids:
                    jname = f"{fid}.job"
                    if hasattr(self, "_attachment_skipped"):
                        self._attachment_skipped.discard(jname)
                    if hasattr(self, "_attachment_retry_after"):
                        self._attachment_retry_after.pop(jname, None)
                self._dispatch_cancel_upload_reservations(cancelled_file_ids)

            outbox_mod = globals().get("outbox")
            cancel_outbox_fn = getattr(outbox_mod, "cancel_by_local_msg_id", None) if outbox_mod else None
            if cancel_outbox_fn is not None:
                try:
                    cancelled_outbox_names, any_send_attempted = cancel_outbox_fn(*acct, msg_id)
                except Exception:
                    cancelled_outbox_names, any_send_attempted = [], False
            if cancelled_outbox_names and hasattr(self, "_outbox_skipped"):
                self._outbox_skipped.difference_update(cancelled_outbox_names)

        del_meta_fn = getattr(storage, "delete_message_with_meta", None)
        if del_meta_fn is not None:
            deleted, was_mine = del_meta_fn(state.username, state.current_chat_username, msg_id)
        else:
            deleted = bool(storage.delete_message(state.username, state.current_chat_username, msg_id))
            was_mine = True

        if deleted or cancelled_file_ids or cancelled_outbox_names:
            voice_cache.delete_group(message_scope(state.username, state.server_url, state.current_chat_username, msg_id))
            img_cache = getattr(self, "_image_cache", None)
            del_prefix = getattr(img_cache, "delete_prefix", None)
            if callable(del_prefix):
                del_prefix((
                    getattr(state, "username", None),
                    getattr(state, "device_id", None),
                    getattr(state, "server_url", None),
                    state.current_chat_username,
                ))
            self._render_history_page()
            # Only send delete_msg to the peer when deleting our OWN message AND
            # the message could have already reached the relay server.
            should_notify_peer = (
                deleted
                and was_mine
                and not cancelled_file_ids
                and (not cancelled_outbox_names or any_send_attempted)
            )
            if should_notify_peer:
                self._send_system_payload(
                    state.current_chat_username,
                    {"type": "delete_msg", "msg_id": msg_id},
                )

    def _show_chat_menu(self):
        from app.theme import get_theme
        t = get_theme()

        menu = QMenu(self)
        menu.setObjectName("ChatContextMenu")
        menu.setAttribute(Qt.WA_TranslucentBackground, True)
        menu.setAttribute(Qt.WA_NoSystemBackground, True)
        menu.setWindowFlags(
            Qt.Popup | Qt.FramelessWindowHint | Qt.NoDropShadowWindowHint
        )

        clear_action = menu.addAction(
            _render_svg_icon("trash.svg", t.get("danger"), 16), "Очистить историю"
        )
        clear_action.triggered.connect(self._confirm_clear_chat)

        chat_key = self._current_chat_storage_key()
        if chat_key:
            ttl_menu = menu.addMenu("Исчезающие сообщения (TTL)")
            _ttl_fn = getattr(globals().get("storage"), "get_chat_ttl", None)
            cur_ttl = _ttl_fn(state.username, chat_key) if callable(_ttl_fn) else None
            for label_txt, sec_val in (
                ("Выключено", None),
                ("1 минута", 60),
                ("1 час", 3600),
                ("24 часа", 86400),
                ("7 дней", 604800),
            ):
                prefix = "✓ " if cur_ttl == sec_val else "   "
                act_ttl = ttl_menu.addAction(f"{prefix}{label_txt}")
                act_ttl.triggered.connect(
                    lambda _checked=False, ck=chat_key, sv=sec_val: self._set_current_chat_ttl(ck, sv)
                )

        if state.current_chat_type == "ally" and state.current_chat_username:
            ally_devices = state.allies.get(state.current_chat_username, {}).get("devices", [])
            if isinstance(ally_devices, list) and len(ally_devices) > 1:
                select_dev_action = menu.addAction("Выбрать устройство собеседника…")
                select_dev_action.triggered.connect(self._select_contact_target_device)
            verify_action = menu.addAction("Сверить ключ собеседника")
            verify_action.triggered.connect(self._verify_current_contact)
            cancel_queue = menu.addAction("Отменить очередь сообщений…")
            cancel_queue.triggered.connect(self._cancel_pending_outbox)
            cancel_attach_queue = menu.addAction("Отменить очередь вложений…")
            cancel_attach_queue.triggered.connect(self._cancel_pending_attachment_outbox)

        if state.current_chat_type == "group" and state.current_group_id:
            group = state.groups.get(state.current_group_id)
            if group and not group.get("archived"):
                is_creator = group.get("created_by_device_id") == state.device_id
                menu.addSeparator()
                verify_grp_act = menu.addAction("Сверить ключи участников группы…")
                verify_grp_act.triggered.connect(self._verify_group_members_dialog)
                invite_act = menu.addAction("Пригласить участника…")
                invite_act.triggered.connect(self._invite_member_to_current_group)
                if is_creator:
                    act = menu.addAction(
                        _render_svg_icon("trash.svg", t.get("danger"), 16),
                        "Удалить группу"
                    )
                    act.triggered.connect(self._delete_group_on_server)
                else:
                    act = menu.addAction(
                        _render_svg_icon("trash.svg", t.get("danger"), 16),
                        "Выйти из группы"
                    )
                    act.triggered.connect(self._leave_group_on_server)

        if self.active_call_username:
            menu.addSeparator()
            profiles = {
                "smooth": "Скорость — 960×540 • 45 fps",
                "balanced": "Быстро   — 1280×720 • 30 fps",
                "sharp": "Чётко    — 1600×900 • 20 fps",
            }
            quality_menu = menu.addMenu("Качество экрана")
            quality_menu.setObjectName("ChatContextMenu")
            quality_menu.setAttribute(Qt.WA_TranslucentBackground, True)
            quality_menu.setAttribute(Qt.WA_NoSystemBackground, True)
            quality_menu.setWindowFlags(
                Qt.Popup | Qt.FramelessWindowHint | Qt.NoDropShadowWindowHint
            )
            for key, label in profiles.items():
                action = quality_menu.addAction(label)
                action.setCheckable(True)
                action.setChecked(self.current_quality_profile == key)
                action.triggered.connect(
                    lambda checked, k=key: self._set_screen_share_quality(k)
                )

        menu.exec(QCursor.pos())

    def _current_chat_storage_key(self) -> str:
        if state.current_chat_type == "group" and state.current_group_id:
            return f"group_{state.current_group_id}"
        if state.current_chat_type == "ally" and state.current_chat_username:
            return state.current_chat_username
        return ""

    def _set_current_chat_ttl(self, chat_key: str, ttl_seconds: int | None) -> bool:
        if not state.username or not chat_key:
            return False
        set_fn = getattr(globals().get("storage"), "set_chat_ttl", None)
        if not callable(set_fn):
            return False
        try:
            return bool(set_fn(state.username, chat_key, ttl_seconds))
        except Exception:
            return False

    def refresh_visible_chat_if_needed(self):
        if not state.username:
            return
        if (state.current_chat_type == "ally" and state.current_chat_username) or (
            state.current_chat_type == "group" and state.current_group_id
        ):
            self._render_history_page()

    def _select_contact_target_device(self) -> bool:
        if state.current_chat_type != "ally" or not state.current_chat_username:
            return False
        username = state.current_chat_username
        ally_data = state.allies.get(username)
        if not isinstance(ally_data, dict):
            return False
        devices = ally_data.get("devices")
        if not isinstance(devices, list) or len(devices) < 2:
            return False
        try:
            device_key_map(ally_data)
        except (ValueError, TypeError) as exc:
            QMessageBox.warning(self, "Выбор устройства", str(exc))
            return False

        account = (state.username, state.device_id, state.server_url, state.token)
        if not all(isinstance(v, str) and v for v in account):
            return False
        clean_srv = account[2].rstrip("/")

        labels = []
        current_idx = 0
        for idx, dev in enumerate(devices):
            dev_id = dev["device_id"]
            ctx = RecipientContext(username, dev_id, dev["public_key"], account[0], account[1], clean_srv)
            is_ver = recipient_is_verified(state, ctx)
            badge = "проверено" if is_ver else "не проверено"
            active_mark = " • активно" if dev_id == state.current_chat_device_id else ""
            if dev_id == state.current_chat_device_id:
                current_idx = idx
            labels.append(f"{dev.get('device_name', 'Устройство')} — {dev_id} [{badge}]{active_mark}")

        choice, ok = QInputDialog.getItem(
            self,
            "Устройство собеседника",
            f"Выберите активное устройство @{username} для отправки сообщений и звонков:",
            labels,
            current_idx,
            False,
        )
        if not ok or choice not in labels:
            return False

        if ((state.username, state.device_id, state.server_url, state.token) != account
                or state.current_chat_type != "ally"
                or state.current_chat_username != username):
            return False
        chosen = devices[labels.index(choice)]
        chosen_id = chosen.get("device_id")
        chosen_pub = chosen.get("public_key")
        if not isinstance(chosen_id, str) or not isinstance(chosen_pub, str):
            return False
        ctx = RecipientContext(username, chosen_id, chosen_pub, account[0], account[1], clean_srv)
        if not recipient_still_trusted(state, ctx):
            QMessageBox.warning(self, "Выбор отменён", "Список устройств контакта изменился.")
            return False

        state.current_chat_device_id = chosen_id
        if not recipient_is_verified(state, ctx):
            self._verify_call_contact(username, chosen_id)
        if ((state.username, state.device_id, state.server_url, state.token) != account
                or state.current_chat_type != "ally"
                or state.current_chat_username != username):
            return False
        self._persist_preferred_contact_device(username, chosen_id)
        self._update_contact_identity_status()
        QTimer.singleShot(0, self._try_outbox)
        QTimer.singleShot(0, self._try_attachment_outbox)
        return True

    def _verify_current_contact(self):
        if getattr(state, "current_chat_type", None) == "group" and getattr(state, "current_group_id", None):
            self._verify_group_members_dialog()
            return
        try:
            selected = capture_recipient(state)
            devices = state.allies[selected.username]["devices"]
            device_key_map(state.allies[selected.username])
            if len(devices) > 1:
                labels = [f"{d.get('device_name', 'Устройство')} — {d['device_id']}" for d in devices]
                choice, ok = QInputDialog.getItem(self, "Проверка устройства", "Выберите устройство собеседника:", labels, 0, False)
                if not ok or choice not in labels:
                    return
                device = devices[labels.index(choice)]
                context = RecipientContext(selected.username, device["device_id"], device["public_key"],
                                           selected.owner_username, selected.owner_device_id, selected.server_url)
            else:
                context = selected
        except (ValueError, KeyError, TypeError) as exc:
            QMessageBox.warning(self, "Проверка ключа", str(exc))
            return
        if not recipient_still_trusted(state, context) or state.current_chat_username != context.username:
            QMessageBox.warning(self, "Проверка отменена", "Чат или ключ контакта изменился.")
            return
        if recipient_is_verified(state, context):
            fp_hex = fingerprint_public_key(context.public_key)
            info_txt = self._format_key_verification_prompt(context.username, context.public_key, fp_hex, verified=True)
            QMessageBox.information(self, "Проверенный ключ", info_txt)
        elif not self._verify_call_contact(context.username, context.device_id):
            return
        if not recipient_is_verified(state, context) or state.current_chat_username != context.username or state.current_chat_type != "ally":
            QMessageBox.warning(self, "Проверка отменена", "Чат или ключ контакта изменился.")
            return
        state.current_chat_device_id = context.device_id
        self._persist_preferred_contact_device(context.username, context.device_id)
        self._outbox_skipped.clear()
        self._attachment_skipped.clear()
        self._attachment_retry_after.clear()
        self._outbox_identity_warning_shown = False
        self._incoming_identity_notice_shown = False
        self._update_contact_identity_status()
        self.contact_verification_changed.emit()
        QMessageBox.information(self, "Ключ проверен", "Совпадение ключа сохранено. Ожидающие сообщения будут проверены повторно.")
        QTimer.singleShot(0, self._try_outbox)
        QTimer.singleShot(0, self._try_attachment_outbox)

    def _cancel_pending_outbox(self):
        if self._outbox_worker is not None or self._attachment_worker is not None:
            QMessageBox.warning(self, "Запрос выполняется", "Дождитесь завершения текущей отправки или загрузки и повторите попытку.")
            return
        account = (state.username, state.server_url, state.device_id)
        if not all(account):
            return
        self._outbox_management_active = True
        try:
            paths = outbox.pending_paths(*account)
            if not paths:
                QMessageBox.information(self, "Очередь сообщений", "Ожидающих сообщений нет. Отдельная очередь загрузки вложений не учитывается.")
                return
            answer = QMessageBox.question(
                self, "Отменить очередь сообщений?",
                f"Будет удалено из очереди сообщений: {len(paths)}. Это все контакты этой учётной записи и сервера. "
                "История останется, а загружаемые вложения не будут отменены. "
                "Ранее отправленные пакеты могли уже дойти, даже если ответ сервера был потерян. "
                "Это действие необратимо. Продолжить?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
            if (state.username, state.server_url, state.device_id) != account:
                QMessageBox.warning(self, "Отмена очереди", "Учётная запись изменилась; данные не удалены.")
                return
            outbox.discard_paths(paths, *account)
            self._outbox_skipped.difference_update(p.name for p in paths)
            self._outbox_identity_warning_shown = False
            QMessageBox.information(self, "Очередь сообщений", "Выбранные ожидающие записи удалены. Проверьте историю перед повторной отправкой.")
        except Exception as exc:
            print(f"[OUTBOX] Ошибка отмены: {type(exc).__name__}")
            QMessageBox.warning(self, "Ошибка очереди", "Не все записи удалось удалить. Проверьте очередь и хранилище.")
        finally:
            self._outbox_management_active = False

    def _cancel_pending_attachment_outbox(self):
        if self._outbox_worker is not None or self._attachment_worker is not None:
            QMessageBox.warning(
                self,
                "Запрос выполняется",
                "Дождитесь завершения текущей отправки или загрузки и повторите попытку.",
            )
            return
        account = (state.username, state.server_url, state.device_id)
        if not all(account):
            return
        self._outbox_management_active = True
        try:
            paths = attachment_outbox.pending_job_paths(*account)
            if not paths:
                QMessageBox.information(
                    self,
                    "Очередь вложений",
                    "Ожидающих загрузки вложений нет.",
                )
                return
            answer = QMessageBox.question(
                self,
                "Отменить очередь вложений?",
                f"Будет удалено ожидающих вложений: {len(paths)}. "
                "Локальные зашифрованные блобы очереди вложений будут удалены, "
                "а незавершённые серверные брони освобождены (история чата сохранится). "
                "Это действие необратимо. Продолжить?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            if (state.username, state.server_url, state.device_id) != account:
                QMessageBox.warning(
                    self,
                    "Отмена очереди вложений",
                    "Учётная запись изменилась; данные не удалены.",
                )
                return
            cancelled_file_ids = attachment_outbox.discard_jobs(paths, *account)
            for job_path in paths:
                self._attachment_skipped.discard(job_path.name)
                self._attachment_retry_after.pop(job_path.name, None)
            self._attachment_warning_shown = False
            self._dispatch_cancel_upload_reservations(cancelled_file_ids)
            self._render_history_page()
            QMessageBox.information(
                self,
                "Очередь вложений",
                "Ожидающие загрузки вложений отменены.",
            )
        except Exception as exc:
            print(f"[ATTACHMENT] Ошибка отмены очереди: {type(exc).__name__}")
            QMessageBox.warning(
                self,
                "Ошибка очереди вложений",
                "Не удалось отменить все вложения. Проверьте хранилище.",
            )
        finally:
            self._outbox_management_active = False

    def _confirm_clear_chat(self):
        name = (
            state.groups.get(state.current_group_id, {}).get("name")
            if state.current_chat_type == "group"
            else state.current_chat_username
        )
        if not name:
            return
        context = (state.username, state.server_url, state.device_id, state.token,
                   state.current_chat_type, state.current_group_id, state.current_chat_username)
        reply = QMessageBox.question(
            self, "Очистить историю?",
            "Вы уверены, что хотите удалить всю историю?\n\nЭто действие необратимо. Резервные копии и старые файлы могут сохраниться.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            if context != (state.username, state.server_url, state.device_id, state.token,
                           state.current_chat_type, state.current_group_id, state.current_chat_username):
                QMessageBox.warning(self, "Очистка отменена", "Чат или учётная запись изменились во время подтверждения.")
                return
            self._clear_chat()

    def _clear_chat(self):
        vc_mod = globals().get("voice_cache")
        scope_fn = globals().get("message_scope")
        list_ids_fn = getattr(storage, "list_message_ids", None)

        if state.current_chat_type == "group":
            group_id = state.current_group_id
            if group_id:
                chat_key = f"group_{group_id}"
                existing_ids = []
                if callable(list_ids_fn):
                    try:
                        existing_ids = list_ids_fn(state.username, chat_key)
                    except Exception:
                        existing_ids = []
                try:
                    storage.clear_chat(state.username, chat_key)
                except Exception as exc:
                    print(f"[HISTORY] Не удалось очистить историю: {type(exc).__name__}")
                    QMessageBox.warning(self, "История недоступна", "Не удалось подтвердить результат очистки. Проверьте хранилище и резервные копии.")
                    return
                if vc_mod is not None and callable(scope_fn) and getattr(state, "server_url", None):
                    for mid in set(existing_ids):
                        try:
                            vc_mod.delete_group(scope_fn(state.username, state.server_url, chat_key, mid))
                        except Exception:
                            pass
                img_cache = getattr(self, "_image_cache", None)
                del_prefix = getattr(img_cache, "delete_prefix", None)
                if callable(del_prefix):
                    del_prefix((
                        getattr(state, "username", None),
                        getattr(state, "device_id", None),
                        getattr(state, "server_url", None),
                        chat_key,
                    ))
                self._history_offset = 0
                self._history_query = None
                self._render_history_page()
                card = self._get_group_card(group_id)
                if card:
                    card.update_preview("Нет сообщений")
        else:
            ally_username = state.current_chat_username
            if not ally_username:
                return

            active_outbox_w = getattr(self, "_outbox_worker", None)
            active_outbox_hist = getattr(active_outbox_w, "local_history", None) if active_outbox_w else None
            if (active_outbox_w and active_outbox_w.isRunning()
                    and isinstance(active_outbox_hist, dict)
                    and active_outbox_hist.get("ally_username") == ally_username):
                QMessageBox.warning(
                    self,
                    "Отправка выполняется",
                    "Дождитесь завершения активной отправки сообщения перед очисткой истории.",
                )
                return

            for w in getattr(self, "_net_workers", ()):
                w_ctx = getattr(w, "recipient_context", None)
                if w_ctx is not None and getattr(w_ctx, "ally_username", None) == ally_username and w.isRunning():
                    QMessageBox.warning(
                        self,
                        "Вложение выгружается",
                        "Дождитесь завершения текущей выгрузки вложения перед очисткой истории.",
                    )
                    return

            existing_ids = []
            if callable(list_ids_fn):
                try:
                    existing_ids = list_ids_fn(state.username, ally_username)
                except Exception:
                    existing_ids = []

            acct = (
                getattr(state, "username", None),
                getattr(state, "server_url", None),
                getattr(state, "device_id", None),
            )
            cancelled_att_mids: list[str] = []
            cancelled_out_mids: list[str] = []
            if all(isinstance(v, str) and v for v in acct):
                att_mod = globals().get("attachment_outbox")
                cancel_att_ally = getattr(att_mod, "cancel_by_ally", None) if att_mod else None
                if callable(cancel_att_ally):
                    try:
                        cancelled_fids, cancelled_att_mids = cancel_att_ally(*acct, ally_username)
                    except Exception:
                        cancelled_fids, cancelled_att_mids = [], []
                    if cancelled_fids:
                        for fid in cancelled_fids:
                            jname = f"{fid}.job"
                            if hasattr(self, "_attachment_skipped"):
                                self._attachment_skipped.discard(jname)
                            if hasattr(self, "_attachment_retry_after"):
                                self._attachment_retry_after.pop(jname, None)
                        dispatch_cancel = getattr(self, "_dispatch_cancel_upload_reservations", None)
                        if callable(dispatch_cancel):
                            dispatch_cancel(cancelled_fids)

                out_mod = globals().get("outbox")
                cancel_out_ally = getattr(out_mod, "cancel_by_ally", None) if out_mod else None
                if callable(cancel_out_ally):
                    ally_devs = {
                        d.get("device_id")
                        for d in (getattr(state, "allies", {}) or {}).get(ally_username, {}).get("devices", [])
                        if isinstance(d, dict) and isinstance(d.get("device_id"), str) and d.get("device_id")
                    }
                    try:
                        removed_names, cancelled_out_mids = cancel_out_ally(*acct, ally_username, ally_devs)
                    except Exception:
                        removed_names, cancelled_out_mids = [], []
                    if removed_names and hasattr(self, "_outbox_skipped"):
                        self._outbox_skipped.difference_update(removed_names)

            try:
                storage.clear_chat(state.username, ally_username)
            except Exception as exc:
                print(f"[HISTORY] Не удалось очистить историю: {type(exc).__name__}")
                QMessageBox.warning(self, "История недоступна", "Не удалось подтвердить результат очистки. Проверьте хранилище и резервные копии.")
                return

            if vc_mod is not None and callable(scope_fn) and getattr(state, "server_url", None):
                for mid in set(existing_ids) | set(cancelled_att_mids) | set(cancelled_out_mids):
                    try:
                        vc_mod.delete_group(scope_fn(state.username, state.server_url, ally_username, mid))
                    except Exception:
                        pass

            img_cache = getattr(self, "_image_cache", None)
            del_prefix = getattr(img_cache, "delete_prefix", None)
            if callable(del_prefix):
                del_prefix((
                    getattr(state, "username", None),
                    getattr(state, "device_id", None),
                    getattr(state, "server_url", None),
                    ally_username,
                ))

            self._history_offset = 0
            self._history_query = None
            self._render_history_page()
            card = self._get_ally_card(ally_username)
            if card:
                card.update_preview("Нет сообщений")

    def _toggle_search(self):
        is_visible = self.search_bar.isVisible()
        self.search_bar.setVisible(not is_visible)
        if not is_visible:
            self.search_input.setFocus()
            self.search_input.clear()

    def _close_search(self):
        self.search_bar.setVisible(False)
        self.search_input.clear()
        self._history_offset = 0
        self._history_query = None
        self._render_history_page()

    def _load_group_message_history(self, group_id: str, messages):
        self._load_message_history(f"group_{group_id}", messages)

    def _do_search(self):
        query = self.search_input.text().strip()
        if not query:
            return
        self._history_query = query
        self._history_offset = 0
        self._render_history_page()

    def force_remove_group(self, group_id: str):
        if not isinstance(group_id, str):
            return
        # An unauthenticated server event or a delayed response must never
        # erase the only local copy of a group's history. Keep it readable in
        # this session and across restarts; explicit Clear History is separate.
        group = state.groups.get(group_id)
        if not group:
            return
        group["archived"] = True
        group["my_sender_key"] = None
        card = self._get_group_card(group_id)
        if card:
            card.setToolTip("Группа недоступна на сервере. Локальная история сохранена.")
        if state.current_chat_type == "group" and state.current_group_id == group_id:
            self.chat_title.setText(group.get("name", "Группа") + " (неактивна)")
            if hasattr(self, "msg_input"):
                self.msg_input.setEnabled(False)
                self.msg_input.setPlaceholderText("Группа неактивна — доступна только локальная история")
            for btn_name in ("attach_btn", "mic_input_btn", "send_btn"):
                btn = getattr(self, btn_name, None)
                if btn is not None:
                    btn.setEnabled(False)
        if hasattr(self, "_persist_groups_index"):
            self._persist_groups_index()

    def _group_action_context(self):
        return (state.username, state.server_url, state.device_id, state.token)

    def _delete_group_on_server(self):
        group_id = state.current_group_id
        if not group_id or state.groups.get(group_id, {}).get("archived"):
            return
        account = self._group_action_context()
        answer = QMessageBox.question(self, "Удалить группу?",
            "Группа и её данные будут удалены на сервере для всех участников. Локальная история будет сохранена.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        if (account != self._group_action_context()):
            return
        if state.current_chat_type != "group" or state.current_group_id != group_id or state.groups.get(group_id, {}).get("archived"):
            return
        worker = DeleteGroupWorker(state.server_url, state.token, group_id)
        worker.account_context = account
        worker.finished.connect(
            lambda s, d, gid, w=worker: self._on_group_deleted_response(s, d, gid, w),
            Qt.QueuedConnection
        )
        self._net_workers.append(worker)
        worker.start()

    def _leave_group_on_server(self):
        group_id = state.current_group_id
        if not group_id or state.groups.get(group_id, {}).get("archived"):
            return
        account = self._group_action_context()
        answer = QMessageBox.question(self, "Выйти из группы?",
            "Вы потеряете доступ к группе на сервере. Локальная история будет сохранена.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        if account != self._group_action_context() or state.current_chat_type != "group" or state.current_group_id != group_id or state.groups.get(group_id, {}).get("archived"):
            return
        worker = LeaveGroupWorker(state.server_url, state.token, group_id)
        worker.account_context = account
        worker.finished.connect(
            lambda s, d, gid, w=worker: self._on_group_left_response(s, d, gid, w),
            Qt.QueuedConnection
        )
        self._net_workers.append(worker)
        worker.start()

    def _finish_group_action(self, success, data, group_id, worker):
        worker.wait()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if worker.account_context != self._group_action_context() or worker.group_id != group_id:
            return
        if success:
            self.force_remove_group(group_id)
        else:
            QMessageBox.warning(self, "Ошибка", str(data))

    def _on_group_deleted_response(self, success, data, group_id, worker):
        self._finish_group_action(success, data, group_id, worker)

    def _on_group_left_response(self, success, data, group_id, worker):
        self._finish_group_action(success, data, group_id, worker)

    # ─────────────────────────────────────────────────────────────────
    # ГОЛОСОВЫЕ — ЗАПИСЬ
    # ─────────────────────────────────────────────────────────────────

    def _start_voice_recording(self):
        if self._is_recording:
            return
        if self._voice_thread and self._voice_thread.is_alive():
            QMessageBox.warning(self, "Микрофон ещё закрывается", "Дождитесь остановки предыдущей записи и попробуйте снова.")
            return
        try:
            self._voice_recipient_context = capture_recipient(state)
        except ValueError as e:
            QMessageBox.warning(self, "Запись недоступна", str(e))
            return
        self._is_recording  = True
        self._voice_cancelled = False
        self._voice_frames  = []
        self._show_voice_recording_bar()
        self._voice_recording_generation += 1
        generation = self._voice_recording_generation
        self._voice_thread = threading.Thread(target=self._record_voice, args=(generation,), daemon=True)
        try:
            self._voice_thread.start()
        except RuntimeError:
            self._is_recording = False
            self._hide_voice_recording_bar()
            QMessageBox.warning(self, "Запись недоступна", "Не удалось запустить запись с микрофона.")

    def _record_voice(self, generation):
        pa = None
        recorded_bytes = 0
        max_bytes = 120 * 16000 * 2  # Two minutes of 16-bit mono PCM.
        try:
            pa = pyaudio.PyAudio()
            self._voice_stream = pa.open(
                format=pyaudio.paInt16, channels=1, rate=16000,
                input=True, frames_per_buffer=1024,
            )
            while self._is_recording:
                data = self._voice_stream.read(1024, exception_on_overflow=False)
                if not self._is_recording:
                    break
                if not data or len(data) % 2:
                    raise RuntimeError("Микрофон вернул некорректные данные")
                data = data[:max_bytes - recorded_bytes]
                self._voice_frames.append(data)
                recorded_bytes += len(data)
                samples = struct.unpack(f"{len(data) // 2}h", data)
                rms = (sum(s * s for s in samples) / len(samples)) ** 0.5
                self._voice_level_signal.emit(generation, min(1.0, rms / 2000.0))
                if recorded_bytes >= max_bytes:
                    self._voice_recording_limit.emit(generation)
                    break
        except Exception as e:
            print(f"[VOICE] Ошибка записи: {type(e).__name__}")
            self._voice_recording_error.emit(generation, "Не удалось записать голосовое сообщение. Проверьте микрофон.")
        finally:
            if self._voice_stream:
                try:
                    self._voice_stream.stop_stream()
                    self._voice_stream.close()
                except Exception:
                    pass
                self._voice_stream = None
            if pa:
                pa.terminate()

    def _on_voice_recording_limit(self, generation):
        if self._is_recording and generation == self._voice_recording_generation:
            self.voice_recording_bar._sec_timer.stop()
            self.voice_recording_bar._rec_label.setText("Лимит 2 минуты. Отпустите кнопку для отправки.")

    def _on_voice_recording_error(self, generation, message):
        if self._is_recording and generation == self._voice_recording_generation:
            self._cancel_voice_recording()
            QMessageBox.warning(self, "Ошибка микрофона", message)

    def _stop_voice_recording(self):
        if not self._is_recording:
            return
        self._is_recording = False
        self._hide_voice_recording_bar()
        if self._voice_thread:
            self._voice_thread.join(timeout=1.0)
            if self._voice_thread.is_alive():
                self._voice_frames = []
                QMessageBox.warning(self, "Запись не отправлена", "Микрофон не остановился вовремя; запись отменена. Дождитесь остановки устройства.")
                return
        if self._voice_cancelled or len(self._voice_frames) < 8:
            self._voice_frames = []
            return
        wav_buffer = io.BytesIO()
        with wave.open(wav_buffer, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(16000)
            wf.writeframes(b"".join(self._voice_frames))
        voice_data = wav_buffer.getvalue()
        duration = sum(map(len, self._voice_frames)) / (16000 * 2)
        self._voice_frames = []
        context = getattr(self, "_voice_recipient_context", None)
        if not context or not is_active_recipient(state, context):
            QMessageBox.warning(self, "Отправка отменена", "Чат или ключ контакта изменился во время записи.")
            return
        self._send_voice_message(voice_data, duration, context)

    def _cancel_voice_recording(self):
        self._voice_cancelled = True
        self._is_recording    = False
        self._hide_voice_recording_bar()
        if self._voice_thread:
            self._voice_thread.join(timeout=1.0)
        self._voice_frames = []

    def _send_voice_message(self, voice_data: bytes, duration: float, context):
        self._queue_attachment(voice_data, context, "voice", duration=duration)

    def _prepare_voice_bubble(self, bubble, file_id, secret_key, msg_id):
        bubble._voice_descriptor = (self._media_context(), file_id, secret_key, msg_id)
        bubble._voice_loading = False

    def _download_voice_for_bubble(self, bubble, file_id: str,
                                   secret_key: str, msg_id: str):
        worker = DownloadFileWorker(state.server_url, state.token, file_id)
        worker.secret_key = secret_key
        worker.bubble = bubble
        worker.is_voice = True
        worker.msg_id = msg_id
        worker.voice_request_serial = self._voice_request_serial
        bubble._voice_loading = True
        bubble.msg_label.setText("Загрузка голосового…")
        bubble.msg_label.setVisible(True)
        try:
            worker.voice_group = message_scope(state.username, state.server_url, state.current_chat_username, msg_id)
            worker.voice_asset = asset_scope(file_id, secret_key)
        except (TypeError, ValueError):
            bubble._voice_loading = False
            bubble.msg_label.setText("Некорректные данные голосового сообщения")
            return

        worker.finished.connect(
            lambda w=worker: self._on_voice_download_finished(*w.result, w),
            Qt.QueuedConnection
        )

        self._queue_media_download(worker)

    def _on_voice_download_finished(self, success: bool, data: bytes, worker):
        if not self._finish_media_download(worker):
            return
        if not success:
            self._media_download_failed(worker)
            return
        try:
            if not worker.bubble or not worker.bubble.parent():
                return
            decrypted_bytes = crypto.decrypt_file(data, worker.secret_key)
            worker.bubble._voice_loading = False
            worker.bubble.msg_label.setVisible(False)
            voice_cache.save(worker.voice_group, worker.voice_asset, decrypted_bytes)
            if worker.voice_request_serial == self._voice_request_serial:
                worker.bubble.set_voice_data(decrypted_bytes)
                self._play_voice_message(worker.bubble, decrypted_bytes, _from_download=True)
        except Exception as e:
            print(f"[VOICE] Ошибка расшифровки: {type(e).__name__}")
            self._media_download_failed(worker)

    # ─────────────────────────────────────────────────────────────────
    # ГОЛОСОВЫЕ — ВОСПРОИЗВЕДЕНИЕ
    # ─────────────────────────────────────────────────────────────────

    def _play_voice_message(self, bubble: MessageBubble, voice_data: bytes, _from_download=False):
        if not _from_download:
            self._voice_request_serial += 1
        if not voice_data:
            descriptor = getattr(bubble, "_voice_descriptor", None)
            if not descriptor or descriptor[0] != self._media_context():
                return
            if getattr(bubble, "_voice_loading", False):
                # A second click while this same request is pending should not
                # invalidate it; the user can retry via the error link on failure.
                self._voice_request_serial -= 1
                return
            _, file_id, secret_key, msg_id = descriptor
            try:
                group = message_scope(state.username, state.server_url, state.current_chat_username, msg_id)
                asset = asset_scope(file_id, secret_key)
                voice_data = voice_cache.load(group, asset)
            except (TypeError, ValueError):
                group, asset, voice_data = None, None, None
            if not voice_data and getattr(bubble, "is_mine", False):
                voice_data = attachment_outbox.load_pending_plaintext(
                    getattr(state, "username", None),
                    getattr(state, "server_url", None),
                    getattr(state, "device_id", None),
                    file_id,
                    secret_key,
                )
                if voice_data and group and asset:
                    try:
                        voice_cache.save(group, asset, voice_data)
                    except Exception:
                        pass
            if not voice_data:
                self._download_voice_for_bubble(bubble, file_id, secret_key, msg_id)
                return
            bubble.set_voice_data(voice_data)

        # Keep only the current voice payload among visible bubbles; cached
        # messages can be reloaded when the user presses play again.
        for i in range(self.messages_layout.count() - 1):
            other = self.messages_layout.itemAt(i).widget()
            if other is not bubble and getattr(other, "_voice_descriptor", None):
                other._voice_data = None
        if self._current_playing_bubble == bubble and bubble._is_playing:
            self._stop_voice_playback()
            return
        self._start_playback(bubble, voice_data, 0.0)

    def _stop_voice_playback(self):
        self._voice_request_serial += 1  # Invalidate delayed voice downloads too.
        self._voice_playback_generation = self._voice_playback.stop()
        bubble, self._current_playing_bubble = self._current_playing_bubble, None
        if bubble:
            try:
                bubble.set_playing(False)
                bubble.update_playback_progress(0)
            except RuntimeError:
                pass

    def _seek_voice_message(self, bubble: MessageBubble, progress: float):
        if not bubble._voice_data:
            return
        self._voice_request_serial += 1
        self._start_playback(bubble, bubble._voice_data, progress)

    def _start_playback(self, bubble: MessageBubble, voice_data: bytes,
                        start_progress: float = 0.0):
        try:
            generation = self._voice_playback.start(voice_data, start_progress)
        except (ValueError, RuntimeError) as exc:
            print(f"[VOICE] Не удалось начать воспроизведение: {type(exc).__name__}")
            return
        previous = self._current_playing_bubble
        if previous is not None and previous is not bubble:
            try:
                previous.set_playing(False)
                previous.update_playback_progress(0)
            except RuntimeError:
                pass
        self._voice_playback_generation = generation
        self._current_playing_bubble = bubble
        try:
            bubble.set_playing(True)
        except RuntimeError:
            self._stop_voice_playback()

    def _on_voice_playback_finished(self, generation):
        if generation != self._voice_playback_generation:
            return
        bubble, self._current_playing_bubble = self._current_playing_bubble, None
        if bubble:
            try:
                bubble.set_playing(False)
                bubble.update_playback_progress(0)
            except RuntimeError:
                pass

    def _do_create_group(self, name: str, member_usernames: list):
        if not GROUP_CHAT_SEND_ENABLED:
            QMessageBox.warning(
                self, "Групповые чаты временно недоступны",
                "Создание групп приостановлено."
            )
            return
        clean_name = (name or "").strip()
        if not clean_name:
            QMessageBox.warning(self, "Ошибка", "Введите название группы.")
            return

        # Resolve and verify at least one trusted device per selected contact.
        target_devices = []
        seen_dev_ids = set()
        for username in member_usernames:
            ally = state.allies.get(username)
            if not ally or not ally.get("devices"):
                continue
            pref_dev_id = self._resolve_preferred_contact_device_id(username, ally)
            if not pref_dev_id:
                pref_dev_id = ally["devices"][-1].get("device_id")
            if not pref_dev_id:
                continue
            if not self._verify_call_contact(username, pref_dev_id):
                return
            # Include all verified devices of this contact (or the just-verified preferred device).
            for dev in ally.get("devices", []):
                did = dev.get("device_id")
                pub = dev.get("public_key")
                if not did or not pub or did == state.device_id or did in seen_dev_ids:
                    continue
                if did == pref_dev_id or recipient_is_verified(state, dev):
                    seen_dev_ids.add(did)
                    target_devices.append(dev)

        if not target_devices:
            self.create_group_panel.setEnabled(True)
            QMessageBox.warning(self, "Ошибка", "Не удалось найти проверенные устройства участников.")
            return

        self.create_group_panel.setEnabled(False)
        my_sender_key = group_crypto.generate_sender_key(group_id="", epoch=1)
        sender_keys_payload = []
        member_device_ids = []

        for target_device in target_devices:
            dev_id = target_device["device_id"]
            member_device_ids.append(dev_id)
            enc_blob, sig = group_crypto.encrypt_sender_key_for_member(
                my_sender_key,
                target_device["public_key"],
                group_id="",
                sender_device_id=state.device_id,
                recipient_device_id=dev_id,
                group_name=clean_name,
            )
            sender_keys_payload.append({
                "sender_device_id": state.device_id,
                "recipient_device_id": dev_id,
                "encrypted_sender_key": enc_blob,
                "sender_key_signature": sig,
            })

        # Server stores only the fixed opaque placeholder "[E2EE]"; the real group
        # title travels strictly inside the padded E2EE SenderKey bundles.
        payload = {
            "name": SERVER_GROUP_NAME_PLACEHOLDER,
            "member_device_ids": member_device_ids,
            "sender_keys": sender_keys_payload,
        }
        worker = CreateGroupWorker(state.server_url, state.token, payload)
        worker.account_context = (state.username, state.server_url, state.device_id, state.token)
        worker._my_sender_key = my_sender_key
        worker._real_group_name = clean_name
        worker.finished.connect(
            lambda s, d, w=worker: self._on_group_created_on_server(s, d, w),
            Qt.QueuedConnection
        )
        self._net_workers.append(worker)
        worker.start()

    def _on_group_created_on_server(self, success: bool, data, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        self.create_group_panel.setEnabled(True)
        if getattr(worker, "account_context", None) != (
            state.username, state.server_url, state.device_id, state.token
        ):
            return

        if not success or not isinstance(data, dict):
            QMessageBox.warning(self, "Ошибка", f"Не удалось создать группу:\n{data}")
            return

        group_id = data["id"]
        epoch = int(data.get("epoch", 1) or 1)
        my_sender_key = worker._my_sender_key
        my_sender_key["group_id"] = group_id
        my_sender_key["epoch"] = epoch
        real_name = getattr(worker, "_real_group_name", "") or data.get("name", "") or f"Группа {group_id[:8]}"

        state.groups[group_id] = {
            "name": real_name,
            "created_by_device_id": data["created_by_device_id"],
            "epoch": epoch,
            "members": data.get("members", []),
            "archived": False,
            "my_sender_key": my_sender_key,
            "distributed_epoch": 0,
            "sender_keys": {},
        }
        if hasattr(self, "_persist_groups_index"):
            self._persist_groups_index()
        # Immediately publish group_id-bound v2 SenderKey bundle to all members.
        self.ensure_my_group_sender_key(group_id, force_rotate=False, target_epoch=epoch)
        self._save_group_keys_safe()

        self._add_group_card(group_id, real_name)
        self._hide_create_group_panel()
        self._switch_sidebar_tab("groups")

        new_item = self._get_group_item(group_id)
        if new_item:
            self._on_group_selected(new_item)

    def _invite_member_to_current_group(self):
        group_id = state.current_group_id
        if state.current_chat_type != "group" or not group_id:
            return
        group_data = state.groups.get(group_id)
        if not group_data or group_data.get("archived"):
            return

        existing_devs = {
            (m.get("device_id") if isinstance(m, dict) else m)
            for m in (group_data.get("members") or [])
        }
        candidates = []
        for uname, info in sorted(state.allies.items()):
            for dev in info.get("devices", []):
                if dev.get("device_id") and dev.get("device_id") not in existing_devs:
                    candidates.append(uname)
                    break

        if not candidates:
            QMessageBox.information(
                self,
                "Приглашение в группу",
                "Все ваши контакты уже состоят в этой группе (или сначала добавьте контакт во вкладке чатов).",
            )
            return

        chosen_uname, ok = QInputDialog.getItem(
            self,
            "Пригласить участника (E2EE)",
            "Выберите контакт для добавления в группу:",
            candidates,
            0,
            False,
        )
        if not ok or not chosen_uname:
            return
        if state.current_chat_type != "group" or state.current_group_id != group_id:
            return

        ally = state.allies.get(chosen_uname)
        if not ally or not ally.get("devices"):
            return
        pref_dev_id = self._resolve_preferred_contact_device_id(chosen_uname, ally) or ally["devices"][-1].get("device_id")
        if not pref_dev_id or not self._verify_call_contact(chosen_uname, pref_dev_id):
            return
        target_dev = next((d for d in ally["devices"] if d.get("device_id") == pref_dev_id), None)
        if not target_dev or not target_dev.get("public_key"):
            return

        new_epoch = int(group_data.get("epoch", 1) or 1) + 1
        rotated_sk = group_crypto.generate_sender_key(group_id=group_id, epoch=new_epoch)

        recipient_pubs = {pref_dev_id: target_dev["public_key"]}
        for m in group_data.get("members") or []:
            did = m.get("device_id") if isinstance(m, dict) else m
            if not did or did == state.device_id:
                continue
            pub, _lbl = self._resolve_group_member_pub_and_name(group_id, did)
            if not pub:
                self._fetch_group_members_and_rotate(group_id)
                QMessageBox.information(
                    self,
                    "Обновление состава",
                    "Список ключей участников обновлён с сервера. Повторите приглашение.",
                )
                return
            recipient_pubs[did] = pub

        sk_entries = []
        for rec_id, rec_pub in recipient_pubs.items():
            enc_blob, sig = group_crypto.encrypt_sender_key_for_member(
                rotated_sk,
                rec_pub,
                group_id=group_id,
                sender_device_id=state.device_id,
                recipient_device_id=rec_id,
                group_name=group_data.get("name", ""),
            )
            sk_entries.append(
                {
                    "sender_device_id": state.device_id,
                    "recipient_device_id": rec_id,
                    "encrypted_sender_key": enc_blob,
                    "sender_key_signature": sig,
                }
            )

        worker = InviteGroupMemberWorker(
            state.server_url,
            state.token,
            {
                "group_id": group_id,
                "new_member_device_id": pref_dev_id,
                "sender_keys": sk_entries,
            },
        )
        worker.account_context = (state.username, state.server_url, state.device_id, state.token)
        worker._rotated_sk = rotated_sk
        worker._new_member_info = {
            "device_id": pref_dev_id,
            "device_name": target_dev.get("device_name", chosen_uname),
            "public_key": target_dev["public_key"],
            "role": "member",
        }
        worker.finished.connect(
            lambda ok_res, res, gid, w=worker: self._on_group_invite_finished(ok_res, res, gid, w),
            Qt.QueuedConnection,
        )
        self._net_workers.append(worker)
        worker.start()

    def _on_group_invite_finished(self, success: bool, data, group_id: str, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if getattr(worker, "account_context", None) != (
            state.username, state.server_url, state.device_id, state.token
        ):
            return
        if not success or group_id not in state.groups:
            QMessageBox.warning(self, "Ошибка приглашения", f"Не удалось пригласить участника:\n{data}")
            return
        eff_epoch = int((data or {}).get("epoch", 2) if isinstance(data, dict) else 2)
        gdata = state.groups[group_id]
        gdata["epoch"] = eff_epoch
        worker._rotated_sk["epoch"] = eff_epoch
        gdata["my_sender_key"] = worker._rotated_sk
        gdata["distributed_epoch"] = eff_epoch
        members = gdata.setdefault("members", [])
        if not any(isinstance(m, dict) and m.get("device_id") == worker._new_member_info["device_id"] for m in members):
            members.append(worker._new_member_info)
        self._save_group_keys_safe()

    def ingest_sender_key_entry(
        self,
        group_id: str,
        sender_device_id: str,
        encrypted_sender_key: str,
        sender_key_signature: str,
        epoch: int = 1,
    ) -> bool:
        if group_id not in state.groups or not sender_device_id or sender_device_id == state.device_id:
            return False
        sender_pub, _label = self._resolve_group_member_pub_and_name(group_id, sender_device_id)
        if not sender_pub:
            return False
        decrypted_sk = group_crypto.decrypt_sender_key(
            encrypted_sender_key,
            sender_key_signature,
            sender_pub,
            expected_group_id="",  # Initial create bundle may carry "" before server assigns group_id
            expected_sender_device_id=sender_device_id,
            expected_recipient_device_id=state.device_id,
            min_epoch=1,
        )
        if not decrypted_sk:
            return False
        if decrypted_sk.get("group_id") and decrypted_sk["group_id"] != group_id:
            return False
        decrypted_sk["group_id"] = group_id
        unsealed_name = decrypted_sk.pop("group_name", None)
        gdata = state.groups[group_id]
        if isinstance(unsealed_name, str) and unsealed_name:
            cur_name = str(gdata.get("name", "") or "")
            is_owner_sender = bool(gdata.get("created_by_device_id")) and sender_device_id == gdata.get("created_by_device_id")
            is_placeholder = (not cur_name) or cur_name == SERVER_GROUP_NAME_PLACEHOLDER or cur_name.startswith("Группа ")
            if is_owner_sender or is_placeholder:
                gdata["name"] = unsealed_name
                if hasattr(self, "_persist_groups_index"):
                    self._persist_groups_index()
                card = self._get_group_card(group_id) if hasattr(self, "_get_group_card") else None
                if card is not None:
                    if hasattr(card, "name_label"):
                        card.name_label.setText(unsealed_name)
                    if hasattr(card, "avatar"):
                        card.avatar.setText(unsealed_name[0].upper())
                if getattr(state, "current_chat_type", None) == "group" and getattr(state, "current_group_id", None) == group_id:
                    if hasattr(self, "chat_title"):
                        self.chat_title.setText(unsealed_name)
        sk_epoch = int(decrypted_sk.get("epoch", epoch) or 1)
        if sk_epoch > int(gdata.get("epoch", 1) or 1):
            gdata["epoch"] = sk_epoch
        store_member_sender_key(gdata, sender_device_id, decrypted_sk)
        self._save_group_keys_safe()
        self._drain_deferred_group_messages(group_id)
        return True

    def _queue_group_ack(self, message_ids: list):
        if not message_ids or not state.token:
            return
        worker = AcknowledgeGroupMessagesWorker(state.server_url, state.token, message_ids)
        worker.finished.connect(
            lambda _ok, _res, w=worker: self._net_workers.remove(w) if w in self._net_workers else None,
            Qt.QueuedConnection,
        )
        self._net_workers.append(worker)
        worker.start()

    def _request_group_sender_keys(self, group_id: str):
        win = self.window()
        fetch_fn = getattr(win, "fetch_sender_keys_for_group", None)
        if callable(fetch_fn):
            fetch_fn(group_id)

    def _drain_deferred_group_messages(self, group_id: str):
        deferred_map = getattr(self, "_deferred_group_messages", None)
        if not deferred_map or group_id not in deferred_map:
            return
        pending = list(deferred_map.pop(group_id, []))
        still_waiting = []
        acked = []
        for raw_msg in pending:
            if self.process_incoming_group_message(raw_msg, _from_deferred=True):
                mid = raw_msg.get("id") or raw_msg.get("message_id")
                if mid:
                    acked.append(mid)
            else:
                still_waiting.append(raw_msg)
        if still_waiting:
            deferred_map[group_id] = still_waiting[:256]
        if acked:
            self._queue_group_ack(acked)

    def process_incoming_group_message(self, data: dict, *, _from_deferred: bool = False) -> bool:
        """Verify, decrypt, persist, and render an incoming v2 group message.
        Returns True ONLY when durably stored (safe to ACK on server)."""
        if not isinstance(data, dict) or not state.username:
            return False
        group_id = data.get("group_id", "")
        sender_dev = data.get("sender_device_id", "")
        enc_blob = data.get("encrypted_blob", "")
        sig_b64 = data.get("signature", "")
        key_id = data.get("sender_key_id", "")
        chain_index = data.get("chain_index")
        msg_epoch = int(data.get("epoch", 1) or 1)
        server_msg_id = str(data.get("id") or data.get("message_id") or "")

        if not group_id or not sender_dev or not enc_blob or not key_id or chain_index is None:
            return False
        if sender_dev == state.device_id:
            return True

        seen_ids = getattr(self, "_seen_group_msg_ids", None)
        if seen_ids is None:
            self._seen_group_msg_ids = seen_ids = set()
        if server_msg_id and server_msg_id in seen_ids:
            return True

        if group_id not in state.groups:
            if not _from_deferred:
                self._defer_group_message(group_id, data)
                win = self.window()
                if hasattr(win, "_refresh_groups_from_server"):
                    win._refresh_groups_from_server()
            return False

        group_data = state.groups[group_id]
        sender_pub, sender_label = self._resolve_group_member_pub_and_name(group_id, sender_dev)
        sk_state = lookup_member_sender_key(group_data, sender_dev, key_id)

        if not sender_pub or not sk_state:
            if not _from_deferred:
                self._defer_group_message(group_id, data)
                self._fetch_group_members_and_rotate(group_id)
                self._request_group_sender_keys(group_id)
            return False

        enc_arg = {
            "blob": enc_blob,
            "key_id": key_id,
            "epoch": msg_epoch,
            "chain_index": chain_index,
            "signature": sig_b64,
        }
        dec_env_fn = getattr(group_crypto, "decrypt_group_message_envelope", None)
        group_ttl_kw = {}
        env_msg_id = None
        if callable(dec_env_fn):
            dec_env = dec_env_fn(
                enc_arg,
                sk_state,
                expected_group_id=group_id,
                expected_sender_device_id=sender_dev,
                sender_public_key_b64=sender_pub,
            )
            if not isinstance(dec_env, dict):
                return False
            plaintext = dec_env.get("text")
            env_msg_id = dec_env.get("msg_id")
            g_ttl = dec_env.get("ttl_seconds")
            if isinstance(g_ttl, int) and not isinstance(g_ttl, bool) and g_ttl >= 5:
                import time as _time
                group_ttl_kw["expires_at"] = int(_time.time() + g_ttl)
        else:
            plaintext = group_crypto.decrypt_group_message(
                enc_arg,
                sk_state,
                expected_group_id=group_id,
                expected_sender_device_id=sender_dev,
                sender_public_key_b64=sender_pub,
            )
        if plaintext is None:
            return False

        effective_sender_name = sender_label or sender_dev[:8]
        is_active_group = (state.current_chat_type == "group" and state.current_group_id == group_id)

        if plaintext.startswith("[EDIT_MSG]|"):
            parts = plaintext.split("|", 2)
            if len(parts) == 3 and 1 <= len(parts[1]) <= 256 and 1 <= len(parts[2]) <= 256 * 1024:
                edit_fn = getattr(storage, "edit_message", None)
                if callable(edit_fn):
                    edit_fn(
                        state.username,
                        f"group_{group_id}",
                        parts[1],
                        parts[2],
                        only_incoming=True,
                        expected_sender_name=effective_sender_name,
                    )
                if server_msg_id:
                    seen_ids.add(server_msg_id)
                self._save_group_keys_safe()
                if is_active_group:
                    self._render_history_page()
                return True
            return False

        if plaintext.startswith("[PIN_MSG]|"):
            parts = plaintext.split("|", 2)
            if len(parts) == 3 and len(parts[1]) <= 256 and len(parts[2]) <= 1024:
                set_pin_fn = getattr(storage, "set_pinned_message", None)
                if callable(set_pin_fn):
                    pin_obj = {"msg_id": parts[1], "preview": parts[2]} if parts[1] else None
                    set_pin_fn(state.username, f"group_{group_id}", pin_obj)
                if server_msg_id:
                    seen_ids.add(server_msg_id)
                self._save_group_keys_safe()
                if is_active_group and hasattr(self, "_refresh_pinned_banner"):
                    self._refresh_pinned_banner()
                return True
            return False

        local_msg_id = (
            env_msg_id
            if isinstance(env_msg_id, str) and env_msg_id
            else (f"gmsg_{server_msg_id}" if server_msg_id else f"gmsg_{uuid.uuid4().hex[:16]}")
        )

        saved = storage.save_message(
            state.username,
            f"group_{group_id}",
            plaintext,
            is_mine=False,
            msg_id=local_msg_id,
            is_read=is_active_group,
            sender_name=effective_sender_name,
            **group_ttl_kw,
        )
        if not saved:
            return False

        if server_msg_id:
            seen_ids.add(server_msg_id)
            if len(seen_ids) > 4096:
                seen_ids.pop()
        self._save_group_keys_safe()

        card = self._get_group_card(group_id)
        if card:
            card.update_preview(f"{sender_label or sender_dev[:6]}: {plaintext}")
            if not is_active_group:
                card.increment_unread()

        if is_active_group:
            bubble = MessageBubble(text=plaintext, is_mine=False, is_read=True)
            bubble.msg_id = local_msg_id
            if sender_label:
                bubble.set_sender(sender_label)
            self._connect_bubble_signals(bubble, sender_label or sender_dev[:8])
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)
            QTimer.singleShot(
                50,
                lambda: self.messages_scroll.verticalScrollBar().setValue(
                    self.messages_scroll.verticalScrollBar().maximum()
                ),
            )
        else:
            win = self.window()
            if hasattr(win, "show_notification"):
                win.show_notification(group_data.get("name", "Группа"), plaintext, is_group=True)

        if not _from_deferred and server_msg_id:
            self._queue_group_ack([server_msg_id])
        return True

    def _defer_group_message(self, group_id: str, data: dict):
        deferred_map = getattr(self, "_deferred_group_messages", None)
        if deferred_map is None:
            self._deferred_group_messages = deferred_map = {}
        bucket = deferred_map.setdefault(group_id, [])
        mid = data.get("id") or data.get("message_id")
        if mid and any((x.get("id") or x.get("message_id")) == mid for x in bucket):
            return
        if len(bucket) < 256:
            bucket.append(data)

    def process_group_created_event(self, data: dict):
        if not isinstance(data, dict):
            return
        group_id = data.get("group_id", "")
        if not group_id:
            return
        raw_ev_name = data.get("group_name") or ""
        if raw_ev_name == SERVER_GROUP_NAME_PLACEHOLDER:
            raw_ev_name = ""
        group_name = raw_ev_name or state.groups.get(group_id, {}).get("name") or f"Группа {group_id[:8]}"
        epoch = int(data.get("epoch", 1) or 1)
        created_by = data.get("created_by") or data.get("invited_by") or ""

        if group_id not in state.groups:
            state.groups[group_id] = {
                "name": group_name,
                "created_by_device_id": created_by,
                "epoch": epoch,
                "members": [],
                "archived": False,
                "my_sender_key": None,
                "distributed_epoch": 0,
                "sender_keys": {},
            }
        else:
            state.groups[group_id]["archived"] = False
            if raw_ev_name or not state.groups[group_id].get("name"):
                state.groups[group_id]["name"] = group_name
            state.groups[group_id]["epoch"] = max(int(state.groups[group_id].get("epoch", 1) or 1), epoch)

        if not self._get_group_item(group_id):
            self._add_group_card(group_id, group_name)
        self._persist_groups_index()

        # Fetch authoritative member public keys, ingest any inline sender keys, and publish our own v2 SenderKey!
        self._fetch_group_members_and_rotate(group_id, target_epoch=epoch)
        self._request_group_sender_keys(group_id)

    def process_group_sender_key_updated(self, data: dict):
        if not isinstance(data, dict):
            return
        group_id = data.get("group_id", "")
        sender_dev = data.get("sender_device_id", "")
        enc_sk = data.get("encrypted_sender_key", "")
        sig = data.get("sender_key_signature", "")
        epoch = int(data.get("epoch", 1) or 1)
        if not group_id or not sender_dev or not enc_sk:
            return
        if not self.ingest_sender_key_entry(group_id, sender_dev, enc_sk, sig, epoch=epoch):
            self._fetch_group_members_and_rotate(group_id, target_epoch=epoch)
            self._request_group_sender_keys(group_id)

    def process_group_member_joined(self, data: dict):
        if not isinstance(data, dict):
            return
        group_id = data.get("group_id", "")
        if not group_id or group_id not in state.groups:
            return
        new_epoch = int(data.get("epoch", int(state.groups[group_id].get("epoch", 1) or 1) + 1))
        state.groups[group_id]["epoch"] = new_epoch
        self._fetch_group_members_and_rotate(
            group_id,
            force_rotate=bool(data.get("rotation_required", True)),
            target_epoch=new_epoch,
        )

    def process_group_member_left(self, data: dict):
        if not isinstance(data, dict):
            return
        group_id = data.get("group_id", "")
        left_dev = data.get("left_device_id", "")
        if not group_id or group_id not in state.groups:
            return
        new_epoch = int(data.get("epoch", int(state.groups[group_id].get("epoch", 1) or 1) + 1))
        gdata = state.groups[group_id]
        gdata["epoch"] = new_epoch
        if left_dev and isinstance(gdata.get("members"), list):
            gdata["members"] = [
                m for m in gdata["members"]
                if (m.get("device_id") if isinstance(m, dict) else m) != left_dev
            ]
        # Mandatory SenderKey rotation so departed device cannot read any new messages!
        self._fetch_group_members_and_rotate(
            group_id,
            force_rotate=True,
            target_epoch=new_epoch,
        )

    def _on_image_preview_send(self, file_data: bytes, caption: str):
        context = getattr(self, "_image_recipient_context", None)
        if isinstance(context, tuple) and len(context) == 2 and context[0] == "group_image":
            gid = context[1]
            if state.current_chat_type != "group" or state.current_group_id != gid:
                QMessageBox.warning(self, "Отправка отменена", "Группа изменилась. Выберите изображение заново.")
                return
            self.image_preview_panel.setVisible(False)
            self.image_preview_panel.clear()
            self.input_area.setVisible(True)
            self._image_recipient_context = None
            self._send_group_attachment(gid, file_data, "image", caption=caption)
            return
        if not context or not is_active_recipient(state, context):
            QMessageBox.warning(self, "Отправка отменена", "Чат или ключ контакта изменился. Выберите файл заново.")
            return
        if not self._verify_call_contact(context.username, context.device_id):
            return
        if not is_active_recipient(state, context):
            QMessageBox.warning(self, "Отправка отменена", "Чат или ключ контакта изменился во время проверки.")
            return
        self.image_preview_panel.setVisible(False)
        self.image_preview_panel.clear()
        self.input_area.setVisible(True)
        context = getattr(self, "_image_recipient_context", None)
        self._image_recipient_context = None
        self._prepare_file_for_upload(file_data, caption=caption, context=context)

    def _on_image_preview_cancel(self):
        self._image_recipient_context = None
        self.image_preview_panel.setVisible(False)
        self.image_preview_panel.clear()
        self.input_area.setVisible(True)
        self.msg_input.setFocus()

    def _show_image_preview(self, file_data: bytes, context=None):
        if isinstance(context, tuple) and len(context) == 2 and context[0] == "group_image":
            self._image_recipient_context = context
        else:
            try:
                self._image_recipient_context = context or capture_recipient(state)
            except ValueError as e:
                QMessageBox.warning(self, "Отправка недоступна", str(e))
                return
        self.image_preview_panel.set_image(file_data)
        self.image_preview_panel.setVisible(True)
        self.input_area.setVisible(False)

    def _show_voice_recording_bar(self):
        self.input_area.setVisible(False)
        self.image_preview_panel.setVisible(False)
        self.voice_recording_bar.start()
        self.voice_recording_bar.setVisible(True)

    def _hide_voice_recording_bar(self):
        self.voice_recording_bar.stop()
        self.voice_recording_bar.setVisible(False)
        self.input_area.setVisible(True)

    def _on_voice_level_update(self, generation, rms: float):
        if self._is_recording and generation == self._voice_recording_generation:
            self.voice_recording_bar.push_level(rms)

    def _on_text_changed(self):
        has_text = bool(self.msg_input.toPlainText().strip())
        if has_text and not self._showing_send_btn:
            self._showing_send_btn = True
            self._action_btn_stack.setCurrentIndex(1)
            self._fade_mic_out_anim.stop()
            self._fade_to_send_anim.stop()
            self._fade_to_send_anim.start()
        elif not has_text and self._showing_send_btn:
            self._showing_send_btn = False
            self._action_btn_stack.setCurrentIndex(0)
            self._fade_send_out_anim.stop()
            self._fade_to_mic_anim.stop()
            self._fade_to_mic_anim.start()

    def _on_voice_progress_update(self, generation, progress: float):
        if generation != self._voice_playback_generation:
            return
        bubble = self._current_playing_bubble
        if bubble:
            try:
                bubble.update_playback_progress(progress)
            except RuntimeError:
                self._stop_voice_playback()

    # ─────────────────────────────────────────────────────────────────
    # CALL UI & CORE (Discord-like: mini widget → expand on click)
    # ─────────────────────────────────────────────────────────────────

    def _init_call_ui(self):
        self._call_expanded = False

        # ── CallWidget: маленькая плавающая плашка (по умолчанию) ──
        self.call_widget = QFrame(self)
        self.call_widget.setObjectName("CallWidget")
        self.call_widget.setFixedHeight(56)
        self.call_widget.setCursor(Qt.PointingHandCursor)
        self.call_widget.mousePressEvent = self._toggle_call_expand

        cw_layout = QHBoxLayout(self.call_widget)
        cw_layout.setContentsMargins(12, 0, 12, 0)
        cw_layout.setSpacing(10)

        self._cw_avatar = QFrame()
        self._cw_avatar.setObjectName("CallWidgetAvatar")
        self._cw_avatar.setFixedSize(36, 36)
        self._cw_avatar_label = QLabel(self._cw_avatar)
        self._cw_avatar_label.setObjectName("CallWidgetAvatarText")
        self._cw_avatar_label.setAlignment(Qt.AlignCenter)
        self._cw_avatar_label.setGeometry(0, 0, 36, 36)

        self._cw_name = QLabel("@user")
        self._cw_name.setObjectName("CallWidgetName")

        self._cw_status = QLabel("Звонок...")
        self._cw_status.setObjectName("CallWidgetStatus")

        self._cw_end_btn = ThemedIconButton(str(ICONS_PATH / "call_end.svg"), 36, 16)
        self._cw_end_btn.setObjectName("CallWidgetEndBtn")
        self._cw_end_btn.clicked.connect(self._on_end_call)

        self._cw_expand_btn = ThemedIconButton(str(ICONS_PATH / "maximize.svg"), 36, 16)
        self._cw_expand_btn.setObjectName("CallWidgetExpandBtn")
        self._cw_expand_btn.setToolTip("Раскрыть")
        self._cw_expand_btn.clicked.connect(self._toggle_call_expand)

        cw_layout.addWidget(self._cw_avatar)
        cw_layout.addWidget(self._cw_name)
        cw_layout.addWidget(self._cw_status)
        cw_layout.addStretch()
        cw_layout.addWidget(self._cw_expand_btn)
        cw_layout.addWidget(self._cw_end_btn)

        self.call_widget.hide()

        # ── CallExpanded: расширенная панель с контролами ──
        self.call_expanded = QFrame(self)
        self.call_expanded.setObjectName("CallExpanded")
        self.call_expanded.hide()

        ce_layout = QVBoxLayout(self.call_expanded)
        ce_layout.setContentsMargins(0, 0, 0, 0)
        ce_layout.setSpacing(0)

        # Верхняя часть — аватар + статус
        self._ce_center = QFrame()
        self._ce_center.setObjectName("CallScreenCenter")
        ce_center_layout = QVBoxLayout(self._ce_center)
        ce_center_layout.setContentsMargins(0, 0, 0, 0)
        ce_center_layout.setAlignment(Qt.AlignCenter)
        ce_center_layout.setSpacing(12)

        self._ce_collapse_btn = ThemedIconButton(str(ICONS_PATH / "minimize.svg"), 36, 16)
        self._ce_collapse_btn.setObjectName("CallWidgetExpandBtn")
        self._ce_collapse_btn.setToolTip("Свернуть")
        self._ce_collapse_btn.clicked.connect(self._collapse_call)

        collapse_row = QHBoxLayout()
        collapse_row.setContentsMargins(0, 12, 0, 0)
        collapse_row.addStretch()
        collapse_row.addWidget(self._ce_collapse_btn)
        collapse_row.addStretch()
        ce_center_layout.addLayout(collapse_row)

        self._ce_avatar = QLabel()
        self._ce_avatar.setObjectName("CallScreenAvatar")
        self._ce_avatar.setFixedSize(80, 80)
        self._ce_avatar.setAlignment(Qt.AlignCenter)

        self._ce_name = QLabel("@user")
        self._ce_name.setObjectName("CallScreenName")
        self._ce_name.setAlignment(Qt.AlignCenter)

        self._ce_status = QLabel("Звонок...")
        self._ce_status.setObjectName("CallScreenStatus")
        self._ce_status.setAlignment(Qt.AlignCenter)

        ce_center_layout.addStretch()
        ce_center_layout.addWidget(self._ce_avatar, 0, Qt.AlignCenter)
        ce_center_layout.addWidget(self._ce_name)
        ce_center_layout.addWidget(self._ce_status)
        ce_center_layout.addStretch()

        ce_layout.addWidget(self._ce_center, 1)

        # Нижняя панель контролов
        self._ce_controls = QFrame()
        self._ce_controls.setObjectName("CallControls")
        self._ce_controls.setFixedHeight(88)

        ctrl_layout = QHBoxLayout(self._ce_controls)
        ctrl_layout.setContentsMargins(24, 0, 24, 24)
        ctrl_layout.setSpacing(16)
        ctrl_layout.setAlignment(Qt.AlignCenter)

        self._cs_mic_btn = ThemedIconButton(str(ICONS_PATH / "mic_on.svg"), 52, 22)
        self._cs_mic_btn.setObjectName("CallControlBtn")
        self._cs_mic_btn.setToolTip("Микрофон")
        self._cs_mic_btn.clicked.connect(self._toggle_mic)

        self._cs_deaf_btn = ThemedIconButton(str(ICONS_PATH / "headset_on.svg"), 52, 22)
        self._cs_deaf_btn.setObjectName("CallControlBtn")
        self._cs_deaf_btn.setToolTip("Глушение")
        self._cs_deaf_btn.clicked.connect(self._toggle_deafen)

        self._cs_screen_btn = ThemedIconButton(str(ICONS_PATH / "screen_share.svg"), 52, 22)
        self._cs_screen_btn.setObjectName("CallControlBtn")
        self._cs_screen_btn.setToolTip("Демонстрация экрана (ПКМ — качество)")
        self._cs_screen_btn.clicked.connect(self._toggle_screen_share)
        self._cs_screen_btn.setContextMenuPolicy(Qt.CustomContextMenu)
        self._cs_screen_btn.customContextMenuRequested.connect(self._show_screen_quality_menu)
        self._cs_screen_btn.setVisible(False)

        self.screen_quality_label = QLabel()
        self.screen_quality_label.setObjectName("ScreenShareIndicator")
        self.screen_quality_label.setVisible(False)

        self._cs_vol_slider = QSlider(Qt.Horizontal)
        self._cs_vol_slider.setObjectName("VolumeSlider")
        self._cs_vol_slider.setRange(0, 200)
        self._cs_vol_slider.setValue(100)
        self._cs_vol_slider.setFixedWidth(120)
        self._cs_vol_slider.valueChanged.connect(lambda v: rtc.set_remote_volume(v / 100.0))

        self._cs_end_btn = ThemedIconButton(str(ICONS_PATH / "call_end.svg"), 52, 22)
        self._cs_end_btn.setObjectName("CallEndBtn")
        self._cs_end_btn.setToolTip("Завершить звонок")
        self._cs_end_btn.clicked.connect(self._on_end_call)

        ctrl_layout.addWidget(self._cs_mic_btn)
        ctrl_layout.addWidget(self._cs_deaf_btn)
        ctrl_layout.addWidget(self._cs_screen_btn)
        ctrl_layout.addWidget(self.screen_quality_label)
        ctrl_layout.addWidget(self._cs_vol_slider)
        ctrl_layout.addSpacing(20)
        ctrl_layout.addWidget(self._cs_end_btn)

        ce_layout.addWidget(self._ce_controls)

        # Анимация расширения
        self._ce_opacity = QGraphicsOpacityEffect(self.call_expanded)
        self._ce_opacity.setOpacity(0.0)
        self.call_expanded.setGraphicsEffect(self._ce_opacity)
        self._ce_fade_anim = QPropertyAnimation(self._ce_opacity, b"opacity")
        self._ce_fade_anim.setDuration(250)

        # Сохраняем ссылки для совместимости
        self.call_pill = self.call_widget
        self.call_timer = self._cw_status
        self.call_dot = self._cw_avatar
        self.vol_slider = self._cs_vol_slider
        self.screen_share_btn = self._cs_screen_btn
        self.mic_btn = self._cs_mic_btn
        self.deaf_btn = self._cs_deaf_btn
        self.end_call_btn = self._cs_end_btn

        # ── IncomingCallScreen ──
        self.incoming_overlay = QFrame(self)
        self.incoming_overlay.setObjectName("IncomingCallScreen")
        self.incoming_overlay.hide()

        io_layout = QVBoxLayout(self.incoming_overlay)
        io_layout.setContentsMargins(0, 0, 0, 0)
        io_layout.setSpacing(0)

        io_center = QFrame()
        io_center.setObjectName("CallScreenCenter")
        io_center_layout = QVBoxLayout(io_center)
        io_center_layout.setAlignment(Qt.AlignCenter)
        io_center_layout.setSpacing(16)

        self.inc_avatar = QLabel()
        self.inc_avatar.setObjectName("IncomingCallAvatar")
        self.inc_avatar.setFixedSize(96, 96)
        self.inc_avatar.setAlignment(Qt.AlignCenter)

        self.inc_title = QLabel("Входящий E2EE звонок")
        self.inc_title.setObjectName("IncomingCallTitle")
        self.inc_title.setAlignment(Qt.AlignCenter)

        self.inc_caller = QLabel("@User")
        self.inc_caller.setObjectName("IncomingCallName")
        self.inc_caller.setAlignment(Qt.AlignCenter)

        io_center_layout.addStretch()
        io_center_layout.addWidget(self.inc_avatar, 0, Qt.AlignCenter)
        io_center_layout.addWidget(self.inc_title)
        io_center_layout.addWidget(self.inc_caller)
        io_center_layout.addSpacing(40)

        btn_row = QHBoxLayout()
        btn_row.setAlignment(Qt.AlignCenter)
        btn_row.setSpacing(32)

        self.rej_btn = QPushButton("Отклонить")
        self.rej_btn.setObjectName("RejectCallBtn")
        self.rej_btn.setFixedSize(140, 50)
        self.rej_btn.clicked.connect(self._reject_call)

        self.acc_btn = QPushButton("Принять")
        self.acc_btn.setObjectName("AcceptCallBtn")
        self.acc_btn.setFixedSize(140, 50)
        self.acc_btn.clicked.connect(self._accept_call)

        btn_row.addWidget(self.rej_btn)
        btn_row.addWidget(self.acc_btn)
        io_center_layout.addLayout(btn_row)
        io_center_layout.addStretch()

        io_layout.addWidget(io_center)

        self._io_opacity = QGraphicsOpacityEffect(self.incoming_overlay)
        self._io_opacity.setOpacity(0.0)
        self.incoming_overlay.setGraphicsEffect(self._io_opacity)
        self._io_fade_anim = QPropertyAnimation(self._io_opacity, b"opacity")
        self._io_fade_anim.setDuration(300)

        # call_pill_anim для совместимости
        self.call_pill_anim = self._ce_fade_anim

    def _toggle_call_expand(self, event=None):
        if self._call_expanded:
            self._collapse_call()
        else:
            self._expand_call()

    def _expand_call(self):
        self._call_expanded = True
        right_geo = self.right_stack.geometry()
        self.call_expanded.setGeometry(right_geo)
        self._ce_opacity.setOpacity(0.0)
        self.call_expanded.show()
        self.call_expanded.raise_()
        self._ce_fade_anim.stop()
        self._ce_fade_anim.setStartValue(0.0)
        self._ce_fade_anim.setEndValue(1.0)
        self._ce_fade_anim.start()

    def _collapse_call(self):
        self._call_expanded = False
        self._ce_fade_anim.stop()
        self.call_expanded.hide()

    def _on_start_call(self):
        if state.current_chat_type != "ally":
            return
        target_username  = state.current_chat_username
        target_device_id = state.current_chat_device_id
        if not target_username or not target_device_id:
            return
        if rtc.is_in_call() or self._active_call_device_id:
            return
        if not self._verify_call_contact(target_username, target_device_id):
            return
        if rtc.is_in_call() or self._active_call_device_id:
            return
        context = resolve_call_peer(state, target_device_id)
        if (not context or context.username != target_username or not call_context_valid(state, context)
                or state.current_chat_type != "ally" or state.current_chat_username != target_username
                or state.current_chat_device_id != target_device_id):
            return
        self._active_call_context = context
        self.active_call_username   = target_username
        self._active_call_device_id = target_device_id
        self._call_signal_authorized = False
        self._call_direction = "outgoing"
        self._active_call_id = str(uuid.uuid4())

        first_letter = target_username[0].upper()
        self._cw_avatar_label.setText(first_letter)
        self._cw_name.setText(f"@{target_username}")
        self._cw_status.setText("Звонок...")
        self._show_pill()

        main_window = self.window()
        if not main_window._send_call_event("call_offer", target_device_id, self._active_call_id):
            self._cleanup_call()
            QMessageBox.warning(self, "Ошибка звонка", "Нет подключения или не удалось подготовить защищённый сигнал звонка.")

    def _on_incoming_call(self, data: dict):
        from_device_id = data.get("from_device_id", "")
        # Never trust the display name supplied in an unauthenticated envelope.
        context = data.get("peer_context")
        from_username = context.username if context and context.device_id == from_device_id else None
        if not from_username or not call_context_valid(state, context, False):
            print("[CALL] Отклонён звонок от неизвестного устройства")
            return

        print(f"[CALL] Входящий от @{from_username} ({from_device_id})")

        if rtc.is_in_call() or self._active_call_device_id:
            print("[CALL] Уже в звонке, отклоняем")
            main_window = self.window()
            if hasattr(main_window, "ws_worker") and main_window.ws_worker:
                main_window._send_call_event("call_ended", from_device_id, data.get("call_id"))
            return

        self._active_call_context = context
        self.active_call_username = from_username
        self._active_call_device_id = from_device_id
        self._call_signal_authorized = False
        self._call_direction = "incoming"
        self._active_call_id = data["call_id"]

        self.inc_caller.setText(f"@{from_username}")
        first_letter = from_username[0].upper() if from_username else "?"
        self.inc_avatar.setText(first_letter)

        self.incoming_overlay.setGeometry(self.right_stack.geometry())
        self._io_opacity.setOpacity(0.0)
        self.incoming_overlay.show()
        self.incoming_overlay.raise_()
        self._io_fade_anim.stop()
        self._io_fade_anim.setStartValue(0.0)
        self._io_fade_anim.setEndValue(1.0)
        self._io_fade_anim.start()

        main_window = self.window()
        if not main_window.isActiveWindow():
            if hasattr(main_window, "show_notification"):
                main_window.show_notification(
                    f"@{from_username}",
                    "Входящий защищённый звонок"
                )

    def _accept_call(self):
        if not self._active_call_device_id:
            print("[CALL] Нет device_id")
            return

        username, device_id, call_id = self.active_call_username, self._active_call_device_id, self._active_call_id
        if not call_context_valid(state, self._active_call_context, False):
            self._check_call_identity()
            return
        if not self._verify_call_contact(username, device_id):
            return
        # The call may have ended or been replaced while the dialog was open.
        if (self._call_direction != "incoming" or self._active_call_device_id != device_id
                or self._active_call_id != call_id
                or not call_context_valid(state, self._active_call_context, True)):
            return
        print(f"[CALL] Принимаем от @{self.active_call_username}")
        try:
            rtc.activate_call(device_id, call_id)
        except (ValueError, RuntimeError):
            self._cleanup_call()
            QMessageBox.warning(self, "Ошибка звонка", "Не удалось начать новую аудиосессию.")
            return
        self._call_signal_authorized = True

        self._io_fade_anim.stop()
        self.incoming_overlay.hide()

        first_letter = self.active_call_username[0].upper() if self.active_call_username else "?"
        self._cw_avatar_label.setText(first_letter)
        self._cw_name.setText(f"@{self.active_call_username}")
        self._cw_status.setText("Соединение...")
        self._cs_screen_btn.setVisible(True)
        self._show_pill()

        main_window = self.window()
        if not main_window._send_call_event("call_accept", self._active_call_device_id, self._active_call_id):
            rtc.end_call()
            self._cleanup_call()
            QMessageBox.warning(self, "Ошибка звонка", "Нет подключения или не удалось подготовить защищённый сигнал звонка.")

    def _reject_call(self):
        if self._active_call_device_id:
            main_window = self.window()
            if hasattr(main_window, "ws_worker") and main_window.ws_worker:
                main_window._send_call_event("call_ended", self._active_call_device_id, self._active_call_id)
        self.incoming_overlay.hide()
        self.active_call_username = None
        self._active_call_device_id = None
        self._call_signal_authorized = False
        self._call_direction = None
        self._active_call_id = None
        self._active_call_context = None

    def _on_call_accepted(self, data: dict):
        from_device_id = data.get("from_device_id", "")
        if (self._call_direction != "outgoing" or not self._active_call_device_id
                or from_device_id != self._active_call_device_id or self._call_signal_authorized):
            return
        self._call_signal_authorized = True
        self._cw_status.setText("Соединение...")
        try:
            rtc.start_call(self._active_call_device_id, self._active_call_id)
        except (ValueError, RuntimeError):
            rtc.end_call()
            self._cleanup_call()
            QMessageBox.warning(self, "Ошибка звонка", "Не удалось начать новую аудиосессию.")



    def _on_end_call(self):
        if self._active_call_device_id:
            main_window = self.window()
            if hasattr(main_window, "ws_worker") and main_window.ws_worker:
                main_window._send_call_event("call_ended", self._active_call_device_id, self._active_call_id)
        rtc.end_call()
        self._cleanup_call()

    def _on_remote_call_ended(self, data: dict):
        if not self._active_call_device_id or data.get("from_device_id") != self._active_call_device_id:
            return
        rtc.end_call()
        self._cleanup_call()

    def _check_call_identity(self):
        if not self._active_call_device_id:
            return
        # Incoming offers may ring before the user verifies; no media is
        # permitted until verification. Once accepted, continuously recheck.
        require_verified = not (self._call_direction == "incoming" and not self._call_signal_authorized)
        if not call_context_valid(state, self._active_call_context, require_verified):
            rtc.end_call()
            self._cleanup_call()
            QMessageBox.warning(self, "Звонок завершён", "Ключ устройства или учётная запись изменились; повторно сверьте ключ.")

    def _cleanup_call(self):
        self._active_call_context = None
        self._call_signal_authorized = False
        self._call_direction = None
        self._active_call_id = None
        if not self.active_call_username and not self._active_call_device_id: return
        self._hide_pill()
        self.incoming_overlay.hide()
        self._hide_screen_share_widget()
        self.screen_share_btn.setVisible(False)
        self.screen_quality_label.setVisible(False)
        self.is_screen_sharing = False
        self.active_call_username = None
        self._active_call_device_id = None

    def _reposition_call_ui(self):
        try:
            right_geo = self.right_stack.geometry()
            self.call_widget.move(right_geo.x() + 10, right_geo.y() + 10)
            self.call_expanded.setGeometry(right_geo)
            self.incoming_overlay.setGeometry(right_geo)
        except Exception as e:
            print(f"[CALL UI] reposition error: {e}")

    def _show_pill(self):
        self.incoming_overlay.hide()
        self.call_expanded.hide()
        self._call_expanded = False
        right_geo = self.right_stack.geometry()
        self.call_widget.setFixedWidth(min(right_geo.width() - 20, 360))
        self.call_widget.move(right_geo.x() + 10, right_geo.y() + 10)
        self.call_widget.show()
        self.call_widget.raise_()

    def _hide_pill(self):
        self._ce_fade_anim.stop()
        self.call_widget.hide()
        self.call_expanded.hide()
        self._call_expanded = False
        self._cw_status.setText("Звонок...")
        self.is_screen_sharing = False
        self._cs_screen_btn.setVisible(False)
        self.screen_quality_label.setVisible(False)

    def _toggle_mic(self):
        self.is_mic_muted = not self.is_mic_muted
        rtc.set_mute(self.is_mic_muted)
        self.mic_btn.set_icon_path(str(ICONS_PATH / ("mic_off.svg" if self.is_mic_muted else "mic_on.svg")))

    def _toggle_deafen(self):
        self.is_deafened = not self.is_deafened
        rtc.set_deafen(self.is_deafened)
        self.deaf_btn.set_icon_path(str(ICONS_PATH / ("headset_off.svg" if self.is_deafened else "headset_on.svg")))

    def _update_rtc_state(self, peer_device_id_or_status: str, status: str = None):
        if status is not None and peer_device_id_or_status != self._active_call_device_id:
            return
        actual = status if status is not None else peer_device_id_or_status
        if actual == "connected":
            self._cw_status.setText("На связи")
            self._cs_screen_btn.setVisible(True)
        elif actual in ("failed", "closed", "disconnected"):
            rtc.end_call()
            self._cleanup_call()

    # ─────────────────────────────────────────────────────────────────
    # SCREEN SHARE (Isolated E2EE WebRTC channel="screen")
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_preset_dims(profile: str):
        cfg = SCREEN_QUALITY_PRESETS.get(profile)
        if isinstance(cfg, dict):
            return int(cfg.get("width", 1280)), int(cfg.get("height", 720)), int(cfg.get("fps", 24))
        if isinstance(cfg, (tuple, list)) and len(cfg) >= 3:
            return int(cfg[0]), int(cfg[1]), int(cfg[2])
        return 1280, 720, 24

    def _show_screen_quality_menu(self, pos):
        menu = QMenu(self)
        for q_key, q_label in (
            ("smooth", "Плавное • 540p 30 FPS"),
            ("balanced", "Баланс • 720p 24 FPS"),
            ("sharp", "Чёткое • 900p 20 FPS"),
        ):
            prefix = "✓ " if self.current_quality_profile == q_key else "   "
            act = menu.addAction(prefix + q_label)
            act.triggered.connect(lambda _checked=False, k=q_key: self._set_screen_share_quality(k))
        menu.exec(self._cs_screen_btn.mapToGlobal(pos))

    def _toggle_screen_share(self):
        if not self.active_call_username or not self._active_call_device_id:
            return
        if self.is_screen_sharing or getattr(rtc.screen, "is_sharing", False):
            rtc.stop_screen_share()
            self._update_screen_share_ui(False)
            return

        if not self._call_signal_authorized or not call_context_valid(state, self._active_call_context, True):
            QMessageBox.warning(
                self,
                "Требуется сверка ключа",
                "Демонстрация экрана разрешена только в звонке со сверенным отпечатком собеседника.",
            )
            return
        if getattr(rtc, "call_state", "") != "connected":
            QMessageBox.information(
                self,
                "Ожидание соединения",
                "Дождитесь установки голосового соединения перед запуском демонстрации экрана.",
            )
            return

        screens = QGuiApplication.screens()
        if hasattr(self, "screen_share_overlay") and self.screen_share_overlay and len(screens) > 0:
            self.screen_share_overlay.show_overlay()
        else:
            self._on_monitor_selected(0)

    def _on_monitor_selected(self, monitor_index: int):
        if not self._active_call_device_id or not self._call_signal_authorized:
            return
        if not call_context_valid(state, self._active_call_context, True):
            return
        started = rtc.start_screen_share(
            quality=self.current_quality_profile,
            monitor_index=monitor_index,
        )
        if started:
            self._update_screen_share_ui(True, self.current_quality_profile)
        else:
            self._update_screen_share_ui(False)

    def _on_screen_share_cancelled(self):
        if getattr(rtc.screen, "is_sharing", False) and not self.is_screen_sharing:
            rtc.stop_screen_share()

    def _update_screen_share_ui(self, is_sharing: bool, quality: str = "balanced"):
        self.is_screen_sharing = bool(is_sharing)
        self.screen_share_btn.setProperty("active", bool(is_sharing))
        self.screen_share_btn.setToolTip(
            "Остановить демонстрацию (ПКМ — качество)"
            if is_sharing
            else "Поделиться экраном (ПКМ — качество)"
        )
        self.screen_quality_label.setVisible(bool(is_sharing))
        self.call_pill.setProperty("screen_sharing", bool(is_sharing))
        if is_sharing:
            _w, h, fps = self._resolve_preset_dims(quality)
            self.screen_quality_label.setText(f"{h}p • {fps}fps")

        self.screen_share_btn.style().unpolish(self.screen_share_btn)
        self.screen_share_btn.style().polish(self.screen_share_btn)
        self.call_pill.style().unpolish(self.call_pill)
        self.call_pill.style().polish(self.call_pill)

    def _on_screen_share_started(self, from_device_id: str):
        if from_device_id != self._active_call_device_id:
            return
        if hasattr(self, "screen_share_viewer") and self.screen_share_viewer:
            peer_label = f"@{self.active_call_username}" if self.active_call_username else ""
            self.screen_share_viewer.start_viewing(from_device_id, peer_label)
            self.messages_scroll.setVisible(False)

    def _on_screen_share_stopped(self, from_device_id: str):
        if hasattr(self, "screen_share_viewer") and self.screen_share_viewer:
            self.screen_share_viewer.stop_viewing()
            self.messages_scroll.setVisible(True)

    def _toggle_screen_share_maximize(self):
        if self.screen_share_viewer._is_maximized:
            self.messages_scroll.setVisible(False)
        else:
            self.messages_scroll.setVisible(True)

    def _set_screen_share_quality(self, profile: str):
        self.current_quality_profile = profile
        if hasattr(rtc, "set_screen_share_quality"):
            rtc.set_screen_share_quality(profile)
        if self.is_screen_sharing:
            _w, h, fps = self._resolve_preset_dims(profile)
            self.screen_quality_label.setText(f"{h}p • {fps}fps")

    def _on_video_track_received(self, peer_device_id: str, receiver):
        pass

    def _on_screen_frame_numpy(self, numpy_frame, fps: float = 0.0):
        try:
            if numpy_frame is None or numpy_frame.ndim != 3 or numpy_frame.shape[2] != 3:
                return
            h, w, ch = numpy_frame.shape
            bytes_per_line = ch * w
            img = QImage(numpy_frame.data, w, h, bytes_per_line, QImage.Format_RGB888).copy()
            if not img.isNull():
                self._update_screen_share_frame(img, fps=fps)
        except Exception as e:
            print(f"[ScreenShare] frame error: {e}")

    def _show_screen_share_widget(self):
        if hasattr(self, "screen_share_viewer") and self.screen_share_viewer and self._active_call_device_id:
            peer_label = f"@{self.active_call_username}" if self.active_call_username else ""
            self.screen_share_viewer.start_viewing(self._active_call_device_id, peer_label)
            self.messages_scroll.setVisible(False)

    def _update_screen_share_frame(self, img: QImage, fps: float = 0.0):
        if not hasattr(self, "screen_share_viewer") or not self.screen_share_viewer:
            return
        if not self.screen_share_viewer.isVisible() and self._active_call_device_id:
            peer_label = f"@{self.active_call_username}" if self.active_call_username else ""
            self.screen_share_viewer.start_viewing(self._active_call_device_id, peer_label)
            self.messages_scroll.setVisible(False)
        pixmap = QPixmap.fromImage(img)
        self.screen_share_viewer.set_frame(pixmap)
        if fps > 0:
            self.screen_share_viewer.set_fps(fps)

    def _hide_screen_share_widget(self):
        if hasattr(self, "screen_share_overlay") and self.screen_share_overlay:
            self.screen_share_overlay.hide()
        if hasattr(self, "screen_share_viewer") and self.screen_share_viewer:
            self.screen_share_viewer.stop_viewing()
        if hasattr(self, "messages_scroll") and self.messages_scroll:
            self.messages_scroll.setVisible(True)

    def _stop_remote_screen_share(self):
        self._hide_screen_share_widget()
        self._update_screen_share_ui(False)

    # ─────────────────────────────────────────────────────────────────
    # UTILS
    # ─────────────────────────────────────────────────────────────────

    def _on_image_view_requested(self, pixmap):
        main_window = self.window()
        if hasattr(main_window, "show_image_viewer"):
            main_window.show_image_viewer(pixmap)

    def _switch_sidebar_tab(self, tab: str):
        is_allies = tab == "allies"
        self.sidebar_stack.setCurrentIndex(0 if is_allies else 1)
        self.tab_allies_btn.setChecked(is_allies)
        self.tab_groups_btn.setChecked(not is_allies)

    def _set_chat_header_icon(self, chat_type: str):
        t = get_theme()
        if not hasattr(self, "_chat_header_icon_label"):
            self._chat_header_icon_label = QLabel()
            self._chat_header_icon_label.setFixedSize(20, 20)
            self.chat_header.layout().insertWidget(0, self._chat_header_icon_label)
        svg_name = "group.svg" if chat_type == "group" else "shield_check.svg"
        svg_path = ICONS_PATH / svg_name
        if svg_path.exists():
            renderer = QSvgRenderer(svg_path.read_text().replace("currentColor", t.get("text_dim", "#777e8e")).encode())
            pixmap = QPixmap(20, 20)
            pixmap.fill(Qt.transparent)
            painter = QPainter(pixmap)
            renderer.render(painter)
            painter.end()
            self._chat_header_icon_label.setPixmap(pixmap)
        self._chat_header_icon_label.setVisible(True)

    def _get_group_item(self, group_id: str):
        for i in range(self.groups_list.count()):
            item = self.groups_list.item(i)
            if item.data(Qt.UserRole) == group_id:
                return item
        return None


    def _find_public_key_by_device_id(self, device_id: str):
        for ally_data in state.allies.values():
            for dev in ally_data.get("devices", []):
                if dev.get("device_id") == device_id:
                    return dev.get("public_key")
        return None

    def _find_username_by_device_id(self, device_id: str):
        for username, ally_data in state.allies.items():
            for dev in ally_data.get("devices", []):
                if dev.get("device_id") == device_id:
                    return username
        return None

    def _get_group_card(self, group_id: str):
        item = self._get_group_item(group_id)
        return self.groups_list.itemWidget(item) if item else None

    def _add_group_card(self, group_id: str, name: str):
        item = GroupListItem(group_id)
        item.setSizeHint(QSize(0, 72))
        self.groups_list.addItem(item)
        card = GroupCardWidget(name)
        if getattr(state, "groups", {}).get(group_id, {}).get("archived"):
            card.setToolTip("Группа недоступна на сервере. Локальная история сохранена.")
        try:
            page = storage.load_history_page(state.username, f"group_{group_id}", page_size=1)
        except Exception as exc:
            print(f"[HISTORY] История группы недоступна: {type(exc).__name__}")
            page = None
            card.update_preview("История недоступна")
        if page and page.messages:
            last_msg = page.messages[-1]
            raw_text = last_msg.get("text", "")
            if raw_text.startswith("[IMAGE_META]"):
                card.update_preview("Фото")
            elif raw_text.startswith("[VOICE_META]"):
                card.update_preview("Голосовое")
            else:
                card.update_preview(raw_text)
            ts_str = last_msg.get("timestamp")
            if ts_str:
                try:
                    item.last_activity = datetime.fromisoformat(ts_str).timestamp()
                except ValueError:
                    item.last_activity = 0.0
        self.groups_list.setItemWidget(item, card)
        self.groups_list.sortItems(Qt.DescendingOrder)

    # ═════════════════════════════════════════════════════════════════════
    # PACKAGE IV: AUTONOMOUS ICE/TURN + DISCORD-GRADE GROUP VOICE ROOMS
    # ═════════════════════════════════════════════════════════════════════

    def _init_group_voice_ui(self):
        from app.group_voice_room import GroupVoiceRoomController

        self._group_voice_rosters = {}   # group_id -> list[dict]
        self._group_voice_speaking = {}  # device_id -> bool

        self._group_voice_ctrl = GroupVoiceRoomController(
            send_signal_fn=self._dispatch_group_voice_signal,
            on_participants_updated=None,
            on_speaking_updated=lambda dev_id, spk: self._group_voice_speaking_sig.emit(dev_id, spk),
            on_screen_frame=lambda pid, rgb, res: self._group_voice_screen_sig.emit(pid, rgb, res),
        )
        self._group_voice_speaking_sig.connect(self._on_group_voice_speaking_gui, Qt.QueuedConnection)
        self._group_voice_screen_sig.connect(self._on_group_voice_screen_gui, Qt.QueuedConnection)

        self.group_voice_bar = QFrame()
        self.group_voice_bar.setObjectName("SearchBar")
        self.group_voice_bar.setVisible(False)
        bar_v = QVBoxLayout(self.group_voice_bar)
        bar_v.setContentsMargins(24, 8, 24, 8)
        bar_v.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)
        self.gv_status_lbl = QLabel("Голосовая комната")
        self.gv_status_lbl.setObjectName("ReplyPreviewSender")
        top_row.addWidget(self.gv_status_lbl)
        top_row.addStretch()

        self.gv_join_btn = QPushButton("Войти в голос")
        self.gv_join_btn.clicked.connect(self.join_current_group_voice_room)
        top_row.addWidget(self.gv_join_btn)

        self.gv_mic_btn = QPushButton("Микрофон: ВКЛ")
        self.gv_mic_btn.clicked.connect(self._toggle_gv_mic)
        top_row.addWidget(self.gv_mic_btn)

        self.gv_deaf_btn = QPushButton("Звук: ВКЛ")
        self.gv_deaf_btn.clicked.connect(self._toggle_gv_deafen)
        top_row.addWidget(self.gv_deaf_btn)

        self.gv_ptt_btn = QPushButton("Рация (V): ВЫКЛ")
        self.gv_ptt_btn.clicked.connect(self._toggle_gv_ptt)
        top_row.addWidget(self.gv_ptt_btn)

        self.gv_screen_btn = QPushButton("Экран")
        self.gv_screen_btn.clicked.connect(self._toggle_gv_screen_share)
        top_row.addWidget(self.gv_screen_btn)

        self.gv_leave_btn = QPushButton("Выйти")
        self.gv_leave_btn.clicked.connect(self.leave_group_voice_room)
        top_row.addWidget(self.gv_leave_btn)

        bar_v.addLayout(top_row)

        self.gv_peers_row = QHBoxLayout()
        self.gv_peers_row.setSpacing(8)
        bar_v.addLayout(self.gv_peers_row)

        # Periodic heartbeat while inside a group voice room
        self._gv_heartbeat_timer = QTimer(self)
        self._gv_heartbeat_timer.setInterval(30000)
        self._gv_heartbeat_timer.timeout.connect(self._send_group_voice_heartbeat)
        self._gv_heartbeat_timer.start()

    def sync_ice_config(self):
        from app.ice_config import set_ui_relay_only
        from app.workers import FetchIceConfigWorker

        if state.username:
            prefs = storage.get_call_audio_prefs(state.username)
            set_ui_relay_only(bool(prefs.get("ice_relay_only", False)))
            if hasattr(self, "_group_voice_ctrl"):
                self._group_voice_ctrl.apply_audio_prefs(prefs)

        account = (state.username, state.server_url, state.device_id, state.token)
        if not all(isinstance(v, str) and v for v in account):
            return
        if any(isinstance(w, FetchIceConfigWorker) and w.isRunning() for w in self._net_workers):
            return
        w = FetchIceConfigWorker(account[1], account[3])
        w.account_context = account
        self._net_workers.append(w)

        def _done(_ok, _res, worker=w):
            worker.wait()
            if worker in self._net_workers:
                self._net_workers.remove(worker)

        w.finished.connect(_done, Qt.QueuedConnection)
        try:
            w.start()
        except Exception:
            if w in self._net_workers:
                self._net_workers.remove(w)

    def on_call_audio_prefs_changed(self, prefs: dict):
        if hasattr(self, "_group_voice_ctrl") and isinstance(prefs, dict):
            self._group_voice_ctrl.apply_audio_prefs(prefs)
            self._refresh_group_voice_bar()

    def _on_toggle_group_voice_btn(self):
        gvc = getattr(self, "_group_voice_ctrl", None)
        gid = state.current_group_id
        if not gvc or not gid:
            return
        if gvc.active_group_id == gid:
            self.leave_group_voice_room()
        else:
            self.join_current_group_voice_room()

    def _run_gv_worker(self, group_id: str, action: str, payload: dict | None = None):
        from app.workers import GroupVoiceRoomActionWorker

        account = (state.username, state.server_url, state.device_id, state.token)
        if not all(isinstance(v, str) and v for v in account):
            return
        w = GroupVoiceRoomActionWorker(account[1], account[3], group_id, action, payload=payload)
        w.account_context = account
        self._net_workers.append(w)
        w.finished.connect(
            lambda ok, res, gid, act, worker=w: self._on_gv_worker_finished(ok, res, gid, act, worker),
            Qt.QueuedConnection,
        )
        try:
            w.start()
        except Exception:
            if w in self._net_workers:
                self._net_workers.remove(w)

    def _on_gv_worker_finished(self, ok: bool, res, group_id: str, action: str, worker):
        worker.wait()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if worker.account_context[:3] != (state.username, state.server_url, state.device_id):
            return
        if not ok:
            if action == "join" and isinstance(res, str):
                QMessageBox.warning(self, "Голосовая комната", res)
            return
        if isinstance(res, dict) and "participants" in res:
            participants = res.get("participants") or []
            self._group_voice_rosters[group_id] = participants
            if action == "join":
                prefs = storage.get_call_audio_prefs(state.username) if state.username else {}
                self._group_voice_ctrl.start_local_session(
                    group_id=group_id,
                    our_device_id=state.device_id,
                    our_username=state.username,
                    initial_participants=participants,
                    audio_prefs=prefs,
                )
            elif self._group_voice_ctrl.active_group_id == group_id:
                self._group_voice_ctrl.update_participants(group_id, participants)
            self._refresh_group_voice_bar()

    def _fetch_group_voice_state(self, group_id: str):
        self._run_gv_worker(group_id, "fetch_state")

    def _send_group_voice_heartbeat(self):
        gvc = getattr(self, "_group_voice_ctrl", None)
        if gvc and gvc.active_group_id:
            self._fetch_group_voice_state(gvc.active_group_id)

    def join_current_group_voice_room(self):
        gid = state.current_group_id
        if not gid:
            return
        from app.ice_config import runtime_ice_needs_refresh
        if runtime_ice_needs_refresh():
            self.sync_ice_config()
        gvc = self._group_voice_ctrl
        self._run_gv_worker(
            gid,
            "join",
            payload={
                "is_muted": bool(gvc.gate.is_muted),
                "is_deafened": bool(gvc.mixer.is_deafened),
                "is_sharing_screen": False,
            },
        )

    def leave_group_voice_room(self):
        gvc = getattr(self, "_group_voice_ctrl", None)
        if not gvc or not gvc.active_group_id:
            return
        gid = gvc.active_group_id
        gvc.leave_local_session()
        self._group_voice_speaking.clear()
        self._hide_screen_share_widget()
        self._run_gv_worker(gid, "leave")
        self._refresh_group_voice_bar()

    def _sync_gv_self_flags(self):
        gvc = self._group_voice_ctrl
        if not gvc.active_group_id:
            return
        self._run_gv_worker(
            gvc.active_group_id,
            "state",
            payload={
                "is_muted": bool(gvc.gate.is_muted),
                "is_deafened": bool(gvc.mixer.is_deafened),
                "is_sharing_screen": bool(gvc.is_sharing_screen),
            },
        )

    def _toggle_gv_mic(self):
        gvc = self._group_voice_ctrl
        gvc.gate.set_muted(not gvc.gate.is_muted)
        self._sync_gv_self_flags()
        self._refresh_group_voice_bar()

    def _toggle_gv_deafen(self):
        gvc = self._group_voice_ctrl
        gvc.mixer.is_deafened = not gvc.mixer.is_deafened
        if gvc.mixer.is_deafened:
            gvc.gate.set_muted(True)
        self._sync_gv_self_flags()
        self._refresh_group_voice_bar()

    def _toggle_gv_ptt(self):
        gvc = self._group_voice_ctrl
        new_ptt = not gvc.gate.ptt_enabled
        gvc.gate.set_ptt_mode(new_ptt)
        if state.username:
            storage.set_call_audio_prefs(state.username, {"push_to_talk": new_ptt})
        self._refresh_group_voice_bar()

    def _toggle_gv_screen_share(self):
        gvc = self._group_voice_ctrl
        if not gvc.active_group_id:
            return
        gvc.is_sharing_screen = not gvc.is_sharing_screen
        self._sync_gv_self_flags()
        self._refresh_group_voice_bar()

    def _dispatch_group_voice_signal(
        self, group_id: str, target_device_id: str, channel: str, encrypted_blob: str, signature: str
    ):
        self._run_gv_worker(
            group_id,
            "signal",
            payload={
                "target_device_id": target_device_id,
                "channel": channel,
                "encrypted_blob": encrypted_blob,
                "signature": signature,
            },
        )

    def on_group_voice_state_event(self, data: dict):
        if not isinstance(data, dict):
            return
        gid = data.get("group_id")
        participants = data.get("participants")
        if not isinstance(gid, str) or not isinstance(participants, list):
            return
        self._group_voice_rosters[gid] = participants
        if self._group_voice_ctrl.active_group_id == gid:
            self._group_voice_ctrl.update_participants(gid, participants)
        self._refresh_group_voice_bar()

    def on_group_voice_signal_event(self, data: dict):
        if isinstance(data, dict) and hasattr(self, "_group_voice_ctrl"):
            self._group_voice_ctrl.handle_incoming_signal(data)

    def _on_group_voice_speaking_gui(self, device_id: str, is_speaking: bool):
        self._group_voice_speaking[device_id] = bool(is_speaking)
        self._refresh_group_voice_bar()

    def _on_group_voice_screen_gui(self, peer_device_id: str, rgb_frame, resolution: str):
        if not hasattr(self, "screen_share_viewer") or not self.screen_share_viewer or rgb_frame is None:
            return
        h, w = int(rgb_frame.shape[0]), int(rgb_frame.shape[1])
        qimg = QImage(rgb_frame.data, w, h, w * 3, QImage.Format_RGB888).copy()
        if not self.screen_share_viewer.isVisible():
            peer_uname = self._find_username_by_device_id(peer_device_id) or peer_device_id[:8]
            self.screen_share_viewer.start_viewing(peer_device_id, f"@{peer_uname}")
            self.messages_scroll.setVisible(False)
        self.screen_share_viewer.set_frame(QPixmap.fromImage(qimg))

    def _open_peer_volume_menu(self, peer_device_id: str, peer_username: str, anchor_btn: QPushButton):
        from PySide6.QtGui import QWidgetAction
        gvc = self._group_voice_ctrl
        menu = QMenu(self)
        holder = QWidget(menu)
        h_lay = QHBoxLayout(holder)
        h_lay.setContentsMargins(10, 6, 10, 6)
        cur_pct = int(round(gvc.mixer.get_peer_volume(peer_device_id) * 100))
        lbl = QLabel(f"Громкость @{peer_username}: {cur_pct}%")
        slider = QSlider(Qt.Horizontal)
        slider.setRange(0, 200)
        slider.setValue(cur_pct)
        slider.setFixedWidth(150)

        def _on_val(val: int):
            vol = val / 100.0
            gvc.mixer.set_peer_volume(peer_device_id, vol)
            lbl.setText(f"Громкость @{peer_username}: {val}%")
            if state.username:
                storage.set_peer_volume(state.username, peer_device_id, vol)

        slider.valueChanged.connect(_on_val)
        h_lay.addWidget(lbl)
        h_lay.addWidget(slider)
        wa = QWidgetAction(menu)
        wa.setDefaultWidget(holder)
        menu.addAction(wa)
        menu.exec(anchor_btn.mapToGlobal(anchor_btn.rect().bottomLeft()))

    def _refresh_group_voice_bar(self):
        if not hasattr(self, "group_voice_bar"):
            return
        gvc = self._group_voice_ctrl
        active_gid = gvc.active_group_id
        viewing_gid = state.current_group_id if state.current_chat_type == "group" else None
        display_gid = active_gid or viewing_gid

        if not display_gid:
            self.group_voice_bar.setVisible(False)
            return

        roster = self._group_voice_rosters.get(display_gid, [])
        in_room = active_gid == display_gid
        if not in_room and not roster and state.current_chat_type != "group":
            self.group_voice_bar.setVisible(False)
            return

        grp_name = getattr(state, "groups", {}).get(display_gid, {}).get("name", "Группа")
        self.group_voice_bar.setVisible(True)

        if in_room:
            from app.ice_config import ice_relay_only
            relay_badge = " • IP скрыт (TURN)" if ice_relay_only() else ""
            self.gv_status_lbl.setText(f"🔊 В голосовой комнате «{grp_name}» ({len(roster)}/8){relay_badge}")
        else:
            self.gv_status_lbl.setText(
                f"Голосовая комната «{grp_name}» — участников: {len(roster)}/8"
            )

        self.gv_join_btn.setVisible(not in_room)
        for btn in (self.gv_mic_btn, self.gv_deaf_btn, self.gv_ptt_btn, self.gv_screen_btn, self.gv_leave_btn):
            btn.setVisible(in_room)

        if in_room:
            self.gv_mic_btn.setText("Микрофон: ВЫКЛ" if gvc.gate.is_muted else "Микрофон: ВКЛ")
            self.gv_deaf_btn.setText("Звук: ВЫКЛ" if gvc.mixer.is_deafened else "Звук: ВКЛ")
            self.gv_ptt_btn.setText("Рация (V): ВКЛ" if gvc.gate.ptt_enabled else "Рация (V): ВЫКЛ")
            self.gv_screen_btn.setText("Стоп экран" if gvc.is_sharing_screen else "Экран")

        while self.gv_peers_row.count():
            child = self.gv_peers_row.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        for p in roster:
            dev_id = p.get("device_id", "")
            uname = p.get("username", "user")
            speaking = bool(self._group_voice_speaking.get(dev_id, False))
            ring = "🟢 " if speaking else "⚪ "
            mute_tag = " 🔇" if p.get("is_muted") else ""
            scr_tag = " 🖥" if p.get("is_sharing_screen") else ""
            chip = QPushButton(f"{ring}@{uname}{mute_tag}{scr_tag}")
            chip.setFocusPolicy(Qt.NoFocus)
            if in_room and dev_id != state.device_id:
                vol_pct = int(round(gvc.mixer.get_peer_volume(dev_id) * 100))
                chip.setToolTip(f"Нажмите для настройки громкости @{uname} ({vol_pct}%)")
                chip.clicked.connect(
                    lambda _checked=False, d=dev_id, u=uname, b=chip: self._open_peer_volume_menu(d, u, b)
                )
            self.gv_peers_row.addWidget(chip)

            if in_room and dev_id != state.device_id and p.get("is_sharing_screen"):
                watch_btn = QPushButton("Смотреть стрим")
                watch_btn.setFocusPolicy(Qt.NoFocus)
                watch_btn.clicked.connect(lambda _c=False, d=dev_id: gvc.watch_peer_screen(d))
                self.gv_peers_row.addWidget(watch_btn)

        self.gv_peers_row.addStretch()

    def keyPressEvent(self, event):
        gvc = getattr(self, "_group_voice_ctrl", None)
        if (
            gvc is not None
            and gvc.active_group_id
            and gvc.gate.ptt_enabled
            and event.key() == Qt.Key_V
            and not event.isAutoRepeat()
            and not self.msg_input.hasFocus()
        ):
            gvc.gate.set_ptt_pressed(True)
            event.accept()
            return
        super().keyPressEvent(event)

    def keyReleaseEvent(self, event):
        gvc = getattr(self, "_group_voice_ctrl", None)
        if (
            gvc is not None
            and gvc.active_group_id
            and gvc.gate.ptt_enabled
            and event.key() == Qt.Key_V
            and not event.isAutoRepeat()
        ):
            gvc.gate.set_ptt_pressed(False)
            event.accept()
            return
        super().keyReleaseEvent(event)

    # ═════════════════════════════════════════════════════════════════════
    # PACKAGE V: DOCUMENTS, CLIPBOARD/DRAG-DROP & GROUP V2 E2EE ATTACHMENTS
    # ═════════════════════════════════════════════════════════════════════

    _IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".webp"})

    def _process_selected_local_file(self, file_path: str, context=None, group_id: str | None = None):
        from app.media_identity import MAX_DOCUMENT_BYTES, sanitize_attachment_filename

        try:
            p = Path(file_path)
            if not p.is_file() or p.is_symlink():
                QMessageBox.warning(self, "Недопустимый файл", "Символьные ссылки и папки не поддерживаются.")
                return
            with open(p, "rb") as f:
                raw_data = f.read(MAX_DOCUMENT_BYTES + 1)
            if not raw_data:
                QMessageBox.warning(self, "Пустой файл", "Нельзя отправить пустой файл (0 байт).")
                return
            if len(raw_data) > MAX_DOCUMENT_BYTES:
                QMessageBox.warning(self, "Файл слишком большой", "Максимальный размер файла — 20 МБ.")
                return
            safe_name = sanitize_attachment_filename(p.name)
            is_img = p.suffix.lower() in self._IMAGE_EXTENSIONS

            if group_id:
                if state.current_chat_type != "group" or state.current_group_id != group_id:
                    return
                if is_img:
                    self._show_image_preview(raw_data, context=("group_image", group_id))
                else:
                    cap = self.msg_input.toPlainText().strip()
                    if cap:
                        self.msg_input.clear()
                    self._send_group_attachment(group_id, raw_data, "file", filename=safe_name, caption=cap)
                return

            if context is None:
                context = capture_recipient(state)
            if not is_active_recipient(state, context):
                QMessageBox.warning(self, "Отправка отменена", "Чат или ключ контакта изменился.")
                return
            if is_img:
                self._show_image_preview(raw_data, context=context)
            else:
                cap = self.msg_input.toPlainText().strip()
                if cap:
                    self.msg_input.clear()
                self._queue_attachment(raw_data, context, "file", caption=cap, filename=safe_name)
        except Exception as exc:
            QMessageBox.warning(self, "Ошибка файла", f"Не удалось прочитать файл:\n{type(exc).__name__}")

    def _on_files_dropped_or_pasted(self, paths: list):
        if not paths:
            return
        is_group = (state.current_chat_type == "group" and bool(state.current_group_id))
        gid = state.current_group_id if is_group else None
        ctx = None
        if not is_group:
            if not state.current_chat_username:
                return
            try:
                ctx = capture_recipient(state)
            except ValueError as e:
                QMessageBox.warning(self, "Отправка недоступна", str(e))
                return
        for fp in paths[:5]:
            if isinstance(fp, str) and fp:
                self._process_selected_local_file(fp, context=ctx, group_id=gid)

    def dragEnterEvent(self, event):
        mime = event.mimeData()
        if mime and mime.hasUrls() and any(u.isLocalFile() for u in mime.urls()):
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dropEvent(self, event):
        mime = event.mimeData()
        if mime and mime.hasUrls():
            local_files = [u.toLocalFile() for u in mime.urls() if u.isLocalFile() and u.toLocalFile()]
            if local_files:
                event.acceptProposedAction()
                self._on_files_dropped_or_pasted(local_files)
                return
        super().dropEvent(event)

    def _send_group_attachment(
        self,
        group_id: str,
        raw_data: bytes,
        kind: str,
        *,
        filename: str = "",
        caption: str = "",
        duration: float = 0.0,
    ):
        from app.media_identity import build_file_meta, sanitize_attachment_filename
        from app.workers import UploadAndGrantGroupAttachmentWorker

        group_data = state.groups.get(group_id)
        if not group_data or group_data.get("archived"):
            return
        self.ensure_my_group_sender_key(group_id)
        if not group_data.get("my_sender_key"):
            QMessageBox.warning(self, "Ключ группы", "Подождите синхронизации ключей группы и повторите отправку.")
            return

        file_id = str(uuid.uuid4())
        secret_key = crypto.generate_file_key()
        encrypted_blob = crypto.encrypt_file(raw_data, secret_key)
        safe_name = sanitize_attachment_filename(filename or "document.bin")

        if kind == "image":
            special_text = f"[IMAGE_META]|{file_id}|{secret_key}|{caption}"
        elif kind == "voice":
            special_text = f"[VOICE_META]|{file_id}|{secret_key}|{max(0.1, float(duration)):.1f}"
        elif kind == "file":
            special_text = build_file_meta(file_id, secret_key, safe_name, len(raw_data), caption)
        else:
            return

        member_devs = [
            m.get("device_id")
            for m in (group_data.get("members") or [])
            if isinstance(m, dict)
            and isinstance(m.get("device_id"), str)
            and m.get("device_id") != state.device_id
        ]

        acct = (state.username, state.server_url, state.device_id, state.token)
        worker = UploadAndGrantGroupAttachmentWorker(
            state.server_url, state.token, file_id, encrypted_blob, member_devs
        )
        worker.account_context = acct
        self._net_workers.append(worker)

        def _after_upload(ok: bool, info, w=worker):
            w.wait()
            if w in self._net_workers:
                self._net_workers.remove(w)
            if w.account_context[:3] != (state.username, state.server_url, state.device_id):
                return
            if not ok:
                QMessageBox.warning(self, "Ошибка загрузки в группу", f"Не удалось загрузить вложение: {info}")
                return
            if kind == "image":
                self._image_cache[self._media_asset_key(file_id, secret_key)] = raw_data
            self._dispatch_group_meta_message(group_id, special_text)

        worker.finished.connect(_after_upload, Qt.QueuedConnection)
        worker.start()

    def _dispatch_group_meta_message(self, group_id: str, special_text: str):
        group_data = state.groups.get(group_id)
        if not group_data or not group_data.get("my_sender_key"):
            return
        _ttl_fn = getattr(globals().get("storage"), "get_chat_ttl", None)
        _ttl_val = _ttl_fn(state.username, f"group_{group_id}") if callable(_ttl_fn) else None
        _enc_ttl_kw = {}
        _save_ttl_kw = {}
        if isinstance(_ttl_val, int) and not isinstance(_ttl_val, bool) and _ttl_val >= 5:
            import time as _time
            _enc_ttl_kw["ttl_seconds"] = _ttl_val
            _save_ttl_kw["expires_at"] = int(_time.time() + _ttl_val)

        try:
            enc_result = group_crypto.encrypt_group_message(
                special_text,
                group_data["my_sender_key"],
                group_id=group_id,
                sender_device_id=state.device_id,
                **_enc_ttl_kw,
            )
            self._save_group_keys_safe()
        except Exception:
            QMessageBox.warning(self, "Ошибка шифрования", "Не удалось зашифровать вложение для группы.")
            return

        msg_id = f"msg_{uuid.uuid4().hex[:16]}"
        storage.save_message(
            state.username,
            f"group_{group_id}",
            special_text,
            is_mine=True,
            msg_id=msg_id,
            is_read=True,
            **_save_ttl_kw,
        )
        card = self._get_group_card(group_id)
        if card:
            if special_text.startswith("[IMAGE_META]|"):
                card.update_preview("Фото")
            elif special_text.startswith("[VOICE_META]|"):
                card.update_preview("Голосовое")
            elif special_text.startswith("[FILE_META]|"):
                _fp = special_text.split("|", 5)
                card.update_preview(f"📄 {_fp[3]}" if len(_fp) >= 4 else "Документ")
        if state.current_chat_type == "group" and state.current_group_id == group_id:
            self._render_history_page()

        server_payload = {
            "group_id": group_id,
            "encrypted_blob": enc_result["blob"],
            "signature": enc_result["signature"],
            "sender_key_id": enc_result["key_id"],
            "epoch": enc_result["epoch"],
            "chain_index": enc_result["chain_index"],
        }
        req_ctx = (state.username, state.server_url, state.device_id, state.token)
        sw = SendGroupMessageWorker(state.server_url, state.token, server_payload)
        sw.account_context = req_ctx
        sw.group_id = group_id
        sw.finished.connect(lambda s, d, w=sw: self._on_group_send_finished(s, d, w), Qt.QueuedConnection)
        self._net_workers.append(sw)
        sw.start()

    def _on_bubble_file_download_requested(self, file_id: str, secret_key: str, filename: str, size_bytes: int):
        from app.media_identity import (
            is_dangerous_executable_extension,
            sanitize_attachment_filename,
            valid_file_id,
            valid_file_key,
        )

        if not valid_file_id(file_id) or not valid_file_key(secret_key):
            QMessageBox.warning(self, "Ошибка", "Некорректные метаданные файла.")
            return
        safe_name = sanitize_attachment_filename(filename)
        if is_dangerous_executable_extension(safe_name):
            ans = QMessageBox.warning(
                self,
                "Предупреждение безопасности",
                f"Файл «{safe_name}» имеет исполняемое расширение и может содержать вредоносный код.\n\n"
                "Сохранять только если вы на 100% доверяете отправителю. Продолжить?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if ans != QMessageBox.Yes:
                return

        dest_path, _ = QFileDialog.getSaveFileName(self, "Сохранить зашифрованный файл как…", safe_name)
        if not dest_path:
            return

        # Check local pending attachment cache first (if sender clicks download before upload finishes)
        local_plain = attachment_outbox.load_pending_plaintext(
            getattr(state, "username", None),
            getattr(state, "server_url", None),
            getattr(state, "device_id", None),
            file_id,
            secret_key,
        )
        if local_plain is not None:
            self._write_downloaded_document_safely(dest_path, local_plain)
            return

        acct = (state.username, state.server_url, state.device_id, state.token)
        worker = DownloadFileWorker(state.server_url, state.token, file_id)
        worker.account_context = acct
        self._net_workers.append(worker)

        def _after_dl(w=worker):
            w.wait()
            if w in self._net_workers:
                self._net_workers.remove(w)
            if w.account_context[:3] != (state.username, state.server_url, state.device_id):
                return
            ok, enc_bytes = w.result
            if not ok or not enc_bytes:
                QMessageBox.warning(self, "Ошибка скачивания", "Файл недоступен или срок его хранения истёк.")
                return
            try:
                plain = crypto.decrypt_file(enc_bytes, secret_key)
            except Exception:
                QMessageBox.warning(self, "Ошибка целостности", "Не удалось проверить аутентичность файла (Poly1305).")
                return
            self._write_downloaded_document_safely(dest_path, plain)

        worker.finished.connect(_after_dl, Qt.QueuedConnection)
        worker.start()

    def _write_downloaded_document_safely(self, dest_path: str, plain_bytes: bytes):
        import os as _os
        import tempfile as _tempfile

        target = Path(dest_path)
        if target.is_symlink():
            QMessageBox.warning(self, "Ошибка сохранения", "Отказ записи по символьной ссылке.")
            return
        tmp_name = None
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with _tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tf:
                tmp_name = tf.name
                tf.write(plain_bytes)
                tf.flush()
                _os.fsync(tf.fileno())
            _os.replace(tmp_name, target)
            tmp_name = None
        except Exception as exc:
            QMessageBox.warning(self, "Ошибка записи", f"Не удалось сохранить файл:\n{type(exc).__name__}")
        finally:
            if tmp_name and _os.path.exists(tmp_name):
                _os.unlink(tmp_name)

    # ═════════════════════════════════════════════════════════════════════
    # PACKAGE VI: READABLE 60-DIGIT SAFETY NUMBERS & GROUP PEER VERIFICATION
    # ═════════════════════════════════════════════════════════════════════

    def _format_key_verification_prompt(
        self,
        username: str,
        peer_public_key: str,
        fingerprint_hex: str,
        *,
        verified: bool = False,
    ) -> str:
        safety_block = ""
        try:
            from app.contact_keys import safe_safety_number_display
            our_pub = crypto.get_public_key_b64()
            safety_block = safe_safety_number_display(our_pub, peer_public_key)
        except Exception:
            safety_block = ""

        parts = [f"Контакт: @{username}"]
        if safety_block:
            parts.append(f"Код безопасности (одинаков у вас и у @{username}):\n{safety_block}")
        parts.append(f"SHA-256 отпечаток ключа:\n{fingerprint_hex}")
        if not verified:
            parts.append(
                "Сверьте 2–3 блока цифр голосом или по независимому каналу связи.\n"
                "Цифры полностью совпадают?"
            )
        return "\n\n".join(parts)

    def _verify_group_members_dialog(self) -> int:
        if state.current_chat_type != "group" or not state.current_group_id:
            return 0
        group_id = state.current_group_id
        group_data = state.groups.get(group_id)
        if not isinstance(group_data, dict) or group_data.get("archived"):
            return 0

        members = [
            m for m in (group_data.get("members") or [])
            if isinstance(m, dict)
            and isinstance(m.get("device_id"), str)
            and m.get("device_id") != state.device_id
            and isinstance(m.get("public_key"), str)
        ]
        if not members:
            self._fetch_group_members_and_rotate(group_id)
            QMessageBox.information(
                self,
                "Участники группы",
                "Запрашиваем актуальный список устройств участников группы с сервера…",
            )
            return 0

        account = (state.username, state.device_id, (state.server_url or "").rstrip("/"))
        candidates = []
        for m in members:
            dev_id = m["device_id"]
            pub = m["public_key"]
            uname = m.get("username") or self._find_username_by_device_id(dev_id) or ""
            dev_name = m.get("device_name") or "Устройство"
            is_ver = False
            if uname and uname in state.allies:
                ctx = RecipientContext(uname, dev_id, pub, account[0], account[1], account[2])
                is_ver = recipient_is_verified(state, ctx)
            badge = "✓ Проверен" if is_ver else "⚠ Не проверен"
            title = f"@{uname}" if uname else f"Устройство {dev_id[:8]}"
            candidates.append((f"{title} ({dev_name}) — {badge}", uname, dev_id, dev_name, pub, is_ver, m.get("user_id")))

        labels = [c[0] for c in candidates]
        choice, ok = QInputDialog.getItem(
            self,
            "Сверка ключей участников группы",
            "Выберите участника для сверки 60-значного кода безопасности:",
            labels,
            0,
            False,
        )
        if not ok or choice not in labels:
            return 0

        _, uname, dev_id, dev_name, pub, is_ver, member_uid = candidates[labels.index(choice)]
        try:
            fp_hex = fingerprint_public_key(pub)
        except Exception:
            QMessageBox.warning(self, "Некорректный ключ", "Публичный ключ участника повреждён.")
            return 0

        display_uname = uname or dev_id[:8]
        if is_ver:
            QMessageBox.information(
                self,
                "Ключ уже подтверждён",
                self._format_key_verification_prompt(display_uname, pub, fp_hex, verified=True),
            )
            return 1

        prompt = self._format_key_verification_prompt(display_uname, pub, fp_hex, verified=False)
        ans = QMessageBox.question(
            self,
            "Подтверждение участника группы",
            prompt,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if ans != QMessageBox.Yes:
            return 0

        if uname:
            ally_entry = state.allies.setdefault(
                uname,
                {"user_id": member_uid or f"grp_{uname}", "devices": []},
            )
            existing_dev = next((d for d in ally_entry.get("devices", []) if d.get("device_id") == dev_id), None)
            if existing_dev is not None and existing_dev.get("public_key") != pub:
                QMessageBox.warning(
                    self,
                    "Конфликт ключа!",
                    f"Устройство @{uname} уже сохранено с другим ключом. Автоматическая замена заблокирована.",
                )
                return 0
            if existing_dev is None:
                existing_dev = {"device_id": dev_id, "device_name": dev_name, "public_key": pub, "fingerprint": fp_hex}
                ally_entry.setdefault("devices", []).append(existing_dev)
            ctx = RecipientContext(uname, dev_id, pub, account[0], account[1], account[2])
            existing_dev["verified_fingerprint"] = fp_hex
            existing_dev["verified_scope"] = verification_scope(ctx)
            self._save_allies_to_storage()
            if not self._get_ally_item(uname):
                self._add_ally_card(uname)

        self.ensure_my_group_sender_key(group_id)
        self.contact_verification_changed.emit()
        return 1

    # ═════════════════════════════════════════════════════════════════════
    # PACKAGE VII: MESSAGE EDITING (`edit_msg`) & PINNED HEADER BANNER
    # ═════════════════════════════════════════════════════════════════════

    def _init_pinned_banner_ui(self):
        self.pinned_banner = QFrame()
        self.pinned_banner.setObjectName("ReplyPreview")
        self.pinned_banner.setFixedHeight(38)
        self.pinned_banner.setVisible(False)
        lay = QHBoxLayout(self.pinned_banner)
        lay.setContentsMargins(24, 4, 24, 4)
        lay.setSpacing(10)

        self.pinned_jump_btn = QPushButton("📌 Закреплено")
        self.pinned_jump_btn.setFlat(True)
        self.pinned_jump_btn.setCursor(Qt.PointingHandCursor)
        self.pinned_jump_btn.setStyleSheet("text-align: left; font-weight: 600;")
        self.pinned_jump_btn.clicked.connect(self._on_pinned_banner_clicked)

        self.pinned_unpin_btn = QPushButton("✕")
        self.pinned_unpin_btn.setFixedSize(26, 26)
        self.pinned_unpin_btn.setCursor(Qt.PointingHandCursor)
        self.pinned_unpin_btn.setToolTip("Открепить сообщение")
        self.pinned_unpin_btn.clicked.connect(self._unpin_current_chat_message)

        lay.addWidget(self.pinned_jump_btn, 1)
        lay.addWidget(self.pinned_unpin_btn, 0)
        self._current_pinned_msg_id = ""

    def _refresh_pinned_banner(self):
        if not hasattr(self, "pinned_banner"):
            return
        chat_key = self._current_chat_storage_key()
        get_pin_fn = getattr(globals().get("storage"), "get_pinned_message", None)
        pin_info = get_pin_fn(state.username, chat_key) if (chat_key and callable(get_pin_fn)) else None
        if isinstance(pin_info, dict) and pin_info.get("msg_id"):
            self._current_pinned_msg_id = pin_info["msg_id"]
            prev = (pin_info.get("preview") or "Сообщение").replace("\n", " ")
            if len(prev) > 85:
                prev = prev[:85] + "…"
            self.pinned_jump_btn.setText(f"📌 Закреплено: {prev}")
            self.pinned_banner.setVisible(True)
        else:
            self._current_pinned_msg_id = ""
            self.pinned_banner.setVisible(False)

    def _on_pinned_banner_clicked(self):
        mid = getattr(self, "_current_pinned_msg_id", "")
        if mid:
            self._scroll_to_message(mid)

    def _on_bubble_edit_requested(self, msg_id: str, current_text: str):
        if not msg_id or not isinstance(current_text, str):
            return
        if current_text.startswith(("[IMAGE_META]|", "[VOICE_META]|", "[FILE_META]|")):
            return
        self._reply_to_msg_id = None
        self._reply_to_text = None
        self._reply_to_sender = None
        self._editing_msg_id = msg_id
        self.reply_preview_sender.setText("✏ Редактирование сообщения")
        preview = current_text[:60] + "…" if len(current_text) > 60 else current_text
        self.reply_preview_text.setText(preview)
        self.reply_preview.setVisible(True)
        self.msg_input.setPlainText(current_text)
        cursor = self.msg_input.textCursor()
        cursor.movePosition(cursor.End)
        self.msg_input.setTextCursor(cursor)
        self.msg_input.setFocus()

    def _submit_message_edit(self, new_text: str):
        edit_id = getattr(self, "_editing_msg_id", None)
        if not edit_id or not new_text:
            return
        if new_text.startswith(("[IMAGE_META]|", "[VOICE_META]|", "[FILE_META]|", "[EDIT_MSG]|", "[PIN_MSG]|")):
            QMessageBox.warning(self, "Недопустимый текст", "Служебный префикс запрещён.")
            return
        chat_key = self._current_chat_storage_key()
        if not chat_key:
            return

        if state.current_chat_type == "ally":
            if not state.current_chat_username:
                return
            try:
                ctx = capture_recipient(state)
            except ValueError as exc:
                QMessageBox.warning(self, "Редактирование недоступно", str(exc))
                return
            if not self._verify_call_contact(ctx.username, ctx.device_id):
                return
            if not is_active_recipient(state, ctx):
                return

        edit_fn = getattr(storage, "edit_message", None)
        if not callable(edit_fn) or not edit_fn(
            state.username, chat_key, edit_id, new_text, only_mine=True
        ):
            QMessageBox.warning(self, "Ошибка редактирования", "Не удалось изменить сообщение в локальной истории.")
            self._cancel_reply()
            return

        self._cancel_reply()
        self.msg_input.clear()

        for i in range(self.messages_layout.count() - 1):
            w = self.messages_layout.itemAt(i).widget()
            if getattr(w, "msg_id", None) == edit_id and hasattr(w, "set_edited_text"):
                w.set_edited_text(new_text)
                break

        if state.current_chat_type == "group" and state.current_group_id:
            self._send_group_control_text(state.current_group_id, f"[EDIT_MSG]|{edit_id}|{new_text}")
        elif state.current_chat_type == "ally" and state.current_chat_username:
            if getattr(state, "current_chat_device_id", None) and callable(getattr(self, "_verify_call_contact", None)):
                if not self._verify_call_contact(state.current_chat_username, state.current_chat_device_id):
                    return
            self._send_system_payload(
                state.current_chat_username,
                {"type": "edit_msg", "msg_id": edit_id, "new_text": new_text},
            )

    def _on_bubble_pin_requested(self, msg_id: str, preview_text: str):
        if not msg_id:
            return
        chat_key = self._current_chat_storage_key()
        if not chat_key:
            return
        clean_prev = (preview_text or "Вложение").replace("|", "/").replace("\n", " ").strip()[:240]
        set_pin_fn = getattr(storage, "set_pinned_message", None)
        if callable(set_pin_fn):
            set_pin_fn(state.username, chat_key, {"msg_id": msg_id, "preview": clean_prev})
        self._refresh_pinned_banner()

        if state.current_chat_type == "group" and state.current_group_id:
            self._send_group_control_text(state.current_group_id, f"[PIN_MSG]|{msg_id}|{clean_prev}")
        elif state.current_chat_type == "ally" and state.current_chat_username:
            if getattr(state, "current_chat_device_id", None) and callable(getattr(self, "_verify_call_contact", None)):
                if not self._verify_call_contact(state.current_chat_username, state.current_chat_device_id):
                    return
            self._send_system_payload(
                state.current_chat_username,
                {"type": "pin_msg", "msg_id": msg_id, "preview": clean_prev},
            )

    def _unpin_current_chat_message(self):
        chat_key = self._current_chat_storage_key()
        if not chat_key:
            return
        set_pin_fn = getattr(storage, "set_pinned_message", None)
        if callable(set_pin_fn):
            set_pin_fn(state.username, chat_key, None)
        self._refresh_pinned_banner()

        if state.current_chat_type == "group" and state.current_group_id:
            self._send_group_control_text(state.current_group_id, "[PIN_MSG]||")
        elif state.current_chat_type == "ally" and state.current_chat_username:
            if getattr(state, "current_chat_device_id", None) and callable(getattr(self, "_verify_call_contact", None)):
                if not self._verify_call_contact(state.current_chat_username, state.current_chat_device_id):
                    return
            self._send_system_payload(
                state.current_chat_username,
                {"type": "pin_msg", "msg_id": "", "preview": ""},
            )

    def _send_group_control_text(self, group_id: str, control_text: str):
        group_data = state.groups.get(group_id)
        if not group_data or group_data.get("archived"):
            return
        self.ensure_my_group_sender_key(group_id)
        my_sk = group_data.get("my_sender_key")
        if not my_sk:
            return
        try:
            enc_res = group_crypto.encrypt_group_message(
                control_text,
                my_sk,
                group_id=group_id,
                sender_device_id=state.device_id,
            )
            self._save_group_keys_safe()
        except Exception:
            return
        server_payload = {
            "group_id": group_id,
            "encrypted_blob": enc_res["blob"],
            "signature": enc_res["signature"],
            "sender_key_id": enc_res["key_id"],
            "epoch": enc_res["epoch"],
            "chain_index": enc_res["chain_index"],
        }
        req_ctx = (state.username, state.server_url, state.device_id, state.token)
        sw = SendGroupMessageWorker(state.server_url, state.token, server_payload)
        sw.account_context = req_ctx
        sw.group_id = group_id
        sw.finished.connect(lambda s, d, w=sw: self._on_group_send_finished(s, d, w), Qt.QueuedConnection)
        self._net_workers.append(sw)
        sw.start()