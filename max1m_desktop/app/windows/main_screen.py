import time
import threading
import random
import pyaudio
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
    QStackedWidget, QListWidgetItem, QMessageBox, QFileDialog,
    QGraphicsDropShadowEffect, QGraphicsOpacityEffect,
    QSlider, QMenu, QSizePolicy, QWidget
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtGui import QPainter, QIcon, QPixmap, QFontMetrics, QCursor, QColor, QImage, QRadialGradient, QBrush, QPainterPath
from pathlib import Path
from datetime import datetime

from app.state import state
from app.crypto_box import crypto
from app.group_crypto import group_crypto
from app.workers import (
    FindUserWorker, SendMessageWorker, UploadFileWorker, DownloadFileWorker,
    CreateGroupWorker, SendGroupMessageWorker, SyncGroupMessagesWorker,
    FetchGroupsWorker, FetchGroupSenderKeysWorker,
    DeleteGroupWorker, LeaveGroupWorker, GrantFileAccessWorker
)
from app.windows.widgets.message_bubble import MessageBubble
from app.windows.widgets.smart_input import SmartInput
from app.secure_storage import storage
from app.webrtc_manager import rtc, SCREEN_QUALITY_PRESETS
from app.voice_cache import voice_cache
from app.theme import get_theme

ICONS_PATH = Path(__file__).parent.parent / "assets" / "icons"

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
    rtc_state_changed          = Signal(str)
    _voice_playback_finished   = Signal(object)
    _voice_progress_update     = Signal(object, float)
    _voice_level_signal        = Signal(float)

    def __init__(self):
        super().__init__()
        self.setObjectName("MainScreenFrame")

        # ── Базовое состояние ─────────────────────────────────────
        self.find_worker     = None
        self._net_workers    = []
        self._image_cache    = {}
        self.settings_screen = None

        # ── Звонки ────────────────────────────────────────────────
        self.active_call_username   = None
        self._active_call_device_id = None

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
        self._current_playing_bubble  = None
        self._voice_playback_stream   = None
        self._voice_playback_lock     = threading.Lock()
        self._voice_is_seeking        = False

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
        self.msg_input.textChanged.connect(self._on_typing)

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

        input_layout.addWidget(self.attach_btn, 0, Qt.AlignBottom)
        input_layout.addWidget(self.msg_input)
        input_layout.addWidget(self._action_btn_stack, 0, Qt.AlignBottom)

        chat_layout.addWidget(self.chat_header)
        chat_layout.addWidget(self.search_bar)
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
        self.screen_share_overlay.cancelled.connect(self._on_screen_share_cancelled)
        self.screen_share_viewer = ScreenShareViewer(self)
        self.screen_share_viewer.close_requested.connect(self._stop_remote_screen_share)
        self.screen_share_viewer.maximize_requested.connect(self._toggle_screen_share_maximize)
        self.screen_share_viewer.setVisible(False)

        chat_layout.addWidget(self.screen_share_viewer, 1)

        self._voice_playback_finished.connect(self._on_voice_playback_finished)
        self._voice_progress_update.connect(self._on_voice_progress_update)
        self._voice_level_signal.connect(self._on_voice_level_update)

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

    def process_incoming_message(self, data: dict, is_sync: bool = False):
        try:
            sender_id      = data.get("sender_device_id")
            encrypted_blob = data.get("encrypted_blob")
            signature      = data.get("signature")
            if not sender_id or not encrypted_blob:
                return
            if not signature:
                signature = hashlib.sha256(str(encrypted_blob).encode()).hexdigest()

            sender_username, sender_pub_key = None, None
            for username, ally_data in state.allies.items():
                for dev in ally_data.get("devices", []):
                    if dev.get("device_id") == sender_id:
                        sender_username = username
                        sender_pub_key  = dev.get("public_key")
                        break
                if sender_username:
                    break

            if not sender_pub_key:
                return
            if not crypto.verify_signature(encrypted_blob, signature, sender_pub_key):
                return

            decrypted_text = crypto.decrypt_message(encrypted_blob, sender_pub_key)
            self._handle_decrypted_payload(
                sender_username, decrypted_text, signature, is_sync
            )
        except Exception as e:
            print(f"[PROCESS] ❌ {type(e).__name__}: {e}")
        self.incoming_message_processed.emit(data)

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
                                   signature: str, is_sync: bool = False):
        try:
            payload = json.loads(decrypted_text)
        except json.JSONDecodeError:
            payload = {"type": "text", "text": decrypted_text, "msg_id": signature}

        msg_type = payload.get("type", "text")
        if msg_type.startswith("webrtc_"):
            return

        if msg_type == "typing":
            if state.current_chat_username == sender_username:
                self.typing_label.setText(f"@{sender_username} печатает...")
                self.typing_label.setVisible(True)
                self._typing_timer.start(4000)
            return

        if msg_type == "read_ack":
            ack_ids = payload.get("msg_ids", [])
            if storage.mark_messages_as_read(state.username, sender_username, ack_ids):
                if state.current_chat_username == sender_username:
                    for i in range(self.messages_layout.count() - 1):
                        widget = self.messages_layout.itemAt(i).widget()
                        if hasattr(widget, "msg_id") and widget.msg_id in ack_ids:
                            widget.mark_as_read()
            return

        if msg_type == "delete_msg":
            deleted_msg_id = payload.get("msg_id")
            if deleted_msg_id:
                storage.delete_message(state.username, sender_username, deleted_msg_id)
                voice_cache.delete(deleted_msg_id)
                if state.current_chat_username == sender_username:
                    for i in range(self.messages_layout.count() - 1):
                        widget = self.messages_layout.itemAt(i).widget()
                        if hasattr(widget, "msg_id") and widget.msg_id == deleted_msg_id:
                            for sig in (
                                "reply_requested", "delete_requested",
                                "voice_play_requested", "voice_seek_requested",
                                "scroll_to_msg_requested", "image_view_requested",
                            ):
                                try:
                                    getattr(widget, sig).disconnect()
                                except Exception:
                                    pass
                            widget.setParent(None)
                            widget.deleteLater()
                            break
            return

        msg_id           = payload.get("msg_id", signature)
        is_window_active = self.window().isActiveWindow()
        is_chat_open     = (state.current_chat_username == sender_username)
        is_read_now      = is_chat_open and is_window_active
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
            )
            if is_new:
                card = self._get_ally_card(sender_username)
                if card:
                    card.update_preview(text)
                ally_item = self._get_ally_item(sender_username)
                if ally_item:
                    ally_item.last_activity = time.time()
                    self.allies_list.sortItems(Qt.DescendingOrder)

            if is_chat_open:
                if is_window_active:
                    self._send_system_payload(
                        sender_username, {"type": "read_ack", "msg_ids": [msg_id]}
                    )
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
            if not is_chat_open and is_new:
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
            if not file_id or not secret_key:
                return
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
            )
            if is_new:
                card = self._get_ally_card(sender_username)
                if card:
                    card.update_preview("Фото")
                ally_item = self._get_ally_item(sender_username)
                if ally_item:
                    ally_item.last_activity = time.time()
                    self.allies_list.sortItems(Qt.DescendingOrder)
                if is_chat_open:
                    if is_window_active:
                        self._send_system_payload(
                            sender_username,
                            {"type": "read_ack", "msg_ids": [msg_id]}
                        )
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
                        lambda s, d, fid, w=worker: self._on_download_finished(s, d, w)
                    )
                    self._net_workers.append(worker)
                    worker.start()
                else:
                    if card:
                        card.increment_unread()
                if should_notify:
                    main_window = self.window()
                    if hasattr(main_window, "show_notification"):
                        main_window.show_notification(f"@{sender_username}", "Фото")

        elif msg_type == "voice":
            file_id    = payload.get("file_id")
            secret_key = payload.get("secret_key")
            duration   = payload.get("duration", 0)
            if not file_id or not secret_key:
                return
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
            )
            if is_new:
                card = self._get_ally_card(sender_username)
                if card:
                    card.update_preview("Голосовое")
                ally_item = self._get_ally_item(sender_username)
                if ally_item:
                    ally_item.last_activity = time.time()
                    self.allies_list.sortItems(Qt.DescendingOrder)
                if is_chat_open:
                    if is_window_active:
                        self._send_system_payload(
                            sender_username,
                            {"type": "read_ack", "msg_ids": [msg_id]}
                        )
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
                    self._download_voice_for_bubble(bubble, file_id, secret_key, msg_id)
                else:
                    if card:
                        card.increment_unread()
                if should_notify:
                    main_window = self.window()
                    if hasattr(main_window, "show_notification"):
                        main_window.show_notification(
                            f"@{sender_username}", "Голосовое сообщение"
                        )

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
        messages = storage.load_messages(state.username, username)
        if messages:
            last_msg = messages[-1]
            raw_text = last_msg.get("text", "")
            if raw_text.startswith("[IMAGE_META]"):
                card.update_preview("Фото")
            elif raw_text.startswith("[VOICE_META]"):
                card.update_preview("Голосовое")
            else:
                card.update_preview(raw_text)
            unread_ids = storage.get_unread_incoming_msg_ids(state.username, username)
            if unread_ids:
                card.unread_count = len(unread_ids)
                card.increment_unread()
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
        saved_allies = storage.load_allies(state.username)
        if saved_allies:
            state.allies = saved_allies
            self.allies_list.clear()
            for username in saved_allies.keys():
                self._add_ally_card(username)
            self.allies_list.sortItems(Qt.DescendingOrder)

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
        self.find_worker.finished.connect(self._on_search_finished)
        self.find_worker.start()

    def _on_search_finished(self, success: bool, data):
        self.add_ally_btn.setEnabled(True)
        self.ally_input.setEnabled(True)
        if success:
            ally_username = data.get("username")
            state.allies[ally_username] = data
            if not self._get_ally_item(ally_username):
                self._add_ally_card(ally_username)
                self.ally_input.clear()
                self.search_status.setVisible(False)
                self._save_allies_to_storage()
                new_item = self._get_ally_item(ally_username)
                if new_item:
                    new_item.last_activity = time.time()
                    self.allies_list.sortItems(Qt.DescendingOrder)
            else:
                self.search_status.setText("Уже в списке.")
                self.search_status.setVisible(True)
        else:
            self.search_status.setText(str(data))
            self.search_status.setVisible(True)

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

        self.chat_title.setText(group_data["name"])
        self._set_chat_header_icon("group")
        self.call_btn.setVisible(False)
        self.search_btn.setVisible(True)
        self.chat_menu_btn.setVisible(True)
        self.right_stack.setCurrentWidget(self.chat_area)
        self.msg_input.setEnabled(True)
        self.attach_btn.setEnabled(True)
        self.mic_input_btn.setEnabled(True)
        self.send_btn.setEnabled(True)
        self.msg_input.setPlaceholderText(f"Сообщение в {group_data['name']}...")
        self.msg_input.setFocus()
        self.clear_messages()
        self._load_group_message_history(group_id)

    def _on_ally_selected(self, item):
        selected_username = item.data(Qt.UserRole)
        ally_data = state.allies.get(selected_username)
        if not ally_data:
            return
        card = self.allies_list.itemWidget(item)
        if isinstance(card, AllyCardWidget):
            card.reset_unread()

        state.current_chat_type      = "ally"
        state.current_group_id       = None
        state.current_chat_username  = selected_username
        state.current_chat_device_id = ally_data["devices"][-1]["device_id"]

        self.chat_title.setText(f"@{selected_username}")
        self._set_chat_header_icon("ally")
        self.call_btn.setVisible(True)
        self.search_btn.setVisible(True)
        self.chat_menu_btn.setVisible(True)
        self.right_stack.setCurrentWidget(self.chat_area)
        self.msg_input.setEnabled(True)
        self.attach_btn.setEnabled(True)
        self.mic_input_btn.setEnabled(True)
        self.send_btn.setEnabled(True)
        self.msg_input.setPlaceholderText(f"Сообщение для {selected_username}...")
        self.msg_input.setFocus()
        self.clear_messages()
        self._load_message_history(selected_username)

        unread_ids = storage.get_unread_incoming_msg_ids(state.username, selected_username)
        if unread_ids:
            storage.mark_messages_as_read(state.username, selected_username, unread_ids)
            self._send_system_payload(
                selected_username, {"type": "read_ack", "msg_ids": unread_ids}
            )

    def open_chat_by_username(self, username: str):
        item = self._get_ally_item(username)
        if item:
            self._on_ally_selected(item)
            self.allies_list.setCurrentItem(item)

    def clear_messages(self):
        if self._current_playing_bubble:
            try:
                self._current_playing_bubble._is_playing = False
            except RuntimeError:
                pass
            self._current_playing_bubble = None
        for i in reversed(range(self.messages_layout.count() - 1)):
            item = self.messages_layout.itemAt(i)
            if item.widget():
                item.widget().setParent(None)

    def _load_message_history(self, ally_username: str):
        messages = storage.load_messages(state.username, ally_username)

        for msg in messages:
            raw_text = msg.get("text", "")
            is_mine = msg.get("is_mine", False)
            msg_id = msg.get("msg_id")
            is_read = msg.get("is_read", False)
            reply_to_text = msg.get("reply_to_text")
            reply_to_sender = msg.get("reply_to_sender")
            reply_to_msg_id = msg.get("reply_to_msg_id")

            # ── Голосовое ─────────────────────────────────────────────
            if raw_text.startswith("[VOICE_META]|"):
                parts = raw_text.split("|")
                if len(parts) >= 4:
                    file_id, secret_key, duration_str = parts[1], parts[2], parts[3]

                    try:
                        duration = float(duration_str)
                    except Exception:
                        duration = 0.0

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

                    if reply_to_msg_id:
                        bubble.set_reply_to_msg_id(reply_to_msg_id)

                    self._connect_bubble_signals(bubble, ally_username)
                    self.messages_layout.insertWidget(
                        self.messages_layout.count() - 1,
                        bubble
                    )

                    if voice_cache.exists(msg_id):
                        wav_data = voice_cache.load(msg_id)
                        if wav_data:
                            bubble.set_voice_data(wav_data)
                        else:
                            self._download_voice_for_bubble(
                                bubble, file_id, secret_key, msg_id
                            )
                    else:
                        self._download_voice_for_bubble(
                            bubble, file_id, secret_key, msg_id
                        )
                    continue

            # ── Картинка ──────────────────────────────────────────────
            if raw_text.startswith("[IMAGE_META]|"):
                parts = raw_text.split("|")
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

                    if reply_to_msg_id:
                        bubble.set_reply_to_msg_id(reply_to_msg_id)

                    self._connect_bubble_signals(bubble, ally_username)
                    self.messages_layout.insertWidget(
                        self.messages_layout.count() - 1,
                        bubble
                    )

                    if file_id in self._image_cache:
                        bubble.set_image(
                            self._image_cache[file_id],
                            caption=saved_caption
                        )
                    else:
                        worker = DownloadFileWorker(
                            state.server_url,
                            state.token,
                            file_id
                        )
                        worker.secret_key = secret_key
                        worker.bubble = bubble
                        worker.file_id_cache = file_id
                        worker.caption = saved_caption

                        worker.finished.connect(
                            lambda s, d, fid, w=worker:
                            self._on_download_finished(s, d, w),
                            Qt.QueuedConnection
                        )

                        self._net_workers.append(worker)
                        worker.start()
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

            if reply_to_msg_id:
                bubble.set_reply_to_msg_id(reply_to_msg_id)

            self._connect_bubble_signals(bubble, ally_username)
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
        if getattr(state, "current_chat_type", "ally") == "group":
            self._send_group_text_message(text)
        else:
            self._send_ally_text_message(text)

    def _send_ally_text_message(self, text: str):
        if not state.current_chat_username:
            return
        self.msg_input.clear()
        msg_id = f"msg_{uuid.uuid4().hex[:16]}"

        bubble = MessageBubble(
            text, is_mine=True, is_read=False,
            reply_to_text=self._reply_to_text,
            reply_to_sender=self._reply_to_sender,
            reply_to_msg_id=self._reply_to_msg_id,
        )
        bubble.msg_id = msg_id
        self._connect_bubble_signals(bubble, state.username)
        self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)
        QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
            self.messages_scroll.verticalScrollBar().maximum()
        ))

        storage.save_message(
            state.username, state.current_chat_username, text,
            is_mine=True, msg_id=msg_id, is_read=False,
            reply_to_msg_id=self._reply_to_msg_id,
            reply_to_text=self._reply_to_text,
            reply_to_sender=self._reply_to_sender,
        )

        card = self._get_ally_card(state.current_chat_username)
        if card:
            card.update_preview(text)
        ally_item = self._get_ally_item(state.current_chat_username)
        if ally_item:
            ally_item.last_activity = time.time()
            self.allies_list.sortItems(Qt.DescendingOrder)

        payload = {"type": "text", "text": text, "msg_id": msg_id}
        if self._reply_to_msg_id:
            payload["reply_to"] = {
                "msg_id": self._reply_to_msg_id,
                "text":   self._reply_to_text,
                "sender": self._reply_to_sender,
            }
        self._send_system_payload(state.current_chat_username, payload)
        self._cancel_reply()
        self.msg_input.setFocus()

    def _send_group_text_message(self, text: str):
        group_id = state.current_group_id
        if not group_id:
            return
        group_data = state.groups.get(group_id)
        if not group_data:
            return
        my_sender_key = group_data.get("my_sender_key")
        if not my_sender_key:
            return

        try:
            enc_result = group_crypto.encrypt_group_message(text, my_sender_key)
            signature_bytes = crypto.private_key.sign(
                enc_result["blob"].encode("utf-8")
            ).signature
            signature_b64 = Base64Encoder.encode(signature_bytes).decode("utf-8")
        except Exception as e:
            print(f"[GROUP] Ошибка шифрования: {e}")
            return

        msg_id = f"msg_{uuid.uuid4().hex[:16]}"
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
        )

        card = self._get_group_card(group_id)
        if card:
            card.update_preview(text)

        server_payload = {
            "group_id":       group_id,
            "encrypted_blob": enc_result["blob"],
            "signature":      signature_b64,
            "sender_key_id":  enc_result["key_id"],
            "chain_index":    enc_result["chain_index"],
        }
        worker = SendGroupMessageWorker(state.server_url, state.token, server_payload)
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

    def _on_attach_file(self):
        if not state.current_chat_username:
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите картинку", "", "Images (*.png *.jpg *.jpeg *.webp)"
        )
        if not file_path:
            return
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            self._show_image_preview(file_data)
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Сбой чтения:\n{e}")

    def _on_image_pasted(self, file_data: bytes):
        if not state.current_chat_username:
            return
        self._show_image_preview(file_data)

    def _prepare_file_for_upload(self, file_data: bytes, caption: str = ""):
        secret_key = crypto.generate_file_key()
        try:
            encrypted_blob = crypto.encrypt_file(file_data, secret_key)
        except Exception as e:
            return QMessageBox.critical(self, "Ошибка", f"Сбой шифрования: {e}")

        self.msg_input.setEnabled(False)
        self.attach_btn.setEnabled(False)
        self.send_btn.setEnabled(False)
        self.msg_input.setPlaceholderText(
            f"Шифрование и отправка ({len(file_data) // 1024} KB)..."
        )

        worker = UploadFileWorker(state.server_url, state.token, encrypted_blob)
        worker.secret_key = secret_key
        worker.raw_file_data = file_data
        worker.caption = caption

        worker.finished.connect(
            lambda s, d, w=worker: self._on_upload_finished(s, d, w),
            Qt.QueuedConnection
        )

        self._net_workers.append(worker)
        worker.start()

    def _on_upload_finished(self, success: bool, data: dict, worker: UploadFileWorker):
        self.msg_input.setEnabled(True)
        self.attach_btn.setEnabled(True)
        self.send_btn.setEnabled(True)
        self.msg_input.setPlaceholderText("Написать сообщение...")
        self.msg_input.setFocus()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if not success:
            return QMessageBox.warning(self, "Ошибка", "Не удалось загрузить файл.")

        file_id    = data.get("file_id")
        secret_key = worker.secret_key
        caption    = getattr(worker, "caption", "")
        msg_id     = f"msg_{uuid.uuid4().hex[:16]}"
        special_text = f"[IMAGE_META]|{file_id}|{secret_key}|{caption}"

        # ── Безопасность файлов ─────────────────────────────────────────
        # Сервер теперь не отдаёт файлы по UUID без авторизации. Выдаём
        # устройству получателя право скачать — в фоне, без блокировки UI.
        # Грант идемпотентен; если не успеет — сообщение всё равно уйдёт,
        # получатель повторит скачивание позже.
        recipient_device_id = state.current_chat_device_id
        if recipient_device_id:
            grant_worker = GrantFileAccessWorker(
                state.server_url, state.token,
                file_id, recipient_device_id
            )
            grant_worker.start()

        bubble = MessageBubble("", is_mine=True, is_read=False, caption=caption)
        bubble.msg_id = msg_id
        bubble.set_image(worker.raw_file_data, caption=caption)
        self._connect_bubble_signals(bubble, state.username)
        self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)
        QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
            self.messages_scroll.verticalScrollBar().maximum()
        ))

        storage.save_message(
            state.username, state.current_chat_username, special_text,
            is_mine=True, msg_id=msg_id, is_read=False,
        )
        card = self._get_ally_card(state.current_chat_username)
        if card:
            card.update_preview("Фото")
        ally_item = self._get_ally_item(state.current_chat_username)
        if ally_item:
            ally_item.last_activity = time.time()
            self.allies_list.sortItems(Qt.DescendingOrder)

        self._send_system_payload(
            state.current_chat_username,
            {
                "type": "image", "file_id": file_id,
                "secret_key": secret_key, "caption": caption, "msg_id": msg_id,
            },
        )

    def _on_download_finished(self, success: bool, data: bytes, worker: DownloadFileWorker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if not success:
            worker.bubble.msg_label.setText("❌ Ошибка скачивания")
            worker.bubble.msg_label.setVisible(True)
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

    def _send_system_payload(self, receiver_username: str, payload_dict: dict):
        ally_data = state.allies.get(receiver_username)
        if not ally_data or not ally_data.get("devices"):
            return

        try:
            payload_str = json.dumps(payload_dict, ensure_ascii=False)
            encrypted_data = crypto.encrypt_message(
                payload_str,
                ally_data["devices"][-1]["public_key"]
            )

            payload = {
                "receiver_device_id": ally_data["devices"][-1]["device_id"],
                "encrypted_blob": encrypted_data["encrypted_blob"],
                "signature": encrypted_data["signature"],
            }

            self._net_workers = [w for w in self._net_workers if w.isRunning()]

            worker = SendMessageWorker(state.server_url, state.token, payload)
            msg_type = payload_dict.get("type")

            worker.finished.connect(
                lambda s, d, w=worker: self._on_send_finished(s, d, msg_type, w),
                Qt.QueuedConnection
            )

            self._net_workers.append(worker)
            worker.start()

        except Exception as e:
            print(f"[SEND] ❌ _send_system_payload: {e}")

    def _on_send_finished(self, success: bool, data, msg_type: str, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)

        if not success:
            print(f"[SEND] ❌ Ошибка отправки ({msg_type}): {data}")

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
            self.right_stack.addWidget(self.settings_screen)
        self.right_stack.setCurrentWidget(self.settings_screen)

    def close_settings(self):
        if state.current_chat_type == "group" and state.current_group_id:
            self.right_stack.setCurrentWidget(self.chat_area)
        elif state.current_chat_username:
            self.right_stack.setCurrentWidget(self.chat_area)
        else:
            self.right_stack.setCurrentWidget(self.empty_state)

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
        self.reply_preview.setVisible(False)

    def _connect_bubble_signals(self, bubble: MessageBubble, sender_username: str):
        bubble.set_sender(sender_username)
        bubble.reply_requested.connect(self._set_reply_to)
        bubble.delete_requested.connect(self._delete_message)
        bubble.voice_play_requested.connect(self._play_voice_message)
        bubble.voice_seek_requested.connect(self._seek_voice_message)
        bubble.scroll_to_msg_requested.connect(self._scroll_to_message)
        bubble.image_view_requested.connect(self._on_image_view_requested)

    def _scroll_to_message(self, target_msg_id: str):
        for i in range(self.messages_layout.count() - 1):
            widget = self.messages_layout.itemAt(i).widget()
            if hasattr(widget, "msg_id") and widget.msg_id == target_msg_id:
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
        if storage.delete_message(state.username, state.current_chat_username, msg_id):
            for i in range(self.messages_layout.count() - 1):
                widget = self.messages_layout.itemAt(i).widget()
                if hasattr(widget, "msg_id") and widget.msg_id == msg_id:
                    widget.setParent(None)
                    widget.deleteLater()
                    break
            voice_cache.delete(msg_id)
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

        if state.current_chat_type == "group" and state.current_group_id:
            group = state.groups.get(state.current_group_id)
            if group:
                is_creator = group.get("created_by_device_id") == state.device_id
                menu.addSeparator()
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

    def _confirm_clear_chat(self):
        name = (
            state.groups.get(state.current_group_id, {}).get("name")
            if state.current_chat_type == "group"
            else state.current_chat_username
        )
        if not name:
            return
        reply = QMessageBox.question(
            self, "Очистить историю?",
            "Вы уверены, что хотите удалить всю историю?\n\nЭто действие необратимо.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self._clear_chat()

    def _clear_chat(self):
        if state.current_chat_type == "group":
            group_id = state.current_group_id
            if group_id:
                storage.clear_chat(state.username, f"group_{group_id}")
                self.clear_messages()
                card = self._get_group_card(group_id)
                if card:
                    card.update_preview("Нет сообщений")
        else:
            if not state.current_chat_username:
                return
            storage.clear_chat(state.username, state.current_chat_username)
            self.clear_messages()
            card = self._get_ally_card(state.current_chat_username)
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
        if state.current_chat_type == "group" and state.current_group_id:
            self.clear_messages()
            self._load_group_message_history(state.current_group_id)
        elif state.current_chat_username:
            self.clear_messages()
            self._load_message_history(state.current_chat_username)

    def _load_group_message_history(self, group_id: str):
        messages = storage.load_messages(state.username, f"group_{group_id}")
        for msg in messages:
            raw_text = msg.get("text", "")
            is_mine = msg.get("is_mine", False)
            msg_id = msg.get("msg_id")
            is_read = msg.get("is_read", False)
            sender_name = msg.get("sender_name", "")

            bubble = MessageBubble(
                text=raw_text, is_mine=is_mine,
                timestamp=msg.get("timestamp"), is_read=is_read
            )
            bubble.msg_id = msg_id
            if not is_mine and sender_name:
                bubble.set_sender(sender_name)
            self._connect_bubble_signals(bubble, sender_name or state.username)
            self.messages_layout.insertWidget(
                self.messages_layout.count() - 1, bubble
            )

        if messages:
            QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
                self.messages_scroll.verticalScrollBar().maximum()
            ))

    def _do_search(self):
        query = self.search_input.text().strip()
        if not query:
            return
        if state.current_chat_type == "group" and state.current_group_id:
            chat_key = f"group_{state.current_group_id}"
        elif state.current_chat_username:
            chat_key = state.current_chat_username
        else:
            return
        results = storage.search_messages(state.username, chat_key, query)
        self.clear_messages()
        for msg in results:
            bubble = MessageBubble(
                text=msg.get("text", ""),
                is_mine=msg.get("is_mine", False),
                timestamp=msg.get("timestamp"),
                is_read=msg.get("is_read", False),
            )
            bubble.msg_id = msg.get("msg_id")
            self._connect_bubble_signals(bubble, chat_key)
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)
        if not results:
            empty_label = QLabel(f"По запросу «{query}» ничего не найдено")
            empty_label.setObjectName("SearchEmptyLabel")
            empty_label.setAlignment(Qt.AlignCenter)
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, empty_label)

    def force_remove_group(self, group_id: str):
        storage.clear_chat(state.username, f"group_{group_id}")
        state.groups.pop(group_id, None)
        for i in range(self.groups_list.count()):
            item = self.groups_list.item(i)
            if item.data(Qt.UserRole) == group_id:
                self.groups_list.takeItem(i)
                break
        if state.current_chat_type == "group" and state.current_group_id == group_id:
            state.current_chat_type  = None
            state.current_group_id   = None
            self.clear_messages()
            self.right_stack.setCurrentWidget(self.empty_state)

    def _delete_group_on_server(self):
        group_id = state.current_group_id
        worker = DeleteGroupWorker(state.server_url, state.token, group_id)
        worker.finished.connect(
            lambda s, d, w=worker: self._on_group_deleted_response(s, d, w),
            Qt.QueuedConnection
        )
        self._net_workers.append(worker)
        worker.start()

    def _leave_group_on_server(self):
        group_id = state.current_group_id
        worker = LeaveGroupWorker(state.server_url, state.token, group_id)
        worker.finished.connect(
            lambda s, d, w=worker: self._on_group_left_response(s, d, w),
            Qt.QueuedConnection
        )
        self._net_workers.append(worker)
        worker.start()

    def _on_group_deleted_response(self, success, data, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if success:
            self.force_remove_group(state.current_group_id)
        else:
            QMessageBox.warning(self, "Ошибка", str(data))

    def _on_group_left_response(self, success, data, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if success:
            self.force_remove_group(state.current_group_id)
        else:
            QMessageBox.warning(self, "Ошибка", str(data))

    # ─────────────────────────────────────────────────────────────────
    # ГОЛОСОВЫЕ — ЗАПИСЬ
    # ─────────────────────────────────────────────────────────────────

    def _start_voice_recording(self):
        if self._is_recording:
            return
        self._is_recording  = True
        self._voice_cancelled = False
        self._voice_frames  = []
        self._show_voice_recording_bar()
        self._voice_thread = threading.Thread(target=self._record_voice, daemon=True)
        self._voice_thread.start()

    def _record_voice(self):
        try:
            pa = pyaudio.PyAudio()
            self._voice_stream = pa.open(
                format=pyaudio.paInt16, channels=1, rate=16000,
                input=True, frames_per_buffer=1024,
            )
            while self._is_recording:
                data = self._voice_stream.read(1024, exception_on_overflow=False)
                self._voice_frames.append(data)
                samples    = struct.unpack(f"{len(data) // 2}h", data)
                rms        = (sum(s * s for s in samples) / len(samples)) ** 0.5
                normalized = min(1.0, rms / 2000.0)
                self._voice_level_signal.emit(normalized)
        except Exception as e:
            print(f"[VOICE] Ошибка записи: {e}")
        finally:
            if self._voice_stream:
                self._voice_stream.stop_stream()
                self._voice_stream.close()
            pa.terminate()

    def _stop_voice_recording(self):
        if not self._is_recording:
            return
        self._is_recording = False
        self._hide_voice_recording_bar()
        if self._voice_thread:
            self._voice_thread.join(timeout=1.0)
        if self._voice_cancelled or len(self._voice_frames) < 8:
            return
        wav_buffer = io.BytesIO()
        with wave.open(wav_buffer, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(16000)
            wf.writeframes(b"".join(self._voice_frames))
        voice_data = wav_buffer.getvalue()
        duration   = len(self._voice_frames) * 1024 / 16000
        self._send_voice_message(voice_data, duration)

    def _cancel_voice_recording(self):
        self._voice_cancelled = True
        self._is_recording    = False
        self._hide_voice_recording_bar()
        if self._voice_thread:
            self._voice_thread.join(timeout=1.0)
        self._voice_frames = []

    def _send_voice_message(self, voice_data: bytes, duration: float):
        if not state.current_chat_username:
            return
        secret_key     = crypto.generate_file_key()
        encrypted_data = crypto.encrypt_file(voice_data, secret_key)
        self.msg_input.setPlaceholderText("Отправка голосового...")
        self.mic_input_btn.setEnabled(False)

        worker = UploadFileWorker(state.server_url, state.token, encrypted_data)
        worker.secret_key     = secret_key
        worker.voice_data     = voice_data
        worker.voice_duration = duration
        worker.finished.connect(
            lambda s, d, w=worker: self._on_voice_upload_finished(s, d, w)
        )
        self._net_workers.append(worker)
        worker.start()

    def _on_voice_upload_finished(self, success: bool, data: dict, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        self.msg_input.setPlaceholderText(
            f"Сообщение для {state.current_chat_username}..."
        )
        self.mic_input_btn.setEnabled(True)
        if not success:
            QMessageBox.warning(self, "Ошибка", "Не удалось отправить голосовое")
            return

        file_id    = data.get("file_id")
        secret_key = worker.secret_key
        duration   = worker.voice_duration
        msg_id     = f"msg_{uuid.uuid4().hex[:16]}"

        bubble = MessageBubble(
            "", is_mine=True, is_read=False,
            voice_data=worker.voice_data, voice_duration=duration,
        )
        bubble.msg_id = msg_id
        self._connect_bubble_signals(bubble, state.username)
        self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)
        QTimer.singleShot(50, lambda: self.messages_scroll.verticalScrollBar().setValue(
            self.messages_scroll.verticalScrollBar().maximum()
        ))

        special_text = f"[VOICE_META]|{file_id}|{secret_key}|{duration:.1f}"
        storage.save_message(
            state.username, state.current_chat_username, special_text,
            is_mine=True, msg_id=msg_id, is_read=False,
        )
        card = self._get_ally_card(state.current_chat_username)
        if card:
            card.update_preview("Голосовое")
        ally_item = self._get_ally_item(state.current_chat_username)
        if ally_item:
            ally_item.last_activity = time.time()
            self.allies_list.sortItems(Qt.DescendingOrder)

        self._send_system_payload(
            state.current_chat_username,
            {
                "type": "voice", "file_id": file_id,
                "secret_key": secret_key, "duration": duration, "msg_id": msg_id,
            },
        )

    def _download_voice_for_bubble(self, bubble, file_id: str,
                                   secret_key: str, msg_id: str):
        worker = DownloadFileWorker(state.server_url, state.token, file_id)
        worker.secret_key = secret_key
        worker.bubble = bubble
        worker.is_voice = True
        worker.msg_id = msg_id

        worker.finished.connect(
            lambda s, d, fid, w=worker: self._on_voice_download_finished(s, d, w),
            Qt.QueuedConnection
        )

        self._net_workers.append(worker)
        worker.start()

    def _on_voice_download_finished(self, success: bool, data: bytes, worker):
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if not success:
            return
        try:
            decrypted_bytes = crypto.decrypt_file(data, worker.secret_key)
            worker.bubble.set_voice_data(decrypted_bytes)
            if hasattr(worker, "msg_id") and worker.msg_id:
                voice_cache.save(worker.msg_id, decrypted_bytes)
        except Exception as e:
            print(f"[VOICE] Ошибка расшифровки: {e}")

    # ─────────────────────────────────────────────────────────────────
    # ГОЛОСОВЫЕ — ВОСПРОИЗВЕДЕНИЕ
    # ─────────────────────────────────────────────────────────────────

    def _play_voice_message(self, bubble: MessageBubble, voice_data: bytes):
        if self._current_playing_bubble and self._current_playing_bubble != bubble:
            prev = self._current_playing_bubble
            prev._is_playing = False
            self._current_playing_bubble = None

        if self._current_playing_bubble == bubble and bubble._is_playing:
            bubble._is_playing = False
            self._current_playing_bubble = None
            return

        self._start_playback(bubble, voice_data, 0.0)

    def _seek_voice_message(self, bubble: MessageBubble, progress: float):
        if not bubble._voice_data:
            return
        seek_to = float(progress)
        if bubble._is_playing:
            self._voice_is_seeking = True
            bubble._is_playing = False

            def do_seek():
                acquired = self._voice_playback_lock.acquire(timeout=3.0)
                if acquired:
                    self._voice_playback_lock.release()
                self._voice_is_seeking = False
                self._start_playback(bubble, bubble._voice_data, seek_to)

            threading.Thread(target=do_seek, daemon=True).start()
        else:
            self._start_playback(bubble, bubble._voice_data, seek_to)

    def _start_playback(self, bubble: MessageBubble, voice_data: bytes,
                        start_progress: float = 0.0):
        self._current_playing_bubble = bubble
        bubble.set_playing(True)
        start_pos = float(start_progress)

        def play_audio():
            with self._voice_playback_lock:
                stream = None
                try:
                    wav_io = io.BytesIO(voice_data)
                    with wave.open(wav_io, "rb") as wf:
                        sample_rate  = wf.getframerate()
                        channels     = wf.getnchannels()
                        sample_width = wf.getsampwidth()
                        total_frames = max(wf.getnframes(), 1)
                        start_frame  = int(start_pos * total_frames)
                        if start_frame > 0:
                            wf.setpos(start_frame)

                        pa = rtc.pa
                        stream = pa.open(
                            format=pa.get_format_from_width(sample_width),
                            channels=channels,
                            rate=sample_rate,
                            output=True,
                            output_device_index=rtc.output_device_index
                        )
                        self._voice_playback_stream = stream
                        chunk_size    = 1024
                        frames_played = start_frame

                        while True:
                            chunk = wf.readframes(chunk_size)
                            if not chunk:
                                break
                            if not bubble._is_playing:
                                break
                            stream.write(chunk)
                            frames_played += chunk_size
                            progress = min(1.0, frames_played / total_frames)
                            self._voice_progress_update.emit(bubble, progress)

                except Exception as e:
                    print(f"[VOICE] Ошибка воспроизведения: {e}")
                finally:
                    if stream:
                        try:
                            stream.stop_stream()
                            stream.close()
                        except Exception:
                            pass
                    self._voice_playback_stream = None
                    self._voice_playback_finished.emit(bubble)

        threading.Thread(target=play_audio, daemon=True).start()

    def _on_voice_playback_finished(self, bubble):
        if self._voice_is_seeking:
            return
        try:
            if bubble:
                bubble.set_playing(False)
                bubble.update_playback_progress(0)
        except RuntimeError:
            pass
        self._voice_playback_stream  = None
        self._current_playing_bubble = None

    def _do_create_group(self, name: str, member_usernames: list):
        self.create_group_panel.setEnabled(False)
        my_sender_key = group_crypto.generate_sender_key()
        sender_keys_payload = []
        member_device_ids = []

        for username in member_usernames:
            ally = state.allies.get(username)
            if not ally or not ally.get("devices"):
                continue
            target_device = ally["devices"][-1]
            member_device_ids.append(target_device["device_id"])
            enc_blob, sig = group_crypto.encrypt_sender_key_for_member(
                my_sender_key, target_device["public_key"]
            )
            sender_keys_payload.append({
                "recipient_device_id": target_device["device_id"],
                "encrypted_sender_key": enc_blob,
                "sender_key_signature": sig,
            })

        if not member_device_ids:
            self.create_group_panel.setEnabled(True)
            QMessageBox.warning(self, "Ошибка", "Не удалось найти устройства участников.")
            return

        payload = {
            "name": name,
            "member_device_ids": member_device_ids,
            "sender_keys": sender_keys_payload,
        }
        worker = CreateGroupWorker(state.server_url, state.token, payload)
        worker._my_sender_key = my_sender_key
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

        if not success:
            QMessageBox.warning(self, "Ошибка", f"Не удалось создать группу:\n{data}")
            return

        group_id = data["id"]
        my_sender_key = worker._my_sender_key

        state.groups[group_id] = {
            "name": data["name"],
            "created_by_device_id": data["created_by_device_id"],
            "members": data.get("members", []),
            "my_sender_key": my_sender_key,
            "sender_keys": {},
        }

        self._add_group_card(group_id, data["name"])
        self._hide_create_group_panel()

        new_item = self._get_group_item(group_id)
        if new_item:
            self._on_group_selected(new_item)

    def _on_image_preview_send(self, file_data: bytes, caption: str):
        self.image_preview_panel.setVisible(False)
        self.image_preview_panel.clear()
        self.input_area.setVisible(True)
        self._prepare_file_for_upload(file_data, caption=caption)

    def _on_image_preview_cancel(self):
        self.image_preview_panel.setVisible(False)
        self.image_preview_panel.clear()
        self.input_area.setVisible(True)
        self.msg_input.setFocus()

    def _show_image_preview(self, file_data: bytes):
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

    def _on_voice_level_update(self, rms: float):
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

    def _on_voice_progress_update(self, bubble, progress: float):
        try:
            if bubble:
                bubble.update_playback_progress(progress)
        except RuntimeError:
            if bubble:
                bubble._is_playing = False
            self._current_playing_bubble = None

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
        self._cs_screen_btn.setToolTip("Демонстрация экрана")
        self._cs_screen_btn.clicked.connect(self._toggle_screen_share)
        self._cs_screen_btn.setVisible(False)

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
        self.screen_quality_label = QLabel(self._ce_controls)
        self.screen_quality_label.setObjectName("ScreenShareIndicator")
        self.screen_quality_label.setVisible(False)
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
        if rtc.is_in_call():
            return
        self.active_call_username   = target_username
        self._active_call_device_id = target_device_id

        first_letter = target_username[0].upper()
        self._cw_avatar_label.setText(first_letter)
        self._cw_name.setText(f"@{target_username}")
        self._cw_status.setText("Звонок...")
        self._show_pill()

        main_window = self.window()
        if hasattr(main_window, "ws_worker") and main_window.ws_worker:
            main_window.ws_worker.send_signal({
                "type":          "call_offer",
                "to_device_id":  target_device_id,
                "from_username": state.username,
            })

    def _on_incoming_call(self, data: dict):
        from_device_id = data.get("from_device_id", "")
        from_username = data.get("from_username", "")

        if not from_username:
            from_username = self._find_username_by_device_id(from_device_id) or from_device_id[:8]

        print(f"[CALL] Входящий от @{from_username} ({from_device_id})")

        if rtc.is_in_call():
            print("[CALL] Уже в звонке, отклоняем")
            main_window = self.window()
            if hasattr(main_window, "ws_worker") and main_window.ws_worker:
                main_window.ws_worker.send_signal({
                    "type": "call_ended",
                    "to_device_id": from_device_id,
                })
            return

        self.active_call_username = from_username
        self._active_call_device_id = from_device_id

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

        print(f"[CALL] Принимаем от @{self.active_call_username}")

        self._io_fade_anim.stop()
        self.incoming_overlay.hide()

        first_letter = self.active_call_username[0].upper() if self.active_call_username else "?"
        self._cw_avatar_label.setText(first_letter)
        self._cw_name.setText(f"@{self.active_call_username}")
        self._cw_status.setText("Соединение...")
        self._cs_screen_btn.setVisible(True)
        self._show_pill()

        main_window = self.window()
        if hasattr(main_window, "ws_worker") and main_window.ws_worker:
            main_window.ws_worker.send_signal({
                "type": "call_accept",
                "to_device_id": self._active_call_device_id,
            })

    def _reject_call(self):
        if self._active_call_device_id:
            main_window = self.window()
            if hasattr(main_window, "ws_worker") and main_window.ws_worker:
                main_window.ws_worker.send_signal({"type": "call_ended", "to_device_id": self._active_call_device_id})
        self.incoming_overlay.hide()
        self.active_call_username = None
        self._active_call_device_id = None

    def _on_call_accepted(self, data: dict):
        from_device_id = data.get("from_device_id", "")
        if not self._active_call_device_id:
            self._active_call_device_id = from_device_id
        self._cw_status.setText("Соединение...")
        rtc.start_call(self._active_call_device_id)



    def _on_end_call(self):
        if self._active_call_device_id:
            main_window = self.window()
            if hasattr(main_window, "ws_worker") and main_window.ws_worker:
                main_window.ws_worker.send_signal({"type": "call_ended", "to_device_id": self._active_call_device_id})
        rtc.end_call()
        self._cleanup_call()

    def _on_remote_call_ended(self, data: dict):
        rtc.end_call()
        self._cleanup_call()

    def _cleanup_call(self):
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
        actual = status if status is not None else peer_device_id_or_status
        if actual == "connected":
            self._cw_status.setText("На связи")
            self._cs_screen_btn.setVisible(True)
        elif actual in ("failed", "closed", "disconnected"):
            self._cleanup_call()

    # ─────────────────────────────────────────────────────────────────
    # SCREEN SHARE
    # ─────────────────────────────────────────────────────────────────

    def _toggle_screen_share(self):
        if not self.active_call_username: return
        if self.is_screen_sharing:
            rtc.stop_screen_share()
            self._update_screen_share_ui(False)
            self._hide_screen_share_widget()
        else:
            self.screen_share_overlay.show_overlay()

    def _on_monitor_selected(self, monitor_index: int):
        print(f"[ScreenShare] Выбран монитор #{monitor_index}")
        self._update_screen_share_ui(True, self.current_quality_profile)

        # Показываем виджет ТОЛЬКО если демка уже запущена
        # Сначала запускаем, потом показываем
        rtc.start_screen_share(
            quality=self.current_quality_profile,
            monitor_index=monitor_index
        )
        # Виджет покажется когда придут первые кадры через _on_screen_frame

    def _on_screen_share_cancelled(self):
        if getattr(rtc, "is_screen_sharing", False): rtc.stop_screen_share()

    def _update_screen_share_ui(self, is_sharing: bool, quality: str = "balanced"):
        self.is_screen_sharing = is_sharing
        self.screen_share_btn.setProperty("active", is_sharing)
        self.screen_share_btn.setToolTip("Остановить" if is_sharing else "Поделиться экраном")
        self.screen_quality_label.setVisible(is_sharing)
        self.call_pill.setProperty("screen_sharing", is_sharing)
        if is_sharing:
            w, h, fps = SCREEN_QUALITY_PRESETS.get(quality, (1280, 720, 15))
            self.screen_quality_label.setText(f"{h}p • {fps}fps")


        self.screen_share_btn.style().unpolish(self.screen_share_btn)
        self.screen_share_btn.style().polish(self.screen_share_btn)
        self.call_pill.style().unpolish(self.call_pill)
        self.call_pill.style().polish(self.call_pill)

    def _on_screen_share_started(self, from_device_id: str):
        if hasattr(self, "screen_share_viewer") and self.screen_share_viewer:
            self.screen_share_viewer.start_viewing(from_device_id)
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
        if self.is_screen_sharing:
            w, h, fps = SCREEN_QUALITY_PRESETS.get(profile, (1280, 720, 15))
            self.screen_quality_label.setText(f"{h}p • {fps}fps")

    def _on_video_track_received(self, peer_device_id: str, receiver):
        pass



    def _on_screen_frame_numpy(self, numpy_frame):
        try:
            import cv2
            rgb_frame = cv2.cvtColor(numpy_frame, cv2.COLOR_BGR2RGB)
            h, w, ch = rgb_frame.shape
            bytes_per_line = ch * w
            img = QImage(rgb_frame.data, w, h, bytes_per_line, QImage.Format_RGB888).copy()
            if not img.isNull():
                self._update_screen_share_frame(img)
        except Exception as e:
            print(f"[ScreenShare] numpy frame error: {e}")

    def _show_screen_share_widget(self):
        pass

    def _update_screen_share_frame(self, img: QImage):
        if not hasattr(self, "screen_share_viewer") or not self.screen_share_viewer:
            return
        pixmap = QPixmap.fromImage(img)
        self.screen_share_viewer.set_frame(pixmap)

    def _hide_screen_share_widget(self):
        pass

    def _stop_remote_screen_share(self):
        self._hide_screen_share_widget()
        self._update_screen_share_ui(False)

    # ─────────────────────────────────────────────────────────────────
    # UTILS
    # ─────────────────────────────────────────────────────────────────

    def _on_image_view_requested(self, pixmap):
        main_window = self.window()
        if hasattr(main_window, "show_image_viewer"): main_window.show_image_viewer(pixmap)

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
        messages = storage.load_messages(state.username, f"group_{group_id}")
        if messages:
            last_msg = messages[-1]
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