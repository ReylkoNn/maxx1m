import random
import re
import sys
import threading
from pathlib import Path
from app.windows.widgets.smart_input import SmartInput
from PySide6.QtGui import (
    QPainter, QColor, QLinearGradient, QRadialGradient, QBrush, QPen,
    QIcon, QPixmap, QPainterPath, QImage
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtCore import (
    QRectF, QRect, Qt, QPoint, QTimer,
    QPropertyAnimation, QEasingCurve, Property, Signal,
    QObject, QMetaObject, QEvent
)
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QPushButton, QStackedWidget, QLineEdit, QSizeGrip,
    QApplication, QGraphicsDropShadowEffect, QGraphicsOpacityEffect, QMessageBox
)

from app.delivery import process_delivery_page
from app.client_api import validate_server_url
from app.call_policy import allow_webrtc_signal, resolve_call_peer, call_context_valid
from app import call_envelope, identity_setup
from app.crypto_box import crypto
from app.secure_storage import storage
from app.workers import (RegisterWorker, LoginWorker, WebSocketWorker,
                         SyncMessagesWorker, AcknowledgeMessagesWorker,
                         LogoutSessionWorker)
from app.config import (
    APP_NAME,
    DEFAULT_SERVER_URL,
    WINDOW_START_WIDTH,
    WINDOW_START_HEIGHT,
    WINDOW_MIN_WIDTH,
    WINDOW_MIN_HEIGHT,
    AUTH_CARD_WIDTH,
    START_MODE,
    ENABLE_AUTH_ANIMATION,
    AUTH_ANIMATION_FPS,
    AUTH_ANIMATION_PARTICLES,
)
from app.state import state
from app.windows.main_screen import MainScreen
from app.webrtc_manager import rtc
ICONS_PATH = Path(__file__).parent.parent / "assets" / "icons"


def _render_svg_icon(svg_name: str, color: str, size: int = 18) -> QIcon:
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


class _SvgBtn(QPushButton):
    def __init__(self, svg_name: str, size: int = 24, icon_size: int = 12,
                 parent=None):
        super().__init__(parent)
        self._svg_name = svg_name
        self._icon_size = icon_size
        self.setFixedSize(size, size)
        self.setFocusPolicy(Qt.NoFocus)
        self.setText("")
        self._refresh()

    def _refresh(self):
        from app.theme import get_theme
        t = get_theme()
        color = t.get("text_soft", "#a4aab8")
        icon = _render_svg_icon(self._svg_name, color, self._icon_size)
        self.setIcon(icon)
        self.setIconSize(QPixmap(self._icon_size, self._icon_size).size())

    def refresh_theme(self):
        self._refresh()


class SvgIconButton(QPushButton):
    def __init__(
            self,
            svg_name: str,
            object_name: str = "TitleBarButton",
            button_size: tuple = (48, 40),
            icon_size: int = 16,
            parent=None
    ):
        super().__init__(parent)
        self._svg_name = svg_name
        self._icon_size = icon_size
        self.setObjectName(object_name)
        self.setFixedSize(*button_size)
        self.setFocusPolicy(Qt.NoFocus)
        self.setText("")
        self._refresh_icon()

    def _refresh_icon(self):
        from app.theme import get_theme
        t = get_theme()
        color = t.get("text_soft", "#a4aab8")
        icon = _render_svg_icon(self._svg_name, color, self._icon_size)
        self.setIcon(icon)
        self.setIconSize(QPixmap(self._icon_size, self._icon_size).size())

    def refresh_theme(self):
        self._refresh_icon()

    def set_svg(self, svg_name: str):
        self._svg_name = svg_name
        self._refresh_icon()


class TitleBar(QFrame):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self.setObjectName("TitleBar")
        self.setFixedHeight(40)

        self._drag_start_pos = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 0, 0)
        layout.setSpacing(0)

        self.title_label = QLabel(APP_NAME)
        self.title_label.setObjectName("TitleBarTitle")
        layout.addWidget(self.title_label)
        layout.addStretch()

        self.settings_btn = SvgIconButton(
            svg_name="settings.svg",
            object_name="TitleBarButton",
            button_size=(48, 40),
            icon_size=16,
        )
        self.settings_btn.setToolTip("Настройки")
        self.settings_btn.clicked.connect(self._open_settings)
        layout.addWidget(self.settings_btn)

        self.theme_btn = SvgIconButton(
            svg_name="theme.svg",
            object_name="TitleBarButton",
            button_size=(48, 40),
            icon_size=16,
        )
        self.theme_btn.setToolTip("Переключить тему")
        self.theme_btn.clicked.connect(self._cycle_theme)
        layout.addWidget(self.theme_btn)

        self.min_btn = SvgIconButton(
            svg_name="minimize.svg",
            object_name="TitleBarButton",
            button_size=(48, 40),
            icon_size=16,
        )
        self.min_btn.setToolTip("Свернуть")
        self.min_btn.clicked.connect(self.parent_window.showMinimized)
        layout.addWidget(self.min_btn)

        self.max_btn = SvgIconButton(
            svg_name="maximize.svg",
            object_name="TitleBarButton",
            button_size=(48, 40),
            icon_size=16,
        )
        self.max_btn.setToolTip("Развернуть")
        self.max_btn.clicked.connect(self.parent_window.toggle_maximize)
        layout.addWidget(self.max_btn)

        self.close_btn = SvgIconButton(
            svg_name="close.svg",
            object_name="CloseButton",
            button_size=(48, 40),
            icon_size=14,
        )
        self.close_btn.setToolTip("Закрыть")
        self.close_btn.clicked.connect(self.parent_window.close)
        layout.addWidget(self.close_btn)

    def update_max_icon(self, is_maximized: bool):
        self.max_btn.set_svg("restore.svg" if is_maximized else "maximize.svg")
        self.max_btn.setToolTip("Восстановить" if is_maximized else "Развернуть")

    def refresh_theme(self):
        self.settings_btn.refresh_theme()
        self.min_btn.refresh_theme()
        self.max_btn.refresh_theme()
        self.close_btn.refresh_theme()
        self.theme_btn.refresh_theme()

    def _open_settings(self):
        if hasattr(self.parent_window, "main_screen"):
            self.parent_window.main_screen.open_settings()

    def _cycle_theme(self):
        from PySide6.QtWidgets import QApplication
        from app.theme import set_theme, generate_qss, get_theme_name

        themes = ["obsidian", "frost", "rose"]
        current = get_theme_name()
        next_idx = (themes.index(current) + 1) % 3
        next_theme = themes[next_idx]

        set_theme(next_theme)
        QApplication.instance().setStyleSheet(generate_qss())
        self.refresh_theme()

        if hasattr(self.parent_window, "main_screen"):
            main_screen = self.parent_window.main_screen
            if hasattr(main_screen, "refresh_message_bubbles"):
                main_screen.refresh_message_bubbles()

        print(f"[THEME] Переключено на: {next_theme.upper()}")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_start_pos = event.globalPosition().toPoint()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_start_pos is not None and (event.buttons() & Qt.LeftButton):
            if self.parent_window._is_maximized:
                self.parent_window.toggle_maximize()
                new_x = event.globalPosition().toPoint().x() - (self.parent_window.width() // 2)
                new_y = event.globalPosition().toPoint().y() - 10
                self.parent_window.move(new_x, new_y)
                self._drag_start_pos = event.globalPosition().toPoint()
                return
            current_pos = event.globalPosition().toPoint()
            delta = current_pos - self._drag_start_pos
            self.parent_window.move(self.parent_window.pos() + delta)
            self._drag_start_pos = current_pos
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_start_pos = None
        event.accept()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.parent_window.toggle_maximize()
            event.accept()


# ============================================================================
# АНИМИРОВАННЫЙ ФОН AUTH
# ============================================================================

class AnimatedAuthBackground(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("AnimatedAuthBackground")

        self.particles = []
        self.large_particles = []
        self._initialized = False
        self._animation_enabled = ENABLE_AUTH_ANIMATION

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)

        if self._animation_enabled:
            interval = max(16, int(1000 / max(1, AUTH_ANIMATION_FPS)))
            self.timer.start(interval)

    def set_animation_active(self, active: bool):
        if not self._animation_enabled:
            return
        if active:
            if not self.timer.isActive():
                interval = max(16, int(1000 / max(1, AUTH_ANIMATION_FPS)))
                self.timer.start(interval)
        else:
            self.timer.stop()

    def showEvent(self, event):
        super().showEvent(event)
        if not self._initialized:
            self._init_particles()
            self._initialized = True

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.width() > 0 and self.height() > 0:
            self._init_particles()

    def _init_particles(self):
        w = max(1, self.width())
        h = max(1, self.height())

        self.particles.clear()
        self.large_particles.clear()

        count = AUTH_ANIMATION_PARTICLES if ENABLE_AUTH_ANIMATION else 0

        for _ in range(count):
            layer = random.choice([0, 1, 2])
            if layer == 0:
                radius = random.uniform(0.8, 1.6)
                speed = random.uniform(0.08, 0.18)
                alpha = random.randint(20, 45)
            elif layer == 1:
                radius = random.uniform(1.2, 2.1)
                speed = random.uniform(0.18, 0.32)
                alpha = random.randint(28, 65)
            else:
                radius = random.uniform(1.8, 3.0)
                speed = random.uniform(0.32, 0.52)
                alpha = random.randint(38, 85)

            self.particles.append({
                "x": random.uniform(0, w), "y": random.uniform(0, h),
                "vx": random.uniform(-0.025, 0.025), "vy": speed,
                "r": radius, "a": alpha, "layer": layer,
            })

        for _ in range(6):
            self.large_particles.append({
                "x": random.uniform(0, w), "y": random.uniform(0, h),
                "vx": random.uniform(-0.012, 0.012),
                "vy": random.uniform(0.025, 0.06),
                "r": random.uniform(8, 18), "a": random.randint(6, 14),
            })

    def _tick(self):
        if not self._animation_enabled or not self.isVisible():
            return
        w = self.width()
        h = self.height()
        if w <= 0 or h <= 0:
            return

        for p in self.particles:
            p["x"] += p["vx"]
            p["y"] += p["vy"]
            if p["y"] - p["r"] > h:
                p["y"] = -10
                p["x"] = random.uniform(0, w)
            if p["x"] < -20:
                p["x"] = w + 5
            elif p["x"] > w + 20:
                p["x"] = -5

        for p in self.large_particles:
            p["x"] += p["vx"]
            p["y"] += p["vy"]
            if p["y"] - p["r"] > h:
                p["y"] = -30
                p["x"] = random.uniform(0, w)
            if p["x"] < -40:
                p["x"] = w + 10
            elif p["x"] > w + 40:
                p["x"] = -10

        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        w = self.width()
        h = self.height()

        bg = QLinearGradient(0, 0, 0, h)
        bg.setColorAt(0.0, QColor("#050608"))
        bg.setColorAt(0.45, QColor("#080a0d"))
        bg.setColorAt(0.75, QColor("#090b0d"))
        bg.setColorAt(1.0, QColor("#050608"))
        painter.fillRect(self.rect(), bg)

        glow_left = QRadialGradient(w * 0.18, h * 0.22, min(w, h) * 0.34)
        glow_left.setColorAt(0.0, QColor(100, 115, 170, 24))
        glow_left.setColorAt(0.4, QColor(75, 88, 130, 12))
        glow_left.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(glow_left))
        painter.drawEllipse(QRectF(w * -0.04, h * -0.02, w * 0.46, h * 0.50))

        glow_right = QRadialGradient(w * 0.82, h * 0.76, min(w, h) * 0.38)
        glow_right.setColorAt(0.0, QColor(115, 125, 145, 18))
        glow_right.setColorAt(0.45, QColor(70, 78, 96, 8))
        glow_right.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setBrush(QBrush(glow_right))
        painter.drawEllipse(QRectF(w * 0.58, h * 0.48, w * 0.38, h * 0.42))

        center_glow = QRadialGradient(w * 0.50, h * 0.48, min(w, h) * 0.26)
        center_glow.setColorAt(0.0, QColor(180, 190, 220, 8))
        center_glow.setColorAt(0.45, QColor(120, 130, 160, 4))
        center_glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setBrush(QBrush(center_glow))
        painter.drawEllipse(QRectF(w * 0.31, h * 0.18, w * 0.38, h * 0.52))

        painter.setPen(Qt.NoPen)
        for p in self.large_particles:
            grad = QRadialGradient(p["x"], p["y"], p["r"])
            grad.setColorAt(0.0, QColor(180, 190, 220, p["a"]))
            grad.setColorAt(1.0, QColor(0, 0, 0, 0))
            painter.setBrush(QBrush(grad))
            painter.drawEllipse(
                QPoint(int(p["x"]), int(p["y"])), int(p["r"]), int(p["r"])
            )

        for p in self.particles:
            tail_len = 7 if p["layer"] == 2 else 4 if p["layer"] == 1 else 2
            line_alpha = max(5, p["a"] // 3)
            pen = QPen(QColor(180, 190, 220, line_alpha))
            pen.setWidth(1)
            painter.setPen(pen)
            painter.drawLine(
                int(p["x"]), int(p["y"] - tail_len),
                int(p["x"]), int(p["y"])
            )

            painter.setPen(Qt.NoPen)
            if p["layer"] == 2:
                color = QColor(215, 222, 255, p["a"])
            elif p["layer"] == 1:
                color = QColor(185, 195, 220, p["a"])
            else:
                color = QColor(150, 160, 180, p["a"])
            painter.setBrush(color)
            painter.drawEllipse(
                QPoint(int(p["x"]), int(p["y"])), int(p["r"]), int(p["r"])
            )

        vignette_top = QLinearGradient(0, 0, 0, h * 0.22)
        vignette_top.setColorAt(0.0, QColor(0, 0, 0, 40))
        vignette_top.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.fillRect(QRectF(0, 0, w, h * 0.22), vignette_top)

        vignette_bottom = QLinearGradient(0, h, 0, h * 0.78)
        vignette_bottom.setColorAt(0.0, QColor(0, 0, 0, 28))
        vignette_bottom.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.fillRect(QRectF(0, h * 0.78, w, h * 0.22), vignette_bottom)


# ============================================================================
# AMBIENT PANELS
# ============================================================================

class AnimatedMainBackground(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("AnimatedMainBackground")
        self.particles = []
        self.waves = []
        self._initialized = False
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)

    def set_animation_active(self, active: bool):
        if active and not self._timer.isActive():
            self._timer.start(33)
        elif not active:
            self._timer.stop()

    def showEvent(self, event):
        super().showEvent(event)
        if not self._initialized:
            self._init_elements()
            self._initialized = True

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.width() > 0 and self.height() > 0:
            self._init_elements()

    def _init_elements(self):
        from app.theme import get_theme_name
        theme = get_theme_name()
        w, h = self.width(), self.height()
        self.particles.clear()
        self.waves.clear()

        if theme == "obsidian":
            for _ in range(18):
                self.particles.append({
                    "x": random.uniform(0, w),
                    "y": random.uniform(0, h),
                    "vx": random.uniform(-0.02, 0.02),
                    "vy": random.uniform(0.05, 0.15),
                    "r": random.uniform(0.8, 2.0),
                    "a": random.randint(15, 50),
                })
        elif theme == "frost":
            for i in range(3):
                self.waves.append({
                    "y_offset": h * (0.3 + i * 0.2),
                    "amplitude": random.uniform(8, 15),
                    "speed": random.uniform(0.3, 0.6),
                    "phase": random.uniform(0, 6.28),
                    "alpha": random.randint(12, 25),
                    "width": random.uniform(1.0, 2.0),
                })
        elif theme == "rose":
            for _ in range(12):
                self.particles.append({
                    "x": random.uniform(0, w),
                    "y": random.uniform(0, h),
                    "vx": random.uniform(-0.015, 0.015),
                    "vy": random.uniform(0.03, 0.1),
                    "r": random.uniform(1.0, 3.0),
                    "a": random.randint(10, 30),
                })

    def _tick(self):
        if not self.isVisible() or self.width() <= 0:
            return
        w, h = self.width(), self.height()

        for p in self.particles:
            p["x"] += p["vx"]
            p["y"] += p["vy"]
            if p["y"] - p["r"] > h:
                p["y"] = -10
                p["x"] = random.uniform(0, w)
            if p["x"] < -20:
                p["x"] = w + 5
            elif p["x"] > w + 20:
                p["x"] = -5

        for wave in self.waves:
            wave["phase"] += wave["speed"] * 0.02

        self.update()

    def paintEvent(self, event):
        from app.theme import get_theme_name, get_theme
        theme = get_theme_name()
        t = get_theme()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()

        if theme == "obsidian":
            painter.fillRect(self.rect(), QColor(t["bg_main"]))
            for p in self.particles:
                grad = QRadialGradient(p["x"], p["y"], p["r"] * 2)
                grad.setColorAt(0.0, QColor(180, 190, 220, p["a"]))
                grad.setColorAt(1.0, QColor(0, 0, 0, 0))
                painter.setPen(Qt.NoPen)
                painter.setBrush(QBrush(grad))
                painter.drawEllipse(QPoint(int(p["x"]), int(p["y"])),
                                    int(p["r"]), int(p["r"]))

        elif theme == "frost":
            painter.fillRect(self.rect(), QColor(t["bg_main"]))
            for wave in self.waves:
                path = QPainterPath()
                y_base = wave["y_offset"]
                for x in range(0, w + 1, 4):
                    import math
                    y = y_base + wave["amplitude"] * math.sin(
                        wave["phase"] + x * 0.005
                    )
                    if x == 0:
                        path.moveTo(x, y)
                    else:
                        path.lineTo(x, y)
                pen = QPen(QColor(95, 135, 255, wave["alpha"]))
                pen.setWidthF(wave["width"])
                painter.setPen(pen)
                painter.setBrush(Qt.NoBrush)
                painter.drawPath(path)

        elif theme == "rose":
            painter.fillRect(self.rect(), QColor(t["bg_main"]))
            for p in self.particles:
                grad = QRadialGradient(p["x"], p["y"], p["r"] * 2)
                grad.setColorAt(0.0, QColor(211, 139, 179, p["a"]))
                grad.setColorAt(1.0, QColor(0, 0, 0, 0))
                painter.setPen(Qt.NoPen)
                painter.setBrush(QBrush(grad))
                painter.drawEllipse(QPoint(int(p["x"]), int(p["y"])),
                                    int(p["r"]), int(p["r"]))
        else:
            painter.fillRect(self.rect(), QColor(t["bg_main"]))

        painter.end()


class AmbientPanel(QFrame):
    def __init__(self, title: str, text: str):
        super().__init__()
        self.setObjectName("AmbientCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        title_label = QLabel(title)
        title_label.setObjectName("AmbientTitle")
        text_label = QLabel(text)
        text_label.setObjectName("AmbientText")
        text_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(text_label)
        layout.addStretch()


# ============================================================================
# LOADING SCREEN
# ============================================================================

class LoadingScreen(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("MainScreen")
        root = QVBoxLayout(self)
        root.setContentsMargins(40, 40, 40, 40)
        root.setSpacing(0)
        root.addStretch()

        self.card = QFrame()
        self.card.setObjectName("LoadingCard")
        self.card.setFixedWidth(520)

        shadow = QGraphicsDropShadowEffect(self.card)
        shadow.setBlurRadius(38)
        shadow.setOffset(0, 10)
        shadow.setColor(QColor(0, 0, 0, 135))
        self.card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(34, 34, 34, 34)
        card_layout.setSpacing(18)

        self.eyebrow = QLabel("SECURE SESSION")
        self.eyebrow.setObjectName("LoadingEyebrow")
        self.eyebrow.setAlignment(Qt.AlignCenter)

        self.title = QLabel("Установка защищённого соединения")
        self.title.setObjectName("LoadingTitle")
        self.title.setAlignment(Qt.AlignCenter)
        self.title.setWordWrap(True)

        self.dots = PulseDots()
        dots_row = QHBoxLayout()
        dots_row.setContentsMargins(0, 0, 0, 0)
        dots_row.addStretch()
        dots_row.addWidget(self.dots)
        dots_row.addStretch()

        self.status = QLabel("Проверка устройства")
        self.status.setObjectName("LoadingStatus")
        self.status.setAlignment(Qt.AlignCenter)

        self.substatus = QLabel(
            "Подготавливаем защищённую сессию Max1m "
            "и проверяем параметры подключения."
        )
        self.substatus.setObjectName("LoadingSubstatus")
        self.substatus.setAlignment(Qt.AlignCenter)
        self.substatus.setWordWrap(True)

        self.progress_line = QFrame()
        self.progress_line.setObjectName("LoadingProgressLine")
        self.progress_line.setFixedHeight(6)

        self.stage_label = QLabel("Шаг 1 / 3")
        self.stage_label.setObjectName("LoadingStageLabel")
        self.stage_label.setAlignment(Qt.AlignCenter)

        card_layout.addWidget(self.eyebrow)
        card_layout.addWidget(self.title)
        card_layout.addLayout(dots_row)
        card_layout.addWidget(self.status)
        card_layout.addWidget(self.substatus)
        card_layout.addSpacing(2)
        card_layout.addWidget(self.progress_line)
        card_layout.addWidget(self.stage_label)

        root.addWidget(self.card, alignment=Qt.AlignCenter)
        root.addStretch()

    def set_status(self, title: str, substatus: str = "", step: str = ""):
        self.status.setText(title)
        self.substatus.setText(substatus)
        if step:
            self.stage_label.setText(step)


# ============================================================================
# PULSE DOTS
# ============================================================================

class PulseDots(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(84, 24)
        self.phase = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(90)

    def _tick(self):
        self.phase = (self.phase + 1) % 24
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)
        base_x = 12
        y = self.height() / 2
        spacing = 24

        for i in range(3):
            local_phase = (self.phase - i * 4) % 24
            strength = max(0.22, 1.0 - abs(local_phase - 6) / 8.0)
            strength = min(strength, 1.0)
            radius = 4 + strength * 3
            alpha = int(55 + strength * 135)

            glow = QRadialGradient(base_x + i * spacing, y, radius * 2.6)
            glow.setColorAt(0.0, QColor(188, 198, 255, int(alpha * 0.42)))
            glow.setColorAt(1.0, QColor(0, 0, 0, 0))
            painter.setBrush(QBrush(glow))
            painter.drawEllipse(
                QRectF(
                    base_x + i * spacing - radius * 1.8,
                    y - radius * 1.8,
                    radius * 3.6,
                    radius * 3.6
                )
            )
            painter.setBrush(QColor(214, 221, 255, alpha))
            painter.drawEllipse(
                QRectF(
                    base_x + i * spacing - radius,
                    y - radius,
                    radius * 2,
                    radius * 2
                )
            )


# ============================================================================
# IN-APP NOTIFICATION TOAST
# ============================================================================

class InAppNotification(QWidget):
    clicked = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool
        )
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.setCursor(Qt.PointingHandCursor)

        self.setFixedHeight(90)
        self.setFixedWidth(340)

        self._sender_username = None

        self.container = QFrame(self)
        self.container.setObjectName("InAppNotification")
        self.container.setGeometry(0, 0, 340, 90)

        shadow = QGraphicsDropShadowEffect(self.container)
        shadow.setBlurRadius(25)
        shadow.setColor(QColor(0, 0, 0, 180))
        shadow.setOffset(0, 5)
        self.container.setGraphicsEffect(shadow)

        layout = QHBoxLayout(self.container)
        layout.setContentsMargins(16, 14, 12, 14)
        layout.setSpacing(12)

        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(44, 44)
        self.avatar_label.setAlignment(Qt.AlignCenter)
        self.avatar_label.setObjectName("NotifAvatar")

        text_layout = QVBoxLayout()
        text_layout.setSpacing(4)
        text_layout.setContentsMargins(0, 0, 0, 0)

        self.title_label = QLabel()
        self.title_label.setObjectName("NotifTitle")

        self.msg_label = QLabel()
        self.msg_label.setObjectName("NotifMessage")
        self.msg_label.setWordWrap(True)
        self.msg_label.setMaximumHeight(40)

        text_layout.addWidget(self.title_label)
        text_layout.addWidget(self.msg_label)
        text_layout.addStretch()

        self.close_btn = _SvgBtn("close_small.svg", 24, 10)
        self.close_btn.setObjectName("NotifCloseBtn")
        self.close_btn.setCursor(Qt.PointingHandCursor)
        self.close_btn.clicked.connect(self._start_hide)

        layout.addWidget(self.avatar_label)
        layout.addLayout(text_layout, 1)
        layout.addWidget(self.close_btn, 0, Qt.AlignTop)

        self.auto_hide_timer = QTimer(self)
        self.auto_hide_timer.setSingleShot(True)
        self.auto_hide_timer.timeout.connect(self._start_hide)

        self.slide_anim = QPropertyAnimation(self, b"geometry")
        self.slide_anim.setDuration(300)
        self.slide_anim.setEasingCurve(QEasingCurve.OutCubic)

        self._is_hiding = False

    def show_notification(self, title: str, message: str, is_group: bool = False):
        self.auto_hide_timer.stop()
        self.slide_anim.stop()
        self._is_hiding = False

        self._sender_username = (
            title.lstrip("@") if title.startswith("@") else title
        )

        self.title_label.setText(title)
        display_msg = message[:100] + "..." if len(message) > 100 else message
        self.msg_label.setText(display_msg)

        if is_group:
            from app.theme import get_theme
            t = get_theme()
            svg_path = ICONS_PATH / "group.svg"
            if svg_path.exists():
                svg_content = svg_path.read_text(encoding="utf-8")
                svg_colored = svg_content.replace(
                    "currentColor", t.get("text_soft", "#a4aab8")
                )
                from PySide6.QtSvg import QSvgRenderer
                renderer = QSvgRenderer(svg_colored.encode("utf-8"))
                pixmap = QPixmap(24, 24)
                pixmap.fill(Qt.transparent)
                painter = QPainter(pixmap)
                painter.setRenderHint(QPainter.Antialiasing, True)
                renderer.render(painter)
                painter.end()
                self.avatar_label.setPixmap(pixmap)
                self.avatar_label.setText("")
            else:
                self.avatar_label.setText("G")
                self.avatar_label.setPixmap(QPixmap())
        else:
            first_letter = (
                self._sender_username[0].upper() if self._sender_username else "?"
            )
            self.avatar_label.setText(first_letter)
            self.avatar_label.setPixmap(QPixmap())

        from PySide6.QtGui import QGuiApplication
        screen = QGuiApplication.primaryScreen().availableGeometry()

        margin = 20
        notif_width = self.width()
        notif_height = self.height()

        end_x = screen.width() - notif_width - margin
        end_y = screen.height() - notif_height - margin
        start_x = screen.width() + 10
        start_y = end_y

        self.setGeometry(start_x, start_y, notif_width, notif_height)
        self.container.setGeometry(0, 0, notif_width, notif_height)

        self.show()
        self.raise_()

        self.slide_anim.setStartValue(
            QRect(start_x, start_y, notif_width, notif_height)
        )
        self.slide_anim.setEndValue(
            QRect(end_x, end_y, notif_width, notif_height)
        )
        self.slide_anim.start()

        self.auto_hide_timer.start(5000)

    def _start_hide(self):
        if self._is_hiding:
            return
        self._is_hiding = True

        self.auto_hide_timer.stop()
        self.slide_anim.stop()

        from PySide6.QtGui import QGuiApplication
        screen = QGuiApplication.primaryScreen().availableGeometry()

        current_geo = self.geometry()
        end_x = screen.width() + 10

        try:
            self.slide_anim.finished.disconnect()
        except (RuntimeError, TypeError):
            pass

        self.slide_anim.setStartValue(current_geo)
        self.slide_anim.setEndValue(
            QRect(end_x, current_geo.y(), current_geo.width(), current_geo.height())
        )
        self.slide_anim.finished.connect(self._on_hide_finished)
        self.slide_anim.start()

    def _on_hide_finished(self):
        try:
            self.slide_anim.finished.disconnect(self._on_hide_finished)
        except (RuntimeError, TypeError):
            pass
        self.hide()
        self._is_hiding = False

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self._sender_username:
            self.clicked.emit(self._sender_username)
            self._start_hide()
        super().mousePressEvent(event)


# ============================================================================
# IMAGE VIEWER
# ============================================================================

class ImageViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ImageViewer")
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setFocusPolicy(Qt.StrongFocus)
        self._pixmap = None

        self._close_btn = _SvgBtn("close_small.svg", 44, 16, parent=self)
        self._close_btn.setObjectName("ImageViewerCloseBtn")
        self._close_btn.setCursor(Qt.PointingHandCursor)
        self._close_btn.clicked.connect(self.close_viewer)

        self._opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity_effect)
        self._opacity_effect.setOpacity(0.0)

        self._fade_anim = QPropertyAnimation(self._opacity_effect, b"opacity")
        self._fade_anim.setDuration(180)
        self._fade_anim.setEasingCurve(QEasingCurve.OutCubic)

        self.hide()

    def show_image(self, pixmap: QPixmap):
        self._pixmap = pixmap
        self._reposition()
        self.show()
        self.raise_()
        self.setFocus()
        self.update()

        self._fade_anim.stop()
        try:
            self._fade_anim.finished.disconnect(self._on_fade_out_done)
        except (RuntimeError, TypeError):
            pass
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self._fade_anim.start()

    def close_viewer(self):
        self._fade_anim.stop()
        self._fade_anim.setStartValue(self._opacity_effect.opacity())
        self._fade_anim.setEndValue(0.0)
        try:
            self._fade_anim.finished.disconnect(self._on_fade_out_done)
        except (RuntimeError, TypeError):
            pass
        self._fade_anim.finished.connect(self._on_fade_out_done)
        self._fade_anim.start()

    def _on_fade_out_done(self):
        try:
            self._fade_anim.finished.disconnect(self._on_fade_out_done)
        except (RuntimeError, TypeError):
            pass
        self.hide()

    def _reposition(self):
        if self.parent():
            self.setGeometry(self.parent().rect())
        self._close_btn.move(self.width() - 56, 12)

    def _image_rect(self) -> QRect:
        if not self._pixmap:
            return QRect()
        margin = 60
        available = self.rect().adjusted(margin, margin, -margin, -margin)
        scaled = self._pixmap.scaled(
            available.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        x = available.x() + (available.width() - scaled.width()) // 2
        y = available.y() + (available.height() - scaled.height()) // 2
        return QRect(x, y, scaled.width(), scaled.height())

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._close_btn.move(self.width() - 56, 12)
        self.update()

    def paintEvent(self, event):
        if not self._pixmap:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)

        painter.fillRect(self.rect(), QColor(0, 0, 0, 200))

        img_rect = self._image_rect()

        shadow_rect = img_rect.adjusted(4, 8, 4, 8)
        painter.fillRect(shadow_rect, QColor(0, 0, 0, 80))

        scaled = self._pixmap.scaled(
            img_rect.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        path = QPainterPath()
        path.addRoundedRect(
            img_rect.x(), img_rect.y(),
            img_rect.width(), img_rect.height(),
            12, 12
        )
        painter.setClipPath(path)
        painter.drawPixmap(img_rect.x(), img_rect.y(), scaled)
        painter.setClipping(False)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            if not self._image_rect().contains(event.position().toPoint()):
                self.close_viewer()
        super().mousePressEvent(event)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close_viewer()
        super().keyPressEvent(event)

# ============================================================================
# MAIN APP WINDOW
# ============================================================================

class AppWindow(QMainWindow):
    rtc_state_changed = Signal(str, str, str)
    rtc_screen_state_changed = Signal(bool, str)
    rtc_remote_screen_state_changed = Signal(str, str, bool)
    rtc_screen_frame_ready = Signal()

    def __init__(self):
        super().__init__()
        self._screen_frame_lock = threading.Lock()
        self._screen_frame_mailbox = None
        self._screen_frame_ui_queued = False
        self.mode = "login"
        self._is_maximized = False
        self._normal_rect = None
        self.ws_worker = None
        self.sync_worker = None
        self._sync_cursor = None
        self._sync_restart_requested = False
        self._sync_version_warning_shown = False
        self._ack_worker = None
        self._group_sync_worker = None
        self.groups_fetch_worker = None
        self._sync_timer = QTimer(self)
        self._sync_timer.setInterval(30000)
        self._sync_timer.timeout.connect(self._start_message_sync)
        self._sync_timer.timeout.connect(self._start_group_sync)

        self.setWindowTitle(APP_NAME)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.resize(WINDOW_START_WIDTH, WINDOW_START_HEIGHT)
        self.setMinimumSize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)

        self.root_frame = QFrame()
        self.root_frame.setObjectName("WindowRoot")
        self.setCentralWidget(self.root_frame)

        self.main_layout = QVBoxLayout(self.root_frame)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        self.titlebar = TitleBar(self)
        self.main_layout.addWidget(self.titlebar)

        self.stack = QStackedWidget()
        self.main_layout.addWidget(self.stack)

        self._build_screens()
        self._apply_mode()
        self._refresh_mode_buttons()

        self.stack.currentChanged.connect(
            lambda _: self._update_auth_animation_state()
        )
        QTimer.singleShot(0, self._update_auth_animation_state)

        self._setup_size_grip()
        self._center_window()
        self._init_tray()
        self._load_local_state_on_startup()

        if START_MODE == "maximized":
            QTimer.singleShot(50, self.toggle_maximize)

        self.in_app_toast = InAppNotification()
        self.in_app_toast.clicked.connect(self._on_notification_clicked)

        # ── Image Viewer ────────────────────────────────────────────
        self._image_viewer = ImageViewer(self.root_frame)
        self._image_viewer.hide()

        # ── WebRTC Callbacks ────────────────────────────────────────────────
        self.rtc_state_changed.connect(self._apply_rtc_state_change, Qt.QueuedConnection)
        self.rtc_screen_state_changed.connect(self._apply_screen_share_state, Qt.QueuedConnection)
        self.rtc_remote_screen_state_changed.connect(self._apply_remote_screen_state, Qt.QueuedConnection)
        self.rtc_screen_frame_ready.connect(self._drain_latest_screen_frame, Qt.QueuedConnection)
        rtc.on_signal_generated    = self._send_rtc_signal
        rtc.on_state_change        = self._on_rtc_state_change
        rtc.on_screen_share_state  = self._on_screen_share_state
        rtc.on_remote_screen_state = self._on_remote_screen_state
        rtc.on_frame_ready         = self._on_rtc_screen_frame
        rtc.get_peer_public_key    = self._get_peer_public_key

        self._init_security_watchdog()

    def _init_security_watchdog(self):
        app_inst = QApplication.instance()
        if app_inst is not None:
            app_inst.installEventFilter(self)
        self._security_maintenance_timer = QTimer(self)
        self._security_maintenance_timer.setInterval(15000)
        self._security_maintenance_timer.timeout.connect(self._on_security_maintenance_tick)
        self._security_maintenance_timer.start()

    def _zeroize_local_vaults(self):
        try:
            from app.local_vault import lock_all_vaults
            lock_all_vaults()
        except Exception:
            pass

    def _prompt_emergency_panic_wipe(self):
        if getattr(self, "_panic_wipe_dialog_open", False):
            return
        self._panic_wipe_dialog_open = True
        try:
            answer = QMessageBox.warning(
                self,
                "Экстренное уничтожение данных (Panic Wipe)",
                "Двухпроходно перезаписать и безвозвратно удалить ключи, историю и кэш профиля?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if answer == QMessageBox.Yes:
                from app.local_vault import execute_panic_wipe
                uname = getattr(state, "username", "") or None
                self.logout_session()
                execute_panic_wipe(uname, wipe_all_profiles=(uname is None))
                self._set_status("Сессия завершена.", False)
        finally:
            self._panic_wipe_dialog_open = False

    def eventFilter(self, obj, event):
        etype = event.type()
        if etype in (QEvent.KeyPress, QEvent.MouseButtonPress, QEvent.MouseMove, QEvent.Wheel):
            try:
                from app.local_vault import record_user_activity
                record_user_activity()
            except Exception:
                pass
        if etype == QEvent.KeyPress:
            mods = event.modifiers()
            ctrl_shift = Qt.ControlModifier | Qt.ShiftModifier
            if (mods & ctrl_shift) == ctrl_shift:
                if event.key() == Qt.Key_L:
                    if self.logout_session():
                        self._zeroize_local_vaults()
                        self._set_status("Сессия экстренно заблокирована (RAM очищена).", False)
                    return True
                if event.key() == Qt.Key_Backspace:
                    QTimer.singleShot(0, self._prompt_emergency_panic_wipe)
                    return True
        return super().eventFilter(obj, event)

    def _on_security_maintenance_tick(self):
        uname = getattr(state, "username", "") or ""
        tok = getattr(state, "token", "") or ""
        if not uname or not tok:
            return
        try:
            purge_fn = getattr(storage, "purge_expired_messages", None)
            if callable(purge_fn):
                purged = purge_fn(uname)
                if purged and hasattr(self, "main_screen") and hasattr(self.main_screen, "refresh_visible_chat_if_needed"):
                    self.main_screen.refresh_visible_chat_if_needed()
        except Exception:
            pass

        try:
            from app.local_vault import idle_seconds
            auto_fn = getattr(storage, "get_auto_lock_seconds", None)
            auto_sec = auto_fn(uname) if callable(auto_fn) else 0
            if auto_sec > 0 and idle_seconds() >= float(auto_sec):
                if self.logout_session():
                    self._zeroize_local_vaults()
                    self._set_status("Сессия автоматически заблокирована по таймеру неактивности.", False)
        except Exception:
            pass

    def _ensure_vault_unlocked_ui(self, username: str) -> bool:
        try:
            from app.local_vault import (
                VaultAuthenticationError,
                is_vault_enabled,
                is_vault_unlocked,
                unlock_vault,
            )
        except Exception:
            return True
        if not username or not is_vault_enabled(username) or is_vault_unlocked(username):
            return True

        from PySide6.QtWidgets import QInputDialog
        while True:
            pw, ok = QInputDialog.getText(
                self,
                "Локальный сейф защищён (Argon2id)",
                f"Введите мастер-пароль сейфа для профиля @{username}:",
                QLineEdit.Password,
            )
            if not ok or not pw:
                self._set_status("Разблокировка локального сейфа отменена.", True)
                return False
            try:
                outcome = unlock_vault(username, pw)
                if outcome == "duress_wiped":
                    state.device_id = ""
                    state.username = ""
                    self._set_status("Неверный мастер-пароль или локальный профиль повреждён.", True)
                    return False
                return True
            except VaultAuthenticationError:
                retry = QMessageBox.warning(
                    self,
                    "Неверный пароль сейфа",
                    "Мастер-пароль не подошёл. Попробовать ещё раз?",
                    QMessageBox.Retry | QMessageBox.Cancel,
                    QMessageBox.Retry,
                )
                if retry != QMessageBox.Retry:
                    self._set_status("Разблокировка локального сейфа отменена.", True)
                    return False
            except Exception as exc:
                self._set_status(f"Ошибка открытия локального сейфа: {type(exc).__name__}", True)
                return False


    def _forward_video_track(self, peer_device_id: str, receiver):
        pass  # теперь не используется

    def _init_tray(self):
        from PySide6.QtWidgets import QSystemTrayIcon
        icon_path = ICONS_PATH / "app_icon.png"

        if icon_path.exists():
            icon = QIcon(str(icon_path))
        else:
            pixmap = QPixmap(64, 64)
            pixmap.fill(QColor(0, 0, 0, 0))
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            painter.setBrush(QColor("#6c748a"))
            painter.setPen(Qt.NoPen)
            painter.drawRoundedRect(4, 4, 56, 56, 12, 12)
            painter.setPen(QColor("#ffffff"))
            font = painter.font()
            font.setPixelSize(28)
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(pixmap.rect(), Qt.AlignCenter, "M")
            painter.end()
            icon = QIcon(pixmap)

        self.tray = QSystemTrayIcon(icon, self)
        self.tray.setToolTip("Max1m — Secure Messenger")
        self.tray.show()

    def _on_incoming_screen_frame(self, data: dict):
        """Legacy unencrypted WebSocket screen_frame packets are ignored (E2EE WebRTC only)."""
        return

    def _on_incoming_screen_control(self, data: dict):
        """Legacy unencrypted WebSocket screen_control packets are ignored (E2EE WebRTC only)."""
        return

    def _on_screen_frame(self, data: bytes, w: int, h: int, is_jpeg: bool):
        """Оставляем для совместимости — больше не используется."""
        pass

    def _setup_size_grip(self):
        self.grip_container = QFrame(self.root_frame)
        self.grip_container.setStyleSheet("background: transparent;")
        grip_layout = QVBoxLayout(self.grip_container)
        grip_layout.setContentsMargins(0, 0, 0, 0)
        self.size_grip = QSizeGrip(self.grip_container)
        self.size_grip.setFixedSize(16, 16)
        grip_layout.addWidget(self.size_grip)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.grip_container.setGeometry(
            self.width() - 16, self.height() - 16, 16, 16
        )
        if hasattr(self, '_image_viewer') and self._image_viewer.isVisible():
            self._image_viewer._reposition()
            self._image_viewer.update()

    def show_image_viewer(self, pixmap: QPixmap):
        self._image_viewer._reposition()
        self._image_viewer.show_image(pixmap)

    def _load_local_state_on_startup(self):
        try:
            local_data = storage.load_local_state()
        except Exception:
            if hasattr(self, "_set_status"):
                self._set_status(
                    "Локальное состояние повреждено или недоступно; файл сохранён для восстановления.",
                    True,
                )
            return
        if local_data:
            state.server_url = local_data.get("server_url", DEFAULT_SERVER_URL)
            state.username = local_data.get("username", "")
            state.device_name = local_data.get("device_name", "Windows Desktop")
            state.device_id = local_data.get("device_id", "")
            if state.username and state.device_id:
                self.username_block["input"].setText(state.username)
                self.server_block["input"].setText(state.server_url)
                self.device_block["input"].setText(state.device_name)
                self._set_mode("login")

    def _build_screens(self):
        self.auth_screen = self._build_auth_screen()
        self.loading_screen = self._build_loading_screen()
        self.main_screen = self._build_main_screen()
        self.main_screen.contact_verification_changed.connect(self._on_contact_verification_changed, Qt.QueuedConnection)
        if hasattr(self.main_screen, "logout_requested"):
            self.main_screen.logout_requested.connect(self.logout_session, Qt.QueuedConnection)
        self.stack.addWidget(self.auth_screen)
        self.stack.addWidget(self.loading_screen)
        self.stack.addWidget(self.main_screen)

    def _build_auth_screen(self):
        screen = AnimatedAuthBackground()
        layout = QHBoxLayout(screen)
        layout.setContentsMargins(54, 42, 54, 42)
        layout.setSpacing(28)

        left_layout = QVBoxLayout()
        left_layout.addStretch()
        self.left_panel = AmbientPanel(
            "Защищённый узел",
            "Max1m строится как закрытый мессенджер для своих: "
            "с device-based моделью, локальными ключами "
            "и контролем над инфраструктурой."
        )
        self.left_panel.setFixedWidth(300)
        self.left_panel.setMinimumHeight(250)
        left_layout.addWidget(self.left_panel)
        left_layout.addStretch()

        center_layout = QVBoxLayout()
        center_layout.addStretch()

        self.auth_card = QFrame()
        self.auth_card.setObjectName("AuthCard")
        self.auth_card.setFixedWidth(AUTH_CARD_WIDTH)

        shadow = QGraphicsDropShadowEffect(self.auth_card)
        shadow.setBlurRadius(42)
        shadow.setOffset(0, 10)
        shadow.setColor(QColor(0, 0, 0, 140))
        self.auth_card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout(self.auth_card)
        card_layout.setContentsMargins(34, 32, 34, 32)
        card_layout.setSpacing(16)

        self.brand_title = QLabel(APP_NAME)
        self.brand_title.setObjectName("BrandTitle")
        self.brand_title.setAlignment(Qt.AlignCenter)

        self.brand_subtitle = QLabel("PRIVATE SECURE MESSENGER")
        self.brand_subtitle.setObjectName("BrandSubtitle")
        self.brand_subtitle.setAlignment(Qt.AlignCenter)

        mode_row = QHBoxLayout()
        mode_row.setSpacing(10)
        self.login_button = QPushButton("Вход")
        self.login_button.clicked.connect(lambda: self._set_mode("login"))
        self.login_button.setObjectName("ModeButton")
        self.register_button = QPushButton("Регистрация")
        self.register_button.clicked.connect(lambda: self._set_mode("register"))
        self.register_button.setObjectName("ModeButton")
        mode_row.addWidget(self.login_button)
        mode_row.addWidget(self.register_button)

        self.hint_label = QLabel()
        self.hint_label.setObjectName("HintLabel")
        self.hint_label.setWordWrap(True)

        self.username_block = self._make_input_block("Имя пользователя", "Введите имя")
        self.username_block["input"].textChanged.connect(lambda: self._apply_mode())
        self.password_block = self._make_input_block(
            "Пароль", "Введите пароль", password=True
        )
        self.invite_block = self._make_input_block(
            "Инвайт-код", "Только для регистрации"
        )
        self.device_block = self._make_input_block(
            "Название устройства", "Например: My PC"
        )
        self.device_block["input"].setText("Windows Desktop")

        self.advanced_toggle = QPushButton("Дополнительно")
        self.advanced_toggle.setObjectName("SubtleButton")
        self.advanced_toggle.clicked.connect(self._toggle_advanced)

        self.advanced_card = QFrame()
        self.advanced_card.setObjectName("AdvancedCard")
        self.advanced_card.setVisible(False)
        advanced_layout = QVBoxLayout(self.advanced_card)
        advanced_layout.setContentsMargins(14, 14, 14, 14)
        self.server_block = self._make_input_block("Сервер", DEFAULT_SERVER_URL)
        self.server_block["input"].setText(DEFAULT_SERVER_URL)
        advanced_layout.addWidget(self.server_block["container"])
        self.spki_pin_block = self._make_input_block(
            "TLS SPKI Pin сервера (защита от MITM)",
            "sha256/... (опционально или из max1m-join://)",
        )
        advanced_layout.addWidget(self.spki_pin_block["container"])

        self.join_link_block = QFrame()
        self.join_link_block.setObjectName("InputBlock")
        join_v = QVBoxLayout(self.join_link_block)
        join_v.setContentsMargins(0, 0, 0, 0)
        join_v.setSpacing(6)
        join_lbl = QLabel("Быстрое подключение команды (max1m-join://)")
        join_lbl.setObjectName("FieldLabel")
        join_h = QHBoxLayout()
        join_h.setSpacing(6)
        self.join_link_input = QLineEdit()
        self.join_link_input.setPlaceholderText("Вставьте строку max1m-join:// от администратора")
        self.join_link_input.returnPressed.connect(self.apply_join_link_from_ui)
        self.join_link_btn = QPushButton("Применить")
        self.join_link_btn.setObjectName("SecondaryButton")
        self.join_link_btn.setCursor(Qt.PointingHandCursor)
        self.join_link_btn.clicked.connect(self.apply_join_link_from_ui)
        join_h.addWidget(self.join_link_input, 1)
        join_h.addWidget(self.join_link_btn, 0)
        join_v.addWidget(join_lbl)
        join_v.addLayout(join_h)

        self.status_label = QLabel("")
        self.status_label.setObjectName("StatusLabel")
        self.status_label.setWordWrap(True)

        self.submit_button = QPushButton("Продолжить")
        self.submit_button.setObjectName("PrimaryButton")
        self.submit_button.clicked.connect(self._submit)

        card_layout.addWidget(self.brand_title)
        card_layout.addWidget(self.brand_subtitle)
        card_layout.addSpacing(8)
        card_layout.addLayout(mode_row)
        card_layout.addWidget(self.hint_label)
        card_layout.addWidget(self.join_link_block)
        card_layout.addWidget(self.username_block["container"])
        card_layout.addWidget(self.password_block["container"])
        card_layout.addWidget(self.invite_block["container"])
        card_layout.addWidget(self.device_block["container"])
        card_layout.addWidget(self.advanced_toggle)
        card_layout.addWidget(self.advanced_card)
        card_layout.addWidget(self.status_label)
        card_layout.addWidget(self.submit_button)
        card_layout.addSpacing(4)

        center_layout.addWidget(self.auth_card, alignment=Qt.AlignCenter)
        center_layout.addStretch()

        right_layout = QVBoxLayout()
        right_layout.addStretch()
        self.right_panel = AmbientPanel(
            "Свой круг",
            "Добавляй союзников по user-тегу, управляй устройствами, "
            "сверяй fingerprint'ы и разворачивай Max1m в своей инфраструктуре."
        )
        self.right_panel.setFixedWidth(300)
        self.right_panel.setMinimumHeight(250)
        right_layout.addWidget(self.right_panel)
        right_layout.addStretch()

        layout.addLayout(left_layout, 0)
        layout.addStretch(1)
        layout.addLayout(center_layout, 0)
        layout.addStretch(1)
        layout.addLayout(right_layout, 0)

        return screen

    def _build_loading_screen(self):
        return LoadingScreen()

    def _build_main_screen(self):
        return MainScreen()

    def _make_input_block(self, title: str, placeholder: str, password: bool = False):
        container = QFrame()
        container.setObjectName("InputBlock")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        label = QLabel(title)
        label.setObjectName("FieldLabel")
        input_field = QLineEdit()
        input_field.setPlaceholderText(placeholder)
        if password:
            input_field.setEchoMode(QLineEdit.Password)
        layout.addWidget(label)
        layout.addWidget(input_field)
        return {"container": container, "label": label, "input": input_field}

    def _set_mode(self, mode: str):
        self.mode = mode
        self._apply_mode()
        self._refresh_mode_buttons()

    def _apply_mode(self):
        is_register = self.mode == "register"
        self.invite_block["container"].setVisible(is_register)
        current_input_user = self.username_block["input"].text().strip()
        is_returning = (
                bool(state.device_id)
                and current_input_user == state.username
                and current_input_user != ""
        )
        if not is_register and is_returning:
            self.device_block["container"].setVisible(False)
            self.hint_label.setText(f"С возвращением, @{state.username}!")
        else:
            self.device_block["container"].setVisible(True)
            self.hint_label.setText(
                "Вход в защищённый узел Max1m"
                if not is_register
                else "Регистрация нового защищённого узла Max1m"
            )

    def _refresh_mode_buttons(self):
        self.login_button.setProperty("active", self.mode == "login")
        self.register_button.setProperty("active", self.mode == "register")
        self.login_button.style().unpolish(self.login_button)
        self.login_button.style().polish(self.login_button)
        self.register_button.style().unpolish(self.register_button)
        self.register_button.style().polish(self.register_button)

    def _toggle_advanced(self):
        self.advanced_card.setVisible(not self.advanced_card.isVisible())

    def _set_status(self, text: str, error: bool = False):
        self.status_label.setText(text)
        self.status_label.setProperty("error", error)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def apply_join_link_from_ui(self) -> bool:
        raw_link = self.join_link_input.text().strip() if hasattr(self, "join_link_input") else ""
        if not raw_link:
            return False
        try:
            from app.onboarding import parse_join_link, save_prelogin_spki_pins

            cfg = parse_join_link(raw_link)
            save_prelogin_spki_pins(cfg.server_url, cfg.spki_pins, storage_obj=storage)
            self.server_block["input"].setText(cfg.server_url)
            if hasattr(self, "spki_pin_block"):
                self.spki_pin_block["input"].setText(", ".join(cfg.spki_pins))
            if cfg.invite_code:
                self.invite_block["input"].setText(cfg.invite_code)
                self._set_mode("register")
            self.join_link_input.clear()
            title_note = f" «{cfg.node_title}»" if cfg.node_title else ""
            self._set_status(
                f"Узел{title_note} подключён: TLS SPKI ключ закреплён ({len(cfg.spki_pins)} шт.). "
                + ("Инвайт-код подставлен — введите логин и пароль." if cfg.invite_code else "Введите логин и пароль."),
                False,
            )
            return True
        except Exception as exc:
            self._set_status(str(exc), True)
            return False

    def _submit(self):
        server = self.server_block["input"].text().strip()
        username = self.username_block["input"].text().strip()
        password = self.password_block["input"].text()
        device_name = self.device_block["input"].text().strip()
        invite_code = self.invite_block["input"].text().strip()

        if not server:
            return self._set_status("Укажи адрес сервера", True)
        validate_url_fn = globals().get("validate_server_url")
        if callable(validate_url_fn):
            url_ok, url_err = validate_url_fn(server)
            if not url_ok:
                return self._set_status(url_err, True)
        spki_blk = getattr(self, "spki_pin_block", None)
        raw_spki_text = spki_blk["input"].text().strip() if isinstance(spki_blk, dict) and "input" in spki_blk else ""
        if raw_spki_text:
            try:
                from app.onboarding import save_prelogin_spki_pins

                pins_list = [p.strip() for p in re.split(r"[,;|]", raw_spki_text) if p.strip()]
                save_prelogin_spki_pins(server, pins_list, storage_obj=storage)
            except Exception as exc:
                return self._set_status(f"Некорректный TLS SPKI Pin: {exc}", True)
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            return self._set_status("Имя: 3–30 латинских букв, цифр или знаков подчёркивания", True)
        if (state.device_id and state.username == username and
                (state.server_url or '').rstrip('/') != server.rstrip('/')):
            return self._set_status("Этот локальный профиль уже привязан к другому серверу. Автоматическая замена ключа отключена.", True)
        if len(password) < 8:
            return self._set_status(
                "Пароль должен быть не короче 8 символов", True
            )

        is_returning = bool(state.device_id) and state.username == username
        if not is_returning and not device_name:
            return self._set_status("Укажи название устройства", True)
        if self.mode == "register" and not invite_code:
            return self._set_status("Для регистрации нужен инвайт-код", True)

        self.submit_button.setEnabled(False)

        if self.mode == "register":
            self._start_registration(server, username, password, device_name, invite_code)
        else:
            self._start_login(server, username, password, device_name)

    def _start_registration(self, server, username, password, device_name, invite_code):
        try:
            identity_setup.prepare_new_identity(username, server, "register", crypto)
        except Exception:
            self.submit_button.setEnabled(True)
            return self._set_status("Локальный ключ или профиль уже существует либо недоступен. Он не перезаписан; требуется восстановление.", True)

        payload = {
            "username": username, "password": password,
            "invite_code": invite_code, "device_name": device_name,
            "public_key": crypto.get_public_key_b64(),
            "fingerprint": crypto.get_fingerprint()
        }

        self.worker = RegisterWorker(server_url=server, payload=payload)
        self.worker.auth_context = (server.rstrip('/'), username, device_name, "register", crypto.get_public_key_b64())
        self.worker._register_password = password
        self.worker.finished.connect(self._on_register_finished)
        self.stack.setCurrentWidget(self.loading_screen)
        self._update_auth_animation_state()
        self.loading_screen.set_status(
            "Генерация E2EE ключей",
            f"Ваш Fingerprint:\n{payload['fingerprint']}",
            "Шаг 1 / 3"
        )
        self.worker.start()

    def _on_register_finished(self, success: bool, response_data: dict | str):
        password = getattr(self.worker, "_register_password", None)
        if hasattr(self.worker, "_register_password"):
            self.worker._register_password = None
        self.submit_button.setEnabled(True)
        if success:
            server, username, device_name, purpose, expected_public = self.worker.auth_context
            device_id = response_data.get("device_id") if isinstance(response_data, dict) else None
            if (not isinstance(device_id, str) or not device_id
                    or not identity_setup.current_identity_matches(username, crypto, expected_public)):
                self.stack.setCurrentWidget(self.auth_screen)
                self._update_auth_animation_state()
                return self._set_status("Сервер не подтвердил устройство; ключ сохранён для восстановления.", True)
            try:
                storage.save_local_state({"server_url": server, "username": username,
                                          "device_name": device_name, "device_id": device_id})
            except Exception:
                self.stack.setCurrentWidget(self.auth_screen)
                self._update_auth_animation_state()
                return self._set_status("Не удалось сохранить устройство. Ключ сохранён; может потребоваться восстановление.", True)
            state.server_url, state.username, state.device_name, state.device_id = server, username, device_name, device_id
            try:
                identity_setup.finish_identity(username, server, purpose, crypto)
            except Exception:
                # Preserve any unreadable/mismatched marker for recovery.
                print("[AUTH] Не удалось завершить сохранение маркера ключа")
            save_profile = getattr(storage, "save_profile_device", None)
            if callable(save_profile):
                try:
                    save_profile(username, server, device_id, device_name, expected_public)
                except Exception:
                    print("[AUTH] Не удалось сохранить привязку устройства профиля")
            if hasattr(storage, "save_tls_pins") and hasattr(storage, "load_tls_pins"):
                try:
                    from app.onboarding import promote_prelogin_spki_pins
                    promote_prelogin_spki_pins(username, server, storage_obj=storage)
                except Exception:
                    pass
            if callable(getattr(self, "_set_mode", None)):
                self._set_mode("login")
            if isinstance(password, str) and password and callable(getattr(self, "_start_login", None)):
                self.submit_button.setEnabled(False)
                self._start_login(server, username, password, device_name)
                return
            if hasattr(self, "auth_screen") and hasattr(self.stack, "setCurrentWidget"):
                self.stack.setCurrentWidget(self.auth_screen)
            self._update_auth_animation_state()
            if callable(getattr(self, "_set_status", None)):
                self._set_status("Устройство зарегистрировано. Выполните вход.", False)
        else:
            self.stack.setCurrentWidget(self.auth_screen)
            self._update_auth_animation_state()
            self._set_status(response_data, True)

    def _start_login(self, server, username, password, device_name):
        payload = {"username": username, "password": password}
        clean_server = server.rstrip("/")

        ensure_vault_fn = getattr(self, "_ensure_vault_unlocked_ui", None)
        if callable(ensure_vault_fn):
            if not ensure_vault_fn(username):
                self.submit_button.setEnabled(True)
                return

        profile_record = None
        storage_obj = globals().get("storage")
        load_profile = getattr(storage_obj, "load_profile_device", None)
        if callable(load_profile):
            try:
                profile_record = load_profile(username)
            except Exception:
                self.submit_button.setEnabled(True)
                return self._set_status(
                    "Локальный профиль устройства повреждён или недоступен. Требуется восстановление.",
                    True,
                )

        existing_device_id = None
        bound_server = None
        expected_saved_pub = None
        if profile_record is not None:
            existing_device_id = profile_record.get("device_id")
            bound_server = profile_record.get("server_url")
            expected_saved_pub = profile_record.get("public_key")
            if not device_name:
                device_name = profile_record.get("device_name") or device_name
        elif getattr(state, "device_id", None) and getattr(state, "username", None) == username:
            existing_device_id = state.device_id
            bound_server = getattr(state, "server_url", None)

        if existing_device_id:
            if isinstance(bound_server, str) and bound_server.strip() and bound_server.rstrip("/") != clean_server:
                self.submit_button.setEnabled(True)
                return self._set_status(
                    f"Локальный профиль @{username} привязан к другому серверу ({bound_server.rstrip('/')}).",
                    True,
                )
            payload["device_id"] = existing_device_id
            try:
                priv_key = storage.get_private_key(username)
                if not priv_key:
                    raise ValueError("Missing private key")
                crypto.load_private_key(priv_key)
                if expected_saved_pub and crypto.get_public_key_b64() != expected_saved_pub:
                    raise ValueError("Private key does not match profile device")
            except Exception:
                self.submit_button.setEnabled(True)
                return self._set_status("Ключ устройства недоступен. Восстановите исходный keyring и профиль.", True)
            status_title = "Проверка устройства"
            status_msg = "Авторизация существующего устройства в сети Max1m."
        else:
            try:
                identity_setup.prepare_new_identity(username, server, "device", crypto)
            except Exception:
                self.submit_button.setEnabled(True)
                return self._set_status("Локальный ключ или профиль уже существует либо недоступен. Он не перезаписан; требуется восстановление.", True)
            payload["device_name"] = device_name
            payload["public_key"] = crypto.get_public_key_b64()
            payload["fingerprint"] = crypto.get_fingerprint()
            status_title = "Регистрация устройства"
            status_msg = (
                f"Генерация ключей для нового устройства.\n"
                f"Ваш Fingerprint:\n{payload['fingerprint']}"
            )

        self.worker = LoginWorker(server_url=server, payload=payload)
        self.worker.auth_context = (server.rstrip('/'), username, device_name,
                                    None if "device_id" in payload else "device", payload.get("device_id"),
                                    crypto.get_public_key_b64())
        self.worker.finished.connect(self._on_login_finished)
        self.stack.setCurrentWidget(self.loading_screen)
        self._update_auth_animation_state()
        self.loading_screen.set_status(status_title, status_msg, "Авторизация...")
        self.worker.start()

    def _on_login_finished(self, success: bool, response_data: dict | str):
        self.submit_button.setEnabled(True)
        if success:
            server, username, device_name, purpose, expected_device_id, expected_public = self.worker.auth_context
            token = response_data.get("access_token") if isinstance(response_data, dict) else None
            new_device_id = response_data.get("device_id") if isinstance(response_data, dict) else None
            if not isinstance(token, str) or not token or not isinstance(new_device_id, str) or not new_device_id:
                self.stack.setCurrentWidget(self.auth_screen)
                self._update_auth_animation_state()
                return self._set_status("Сервер не подтвердил авторизацию; ключ сохранён.", True)
            try:
                valid_device = (response_data.get("device_public_key") == expected_public
                                and identity_setup.current_identity_matches(username, crypto, expected_public)
                                and (expected_device_id is None or new_device_id == expected_device_id))
            except Exception:
                valid_device = False
            if not valid_device:
                self.stack.setCurrentWidget(self.auth_screen)
                self._update_auth_animation_state()
                return self._set_status("Ключ или ID устройства не совпадает с ответом сервера. Проверьте keyring или обновите сервер.", True)
            device_name = device_name or state.device_name
            try:
                storage.save_local_state({"server_url": server, "username": username,
                                          "device_name": device_name, "device_id": new_device_id})
            except Exception:
                self.stack.setCurrentWidget(self.auth_screen)
                self._update_auth_animation_state()
                return self._set_status("Не удалось сохранить устройство. Ключ сохранён; может потребоваться восстановление.", True)
            state.server_url, state.token, state.username, state.device_id = server, token, username, new_device_id
            state.device_name = device_name
            if purpose:
                try:
                    identity_setup.finish_identity(username, server, purpose, crypto)
                except Exception:
                    print("[AUTH] Не удалось завершить сохранение маркера ключа")
            save_profile = getattr(storage, "save_profile_device", None)
            if callable(save_profile):
                try:
                    save_profile(username, server, new_device_id, device_name, expected_public)
                except Exception:
                    print("[AUTH] Не удалось сохранить привязку устройства профиля")
            if hasattr(storage, "save_tls_pins") and hasattr(storage, "load_tls_pins"):
                try:
                    from app.onboarding import promote_prelogin_spki_pins
                    promote_prelogin_spki_pins(username, server, storage_obj=storage)
                except Exception:
                    pass
            self.main_screen._load_allies_from_storage()
            if hasattr(self.main_screen, "_load_groups_from_storage"):
                self.main_screen._load_groups_from_storage()

            old_ws = getattr(self, "ws_worker", None)
            if old_ws is not None:
                old_ws.stop()
                old_ws.wait(1000)

            print("[UI] Запускаем WebSocketWorker...")
            self.ws_worker = WebSocketWorker(
                state.server_url, state.token, state.device_id
            )

            worker = self.ws_worker
            worker.account_context = (state.username, state.server_url, state.device_id, state.token)
            for signal, handler in (
                (worker.new_message_received, self._on_incoming_message),
                (worker.group_message_received, self._on_incoming_group_message),
                (worker.group_created_received, self._on_group_created_event),
                (worker.group_invited_received, self._on_group_invited_event),
                (worker.group_member_joined, self._on_group_member_joined),
                (worker.group_member_left, self._on_group_member_left),
                (worker.group_deleted_received, self._on_group_deleted_event),
                (worker.webrtc_signal_received, self._on_webrtc_signal),
                (worker.call_offer_received, self._on_call_offer),
                (worker.call_accept_received, self._on_call_accepted),
                (worker.call_ended_received, self._on_call_ended),
            ):
                self._connect_ws_event(worker, signal, handler)
            sk_upd_sig = getattr(worker, "group_sender_key_updated", None)
            if sk_upd_sig is not None:
                self._connect_ws_event(
                    worker,
                    sk_upd_sig,
                    getattr(self, "_on_group_sender_key_updated", lambda *a: None),
                )
            gv_state_sig = getattr(worker, "group_voice_state_received", None)
            if gv_state_sig is not None and hasattr(self.main_screen, "on_group_voice_state_event"):
                self._connect_ws_event(worker, gv_state_sig, self.main_screen.on_group_voice_state_event)
            gv_sig_sig = getattr(worker, "group_voice_signal_received", None)
            if gv_sig_sig is not None and hasattr(self.main_screen, "on_group_voice_signal_event"):
                self._connect_ws_event(worker, gv_sig_sig, self.main_screen.on_group_voice_signal_event)
            worker.connection_status.connect(
                lambda status, w=worker: self._on_ws_connection_status(status, w), Qt.QueuedConnection)

            self.ws_worker.start()

            self._sync_cursor = None
            self._sync_version_warning_shown = False
            self._sync_timer.start()
            self._start_message_sync()
            if hasattr(self.main_screen, "_try_outbox"):
                QTimer.singleShot(0, self.main_screen._try_outbox)
            if hasattr(self.main_screen, "_try_attachment_outbox"):
                QTimer.singleShot(0, self.main_screen._try_attachment_outbox)
            if hasattr(self.main_screen, "sync_own_prekey_bundle"):
                QTimer.singleShot(0, self.main_screen.sync_own_prekey_bundle)
            if hasattr(self.main_screen, "sync_ice_config"):
                QTimer.singleShot(0, self.main_screen.sync_ice_config)

            from app.workers import FetchGroupsWorker
            self.groups_fetch_worker = FetchGroupsWorker(state.server_url, state.token)
            group_worker = self.groups_fetch_worker
            group_worker.account_context = (state.username, state.server_url, state.device_id, state.token)
            group_worker.finished.connect(lambda ok, data, w=group_worker: self._on_groups_fetched(ok, data, w), Qt.QueuedConnection)
            group_worker.start()

            self.loading_screen.set_status(
                "Успех!", "Защищённое соединение с узлом установлено.", "Готово"
            )
            QTimer.singleShot(
                1500, lambda: self.stack.setCurrentWidget(self.main_screen)
            )
            self._update_auth_animation_state()
        else:
            self.stack.setCurrentWidget(self.auth_screen)
            self._update_auth_animation_state()
            self._set_status(response_data, True)

    def _connect_ws_event(self, worker, signal, handler):
        def deliver(data):
            try:
                if (worker is self.ws_worker and worker.account_context ==
                        (state.username, state.server_url, state.device_id, state.token)):
                    handler(data)
            finally:
                worker.release_event()
        signal.connect(deliver, Qt.QueuedConnection)

    def _on_ws_connection_status(self, status, worker):
        if (worker is not self.ws_worker or worker.account_context !=
                (state.username, state.server_url, state.device_id, state.token)):
            return
        if status == "auth_check":
            self._on_sync_connection_status(status)
            return
        self.main_screen.update_connection_status(status)
        self._on_sync_connection_status(status)

    def _on_group_deleted_event(self, data: dict):
        group_id = data.get("group_id")
        if hasattr(self, "main_screen"):
            self.main_screen.force_remove_group(group_id)

    def _on_sync_connection_status(self, status: str):
        if status == "connected":
            self._start_message_sync()
        elif status == "auth_check":
            if getattr(self, "sync_worker", None) is not None or getattr(self, "_ack_worker", None) is not None:
                self._sync_restart_requested = True
            else:
                self._start_message_sync()

    def _on_contact_verification_changed(self):
        # Rescan from the beginning; earlier rejected messages were not acked.
        self._sync_cursor = None
        self._sync_restart_requested = True
        QTimer.singleShot(250, self._start_message_sync)

    def _start_message_sync(self):
        if not state.token or not state.server_url:
            return
        if self.sync_worker is not None or self._ack_worker is not None:
            return
        self._sync_restart_requested = False
        self.sync_worker = SyncMessagesWorker(state.server_url, state.token, self._sync_cursor)
        worker = self.sync_worker
        worker.account_context = (state.username, state.server_url, state.device_id, state.token)
        worker.finished.connect(lambda ok, data, w=worker: self._on_sync_finished(ok, data, w), Qt.QueuedConnection)
        worker.start()

    def _on_sync_finished(self, success: bool, messages: list | str, worker):
        worker.wait()
        if worker is not self.sync_worker:
            return
        self.sync_worker = None
        if worker.account_context != (state.username, state.server_url, state.device_id, state.token):
            self._sync_cursor = None
            return
        if not success or not isinstance(messages, list):
            if isinstance(messages, str) and messages.startswith(("HTTP 401:", "HTTP 403:")):
                invalidate_fn = getattr(self, "_handle_remote_session_invalidated", None)
                if callable(invalidate_fn):
                    invalidate_fn("Сессия истекла или устройство отозвано. Выполните вход снова.")
                return
            print(f"[SYNC] Ошибка безопасной синхронизации: {messages}")
            self._sync_cursor = None
            if self._sync_restart_requested:
                self._sync_restart_requested = False
                QTimer.singleShot(250, self._start_message_sync)
            if isinstance(messages, str) and messages.startswith("HTTP 404:") and not self._sync_version_warning_shown:
                self._sync_version_warning_shown = True
                QMessageBox.warning(
                    self, "Требуется обновление сервера",
                    "Сервер не поддерживает безопасную синхронизацию. "
                    "Обновите сервер Max1m: сообщения, отправленные вам вне сети, "
                    "не будут загружены до обновления."
                )
            return
        if not hasattr(self, "main_screen") or self.main_screen is None:
            self._sync_cursor = None
            return

        account_context = worker.account_context
        screen = self.main_screen
        def process_for_account(message):
            current = (state.username, state.server_url, state.device_id, state.token)
            if current != account_context or getattr(self, "main_screen", None) is not screen:
                return False
            accepted = screen.process_incoming_message(message, is_sync=True)
            return (accepted and getattr(self, "main_screen", None) is screen and account_context ==
                    (state.username, state.server_url, state.device_id, state.token))

        processed, next_cursor = process_delivery_page(messages, process_for_account)
        if (getattr(self, "main_screen", None) is not screen or account_context !=
                (state.username, state.server_url, state.device_id, state.token)):
            # Never acknowledge or advance a page under a different session.
            self._sync_cursor = None
            return

        if processed:
            # Only one acknowledgement request may run at a time. Continue the
            # scan only after it finishes; otherwise slow servers can create an
            # unbounded number of QThreads while the cursor races ahead.
            worker = AcknowledgeMessagesWorker(account_context[1], account_context[3], processed)
            worker.account_context = account_context
            worker.next_cursor = next_cursor
            self._ack_worker = worker
            worker.finished.connect(lambda ok, result, w=worker: self._on_delivery_ack_finished(ok, result, w),
                                    Qt.QueuedConnection)
            worker.start()
            return
        self._continue_message_sync(next_cursor)

    def _continue_message_sync(self, next_cursor):
        if self._sync_restart_requested:
            self._sync_cursor = None
            self._sync_restart_requested = False
            QTimer.singleShot(250, self._start_message_sync)
        elif next_cursor:
            self._sync_cursor = next_cursor
            QTimer.singleShot(250, self._start_message_sync)
        else:
            self._sync_cursor = None

    def _on_delivery_ack_finished(self, success: bool, result, worker):
        worker.wait()
        if worker is not self._ack_worker:
            return
        self._ack_worker = None
        if worker.account_context != (state.username, state.server_url, state.device_id, state.token):
            self._sync_cursor = None
            return
        if not success:
            if result in (401, 403):
                invalidate_fn = getattr(self, "_handle_remote_session_invalidated", None)
                if callable(invalidate_fn):
                    invalidate_fn("Сессия истекла или устройство отозвано. Выполните вход снова.")
                return
            print(f"[SYNC] Не удалось подтвердить доставку: {result}; повторим при следующей синхронизации")
        self._continue_message_sync(worker.next_cursor)

    def _on_incoming_message(self, data: dict):
        if hasattr(self, "main_screen") and self.main_screen is not None:
            self.main_screen.process_incoming_message(data)

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.ActivationChange and self.isActiveWindow():
            QTimer.singleShot(0, self._on_window_activated)

    def _on_window_activated(self):
        screen = getattr(self, "main_screen", None)
        stack = getattr(self, "stack", None)
        if self.isActiveWindow() and screen and stack and stack.currentWidget() is screen:
            screen._mark_visible_history_read()

    def toggle_maximize(self):
        if not self._is_maximized:
            self._normal_rect = self.geometry()
            screen = QApplication.screenAt(self.geometry().center())
            if not screen:
                screen = QApplication.primaryScreen()
            self.setGeometry(screen.availableGeometry())
            self._is_maximized = True
            self.titlebar.update_max_icon(True)
        else:
            if self._normal_rect is not None:
                self.setGeometry(self._normal_rect)
            self._is_maximized = False
            self.titlebar.update_max_icon(False)

    def _center_window(self):
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            x = geo.x() + (geo.width() - self.width()) // 2
            y = geo.y() + (geo.height() - self.height()) // 2
            self.move(x, y)

    def _update_auth_animation_state(self):
        if isinstance(self.auth_screen, AnimatedAuthBackground):
            is_auth_visible = self.stack.currentWidget() is self.auth_screen
            self.auth_screen.set_animation_active(is_auth_visible)

    def show_notification(self, title: str, message: str, is_group: bool = False):
        mask_fn = getattr(storage, "should_mask_notifications", None)
        masked = bool(mask_fn(getattr(state, "username", ""))) if callable(mask_fn) else False
        if masked:
            self.in_app_toast.show_notification("Max1m", "🔒 Новое зашифрованное сообщение", is_group=False)
            return
        self.in_app_toast.show_notification(title, message, is_group=is_group)

    def _on_notification_clicked(self, sender_username: str):
        print(f"[NOTIFY] Клик: {sender_username}")

        if self.isMinimized():
            self.showNormal()

        self.raise_()
        self.activateWindow()

        if getattr(self, "_vault_locked", False):
            return
        if self.stack.currentWidget() != self.main_screen:
            self.stack.setCurrentWidget(self.main_screen)

        if sender_username and sender_username != "Max1m" and hasattr(self.main_screen, "open_chat_by_username"):
            self.main_screen.open_chat_by_username(sender_username)

    def _on_incoming_group_message(self, data: dict):
        print(f"[WS GROUP] Групповое сообщение: {data.get('group_id')}")
        if hasattr(self, "main_screen") and hasattr(self.main_screen, "process_incoming_group_message"):
            self.main_screen.process_incoming_group_message(data)
        else:
            print("[GROUPS] Сообщение оставлено на сервере: приём групп временно недоступен")

    def _on_group_created_event(self, data: dict):
        print(f"[WS GROUP] Создана группа: {data.get('group_name')}")
        if hasattr(self, "main_screen") and hasattr(self.main_screen, "process_group_created_event"):
            self.main_screen.process_group_created_event(data)
        else:
            print("[GROUPS] Обновление группы будет загружено при следующем входе")

    def _on_group_invited_event(self, data: dict):
        print(f"[WS GROUP] Приглашение в группу: {data.get('group_id')}")
        if hasattr(self, "main_screen") and hasattr(self.main_screen, "process_group_created_event"):
            self.main_screen.process_group_created_event(data)
        else:
            print("[GROUPS] Обновление группы будет загружено при следующем входе")

    def _on_group_member_joined(self, data: dict):
        if hasattr(self, "main_screen") and hasattr(self.main_screen, "process_group_member_joined"):
            self.main_screen.process_group_member_joined(data)

    def _on_group_member_left(self, data: dict):
        if hasattr(self, "main_screen") and hasattr(self.main_screen, "process_group_member_left"):
            self.main_screen.process_group_member_left(data)

    def _on_group_sender_key_updated(self, data: dict):
        if hasattr(self, "main_screen") and hasattr(self.main_screen, "process_group_sender_key_updated"):
            self.main_screen.process_group_sender_key_updated(data)

    def _on_groups_fetched(self, success: bool, data, worker):
        worker.wait()
        if worker is not self.groups_fetch_worker:
            return
        if worker.account_context != (state.username, state.server_url, state.device_id, state.token):
            return
        self.groups_fetch_worker = None
        if not success:
            print(f"[GROUPS] Ошибка загрузки групп: {data}")
            return

        if not isinstance(data, list):
            return

        print(f"[GROUPS] Загружено групп: {len(data)}")

        server_ids = set()
        for group_info in data:
            group_id = group_info.get("id")
            if not group_id:
                continue
            server_ids.add(group_id)

            srv_name = group_info.get("name", "")
            if group_id not in state.groups:
                disp_name = f"Группа {group_id[:8]}" if srv_name == "[E2EE]" else srv_name
                entry = {
                    "name": disp_name,
                    "created_by_device_id": group_info.get("created_by_device_id", ""),
                    "members": group_info.get("members", []),
                    "archived": False,
                    "my_sender_key": None,  # No unannounced keys on restart.
                    "sender_keys": {}
                }
                if "epoch" in group_info:
                    entry["epoch"] = int(group_info.get("epoch", 1) or 1)
                state.groups[group_id] = entry
            else:
                prev_name = state.groups[group_id].get("name", "")
                if srv_name and srv_name != "[E2EE]":
                    state.groups[group_id]["name"] = srv_name
                elif not prev_name:
                    state.groups[group_id]["name"] = f"Группа {group_id[:8]}"
                state.groups[group_id]["created_by_device_id"] = group_info.get(
                    "created_by_device_id", state.groups[group_id].get("created_by_device_id", "")
                )
                state.groups[group_id]["members"] = group_info.get("members", [])
                state.groups[group_id]["archived"] = False
                if "epoch" in group_info:
                    state.groups[group_id]["epoch"] = max(
                        int(state.groups[group_id].get("epoch", 1) or 1),
                        int(group_info.get("epoch", 1) or 1),
                    )

            if hasattr(self, "main_screen") and self.main_screen is not None:
                existing = self.main_screen._get_group_item(group_id)
                if not existing:
                    self.main_screen._add_group_card(
                        group_id,
                        state.groups[group_id].get("name", srv_name)
                    )
                elif hasattr(self.main_screen, "_get_group_card"):
                    card = self.main_screen._get_group_card(group_id)
                    if card:
                        card.setToolTip("")

        for existing_id, group_data in list(state.groups.items()):
            if existing_id not in server_ids:
                group_data["archived"] = True
                group_data["my_sender_key"] = None
                if hasattr(self, "main_screen") and self.main_screen is not None and hasattr(self.main_screen, "force_remove_group"):
                    self.main_screen.force_remove_group(existing_id)

        if hasattr(self, "main_screen") and self.main_screen is not None and hasattr(self.main_screen, "_persist_groups_index"):
            self.main_screen._persist_groups_index()

        post_sync = getattr(self, "_sync_group_keys_after_fetch", None)
        if callable(post_sync):
            post_sync()

    def _refresh_groups_from_server(self):
        if not state.token or (self.groups_fetch_worker and self.groups_fetch_worker.isRunning()):
            return
        from app.workers import FetchGroupsWorker

        w = FetchGroupsWorker(state.server_url, state.token)
        w.account_context = (state.username, state.server_url, state.device_id, state.token)
        self.groups_fetch_worker = w
        w.finished.connect(lambda ok, d, wk=w: self._on_groups_fetched(ok, d, wk), Qt.QueuedConnection)
        w.start()

    def _sync_group_keys_after_fetch(self):
        if not state.token or not hasattr(self, "main_screen") or not self.main_screen:
            return
        if hasattr(self.main_screen, "restore_persisted_group_keys"):
            self.main_screen.restore_persisted_group_keys()
        for gid, gdata in list(state.groups.items()):
            if not isinstance(gdata, dict) or gdata.get("archived"):
                continue
            self.fetch_sender_keys_for_group(gid)
            if hasattr(self.main_screen, "ensure_my_group_sender_key"):
                self.main_screen.ensure_my_group_sender_key(gid)
        self._start_group_sync()

    def fetch_sender_keys_for_group(self, group_id: str):
        if not state.token or not group_id or not hasattr(self, "main_screen") or not self.main_screen:
            return
        from app.workers import FetchGroupSenderKeysWorker

        w = FetchGroupSenderKeysWorker(state.server_url, state.token, group_id)
        w.account_context = (state.username, state.server_url, state.device_id, state.token)
        w.finished.connect(
            lambda ok, d, gid, wk=w: self._on_sender_keys_fetched(ok, d, gid, wk),
            Qt.QueuedConnection,
        )
        self.main_screen._net_workers.append(w)
        w.start()

    def _start_group_sync(self):
        if not state.token or not state.groups:
            return
        if self._group_sync_worker and self._group_sync_worker.isRunning():
            return
        from app.workers import SyncGroupMessagesWorker

        w = SyncGroupMessagesWorker(state.server_url, state.token)
        w.account_context = (state.username, state.server_url, state.device_id, state.token)
        self._group_sync_worker = w
        w.finished.connect(
            lambda ok, msgs, wk=w: self._on_group_sync_finished(ok, msgs, wk),
            Qt.QueuedConnection,
        )
        if hasattr(self, "main_screen") and self.main_screen:
            self.main_screen._net_workers.append(w)
        w.start()

    def _on_group_sync_finished(self, success: bool, messages, worker=None):
        if worker is not None:
            worker.wait()
            if hasattr(self, "main_screen") and self.main_screen and worker in self.main_screen._net_workers:
                self.main_screen._net_workers.remove(worker)
            if worker is self._group_sync_worker:
                self._group_sync_worker = None
            if getattr(worker, "account_context", None) != (
                state.username, state.server_url, state.device_id, state.token
            ):
                return

        if not success or not isinstance(messages, list) or not messages:
            return

        if hasattr(self, "main_screen") and hasattr(self.main_screen, "process_incoming_group_message"):
            acked_ids = []
            for msg in messages:
                # process_incoming_group_message(_from_deferred=True) avoids per-msg ACK so we batch-ACK here!
                if self.main_screen.process_incoming_group_message(msg, _from_deferred=True):
                    mid = msg.get("id") or msg.get("message_id")
                    if mid:
                        acked_ids.append(mid)
            if acked_ids and hasattr(self.main_screen, "_queue_group_ack"):
                self.main_screen._queue_group_ack(acked_ids)

    def _on_sender_keys_fetched(self, success, data, group_id, worker=None):
        if worker is not None:
            worker.wait()
            if hasattr(self, "main_screen") and self.main_screen and worker in self.main_screen._net_workers:
                self.main_screen._net_workers.remove(worker)
            if getattr(worker, "account_context", None) != (
                state.username, state.server_url, state.device_id, state.token
            ):
                return
        if not success or not isinstance(data, list) or group_id not in state.groups:
            return
        if not hasattr(self, "main_screen") or not self.main_screen:
            return
        for entry in data:
            if not isinstance(entry, dict):
                continue
            self.main_screen.ingest_sender_key_entry(
                group_id=group_id,
                sender_device_id=entry.get("sender_device_id", ""),
                encrypted_sender_key=entry.get("encrypted_sender_key", ""),
                sender_key_signature=entry.get("sender_key_signature", ""),
                epoch=int(entry.get("epoch", 1) or 1),
            )

    def _on_rtc_state_change(self, peer_device_id: str, call_id: str, status: str):
        # aiortc calls this on its worker thread; never manipulate Qt there.
        self.rtc_state_changed.emit(peer_device_id, call_id, status)

    def _apply_rtc_state_change(self, peer_device_id: str, call_id: str, status: str):
        if (not hasattr(self, "main_screen") or not self.main_screen
                or self.main_screen._active_call_id != call_id
                or self.main_screen._active_call_device_id != peer_device_id):
            return
        handler = getattr(self.main_screen, "_update_rtc_state", None)
        if callable(handler):
            handler(peer_device_id, status)

    def _on_screen_share_state(self, active: bool, quality: str):
        self.rtc_screen_state_changed.emit(bool(active), str(quality or "balanced"))

    def _apply_screen_share_state(self, active: bool, quality: str):
        if not hasattr(self, "main_screen") or not self.main_screen:
            return
        handler = getattr(self.main_screen, "_update_screen_share_ui", None)
        if callable(handler):
            handler(active, quality)

    def _on_remote_screen_state(self, peer_device_id: str, call_id: str, active: bool):
        self.rtc_remote_screen_state_changed.emit(str(peer_device_id), str(call_id), bool(active))

    def _apply_remote_screen_state(self, peer_device_id: str, call_id: str, active: bool):
        screen = getattr(self, "main_screen", None)
        if not screen:
            return
        if not active:
            if screen._active_call_device_id in (None, peer_device_id):
                stopper = getattr(screen, "_on_screen_share_stopped", None)
                if callable(stopper):
                    stopper(peer_device_id)
            return
        if screen._active_call_id != call_id or screen._active_call_device_id != peer_device_id:
            return
        starter = getattr(screen, "_on_screen_share_started", None)
        if callable(starter):
            starter(peer_device_id)

    def _on_rtc_screen_frame(self, peer_device_id: str, call_id: str, rgb_array, fps: float):
        should_emit = False
        with self._screen_frame_lock:
            self._screen_frame_mailbox = (peer_device_id, call_id, rgb_array, float(fps or 0.0))
            if not self._screen_frame_ui_queued:
                self._screen_frame_ui_queued = True
                should_emit = True
        if should_emit:
            self.rtc_screen_frame_ready.emit()

    def _drain_latest_screen_frame(self):
        with self._screen_frame_lock:
            item = self._screen_frame_mailbox
            self._screen_frame_mailbox = None
            self._screen_frame_ui_queued = False
        if not item:
            return
        peer_device_id, call_id, rgb_array, fps = item
        screen = getattr(self, "main_screen", None)
        if (
            not screen
            or screen._active_call_id != call_id
            or screen._active_call_device_id != peer_device_id
        ):
            return
        handler = getattr(screen, "_on_screen_frame_numpy", None)
        if callable(handler):
            handler(rgb_array, fps=fps)

    def _verified_call_event(self, data):
        """Reject unsigned, misaddressed, stale and replayed signaling."""
        try:
            sender = data.get("from_device_id")
            context = resolve_call_peer(state, sender)
            if context is None:
                return None
            event = call_envelope.open_envelope(crypto, data, state.device_id, context.public_key)
            screen = getattr(self, "main_screen", None)
            if not screen:
                return None
            if event["kind"] == "call_offer":
                if not call_envelope.remember_offer(state.username, state.server_url, state.device_id,
                                                    sender, event["call_id"]):
                    return None
            else:
                pinned = screen._active_call_context
                # A pre-verification hangup may dismiss a ringing offer, but
                # SDP/ICE and acceptance require the original verified key.
                if (context != pinned or not call_context_valid(state, pinned, event["kind"] != "call_ended")
                        or screen._active_call_device_id != sender or
                        screen._active_call_id != event["call_id"]):
                    return None
                scope = (sender, event["call_id"])
                if getattr(self, "_call_seen_scope", None) != scope:
                    self._call_seen_scope, self._call_seen_events = scope, set()
                if event["event_id"] in self._call_seen_events or len(self._call_seen_events) >= 4096:
                    return None
                self._call_seen_events.add(event["event_id"])
            event["peer_context"] = context
            return event
        except Exception as e:
            print(f"[CALL] Сигнал отклонён: {type(e).__name__}")
            return None

    def _send_call_event(self, kind, recipient, call_id, content=None):
        try:
            screen = getattr(self, "main_screen", None)
            pinned = getattr(screen, "_active_call_context", None)
            if (not screen or pinned is None or pinned.device_id != recipient
                    or screen._active_call_id != call_id
                    or not call_context_valid(state, pinned, kind != "call_ended")
                    or not getattr(self, "ws_worker", None)):
                return False
            envelope = call_envelope.seal(crypto, kind, state.device_id, recipient, call_id, pinned.public_key, content)
            return self.ws_worker.send_signal(envelope)
        except Exception as e:
            print(f"[CALL] Ошибка подготовки сигнала: {type(e).__name__}")
            return False

    def _on_webrtc_signal(self, data: dict):
        event = self._verified_call_event(data)
        screen = getattr(self, "main_screen", None)
        if not event or not screen or not allow_webrtc_signal(
            event["sender"], screen._active_call_device_id, screen._call_signal_authorized,
        ):
            return
        inner = event.get("content")
        if (not isinstance(inner, dict) or inner.get("type") != "webrtc_signal"
                or inner.get("to_device_id") != state.device_id):
            return
        rtc.handle_encrypted_signal({**inner, "from_device_id": event["sender"]}, event["call_id"])

    def _on_call_accepted(self, data: dict):
        event = self._verified_call_event(data)
        if event and getattr(self, "main_screen", None):
            self.main_screen._on_call_accepted({"from_device_id": event["sender"]})

    def _get_peer_public_key(self, device_id: str):
        # Called by the WebRTC thread too. Never use the first of ambiguous IDs,
        # or a replacement key after the call has started.
        screen = getattr(self, "main_screen", None)
        pinned = getattr(screen, "_active_call_context", None)
        if (pinned and pinned.device_id == device_id
                and call_context_valid(state, pinned, True)):
            return pinned.public_key
        return None

    def _on_call_ended(self, data: dict):
        event = self._verified_call_event(data)
        if event and getattr(self, "main_screen", None):
            self.main_screen._on_remote_call_ended({"from_device_id": event["sender"]})

    def _send_rtc_signal(self, data: dict):
        screen = getattr(self, "main_screen", None)
        if (screen and screen._call_signal_authorized and data.get("type") == "webrtc_signal"
                and data.get("to_device_id") == screen._active_call_device_id
                and data.get("_local_call_id") == screen._active_call_id):
            inner = {key: value for key, value in data.items() if key != "_local_call_id"}
            self._send_call_event("webrtc_signal", screen._active_call_device_id,
                                  screen._active_call_id, inner)

    def _on_call_offer(self, data: dict):
        event = self._verified_call_event(data)
        if event and getattr(self, "main_screen", None):
            self.main_screen._on_incoming_call({"from_device_id": event["sender"],
                                                "call_id": event["call_id"],
                                                "peer_context": event["peer_context"]})

    def _handle_remote_session_invalidated(self, reason: str = ""):
        """Immediately lock local session when server confirms token/device invalidation (HTTP 401/403)."""
        if not getattr(state, "token", ""):
            return
        storage_obj = globals().get("storage")
        crypto_obj = globals().get("crypto")
        rtc_obj = globals().get("rtc")

        save_profile = getattr(storage_obj, "save_profile_device", None)
        if callable(save_profile) and getattr(state, "username", "") and getattr(state, "server_url", "") and getattr(state, "device_id", ""):
            try:
                pub = crypto_obj.get_public_key_b64() if crypto_obj is not None and getattr(crypto_obj, "public_key", None) else None
                save_profile(state.username, state.server_url, state.device_id, getattr(state, "device_name", ""), pub)
            except Exception:
                pass

        if getattr(self, "_sync_timer", None):
            self._sync_timer.stop()

        # Clear token first so any in-flight worker callbacks reject stale account_context
        # and outbox/attachment timers refuse to start new network requests.
        state.token = ""
        self._sync_cursor = None
        self._sync_restart_requested = False

        screen = getattr(self, "main_screen", None)
        if screen is not None:
            history_worker = getattr(screen, "_history_worker", None)
            if history_worker is not None:
                screen._history_pending = None
                cancel_fn = getattr(history_worker, "cancel", None)
                if callable(cancel_fn):
                    cancel_fn()
            if getattr(screen, "_media_queue", None) is not None and hasattr(screen._media_queue, "reset"):
                screen._media_queue.reset()
            if getattr(screen, "_is_recording", False) or (getattr(screen, "_voice_thread", None) and screen._voice_thread.is_alive()):
                screen._cancel_voice_recording()
            if getattr(screen, "_voice_playback", None) is not None:
                screen._stop_voice_playback()
                screen._voice_playback.stop_and_wait(0.2)
            if getattr(screen, "_in_call", False) and hasattr(screen, "_end_call"):
                try:
                    screen._end_call()
                except Exception:
                    pass
        if rtc_obj is not None and hasattr(rtc_obj, "end_call"):
            try:
                rtc_obj.end_call()
            except Exception:
                pass

        ws = getattr(self, "ws_worker", None)
        if ws is not None:
            ws.stop()
            ws.wait(2000)
            self.ws_worker = None

        if screen is not None and hasattr(screen, "reset_session_view"):
            screen.reset_session_view()

        state.current_chat_username = None
        state.current_chat_device_id = None
        state.current_group_id = None
        state.current_chat_type = "ally"
        if hasattr(state, "allies") and hasattr(state.allies, "clear"):
            state.allies.clear()
        if hasattr(state, "groups") and hasattr(state.groups, "clear"):
            state.groups.clear()
        if crypto_obj is not None:
            crypto_obj.private_key = None
            crypto_obj.public_key = None

        if hasattr(self, "password_block") and isinstance(self.password_block, dict) and "input" in self.password_block:
            self.password_block["input"].clear()
        if hasattr(self, "_set_mode"):
            self._set_mode("login")
        if hasattr(self, "stack") and hasattr(self, "auth_screen"):
            self.stack.setCurrentWidget(self.auth_screen)
        if hasattr(self, "_update_auth_animation_state"):
            self._update_auth_animation_state()
        if hasattr(self, "_set_status"):
            self._set_status(
                reason or "Сессия истекла или устройство отозвано. Выполните вход снова.",
                True,
            )

    def logout_session(self) -> bool:
        auth_worker = getattr(self, "worker", None)
        if auth_worker and auth_worker.isRunning():
            QMessageBox.warning(self, "Запрос выполняется", "Дождитесь завершения авторизации перед выходом.")
            return False
        screen = getattr(self, "main_screen", None)
        if screen is not None:
            if (any(w.isRunning() for w in getattr(screen, "_net_workers", ()))
                    or (getattr(screen, "find_worker", None) and screen.find_worker.isRunning())
                    or (getattr(screen, "_outbox_worker", None) and screen._outbox_worker.isRunning())):
                QMessageBox.warning(self, "Сетевой запрос выполняется", "Дождитесь завершения отправки или загрузки перед выходом из сессии.")
                return False
            settings_view = getattr(screen, "settings_screen", None)
            if settings_view and any(w.isRunning() for w in getattr(settings_view, "_net_workers", ())):
                QMessageBox.warning(self, "Запрос безопасности выполняется", "Дождитесь завершения операции с устройствами перед выходом.")
                return False
            if getattr(screen, "_media_queue", None) and screen._media_queue.active:
                screen._media_queue.reset()
                QMessageBox.warning(self, "Вложения ещё скачиваются", "Дождитесь завершения текущих загрузок и повторите выход.")
                return False
            history_worker = getattr(screen, "_history_worker", None)
            if history_worker is not None:
                screen._history_pending = None
                history_worker.cancel()
                if history_worker.isRunning() and not history_worker.wait(300):
                    QMessageBox.warning(self, "История ещё читается", "Повторите выход через секунду.")
                    return False
        for bg in (getattr(self, "sync_worker", None), getattr(self, "_ack_worker", None), getattr(self, "groups_fetch_worker", None)):
            if bg and bg.isRunning() and not bg.wait(200):
                QMessageBox.warning(self, "Синхронизация выполняется", "Дождитесь завершения фоновой синхронизации и повторите выход.")
                return False

        # Ensure current profile's device_id is durably recorded in its own profile before switching users.
        save_profile = getattr(storage, "save_profile_device", None)
        if callable(save_profile) and getattr(state, "username", "") and getattr(state, "server_url", "") and getattr(state, "device_id", ""):
            try:
                pub = crypto.get_public_key_b64() if getattr(crypto, "public_key", None) else None
                save_profile(state.username, state.server_url, state.device_id, getattr(state, "device_name", ""), pub)
            except Exception:
                pass

        if getattr(self, "_sync_timer", None):
            self._sync_timer.stop()
        if screen is not None:
            if getattr(screen, "_is_recording", False) or (getattr(screen, "_voice_thread", None) and screen._voice_thread.is_alive()):
                screen._cancel_voice_recording()
            if getattr(screen, "_voice_playback", None) is not None:
                screen._stop_voice_playback()
                screen._voice_playback.stop_and_wait(0.2)
            if getattr(screen, "_in_call", False) and hasattr(screen, "_end_call"):
                try:
                    screen._end_call()
                except Exception:
                    pass
        try:
            rtc.end_call()
        except Exception:
            pass

        ws = getattr(self, "ws_worker", None)
        if ws is not None:
            ws.stop()
            ws.wait(2000)
            self.ws_worker = None

        self._sync_cursor = None
        if screen is not None and hasattr(screen, "reset_session_view"):
            screen.reset_session_view()

        prev_server_url = getattr(state, "server_url", "")
        prev_token = getattr(state, "token", "")

        state.token = ""
        state.current_chat_username = None
        state.current_chat_device_id = None
        state.current_group_id = None
        state.current_chat_type = "ally"
        state.allies.clear()
        state.groups.clear()
        crypto.private_key = None
        crypto.public_key = None
        _zeroize_fn = getattr(self, "_zeroize_local_vaults", None)
        if callable(_zeroize_fn):
            _zeroize_fn()

        logout_worker_cls = globals().get("LogoutSessionWorker")
        if logout_worker_cls is not None and isinstance(prev_server_url, str) and prev_server_url and isinstance(prev_token, str) and prev_token:
            try:
                if not hasattr(self, "_logout_workers") or self._logout_workers is None:
                    self._logout_workers = []
                lw = logout_worker_cls(prev_server_url, prev_token)
                self._logout_workers.append(lw)

                def _cleanup_lw(_ok=False, _res=None, w=lw):
                    w.wait()
                    workers_list = getattr(self, "_logout_workers", None)
                    if isinstance(workers_list, list) and w in workers_list:
                        workers_list.remove(w)

                qt_mod = globals().get("Qt")
                if qt_mod is not None and hasattr(qt_mod, "QueuedConnection"):
                    lw.finished.connect(_cleanup_lw, qt_mod.QueuedConnection)
                else:
                    lw.finished.connect(_cleanup_lw)
                lw.start()
            except Exception:
                pass

        if hasattr(self, "password_block") and isinstance(self.password_block, dict) and "input" in self.password_block:
            self.password_block["input"].clear()
        if hasattr(self, "_set_mode"):
            self._set_mode("login")
        if hasattr(self, "stack") and hasattr(self, "auth_screen"):
            self.stack.setCurrentWidget(self.auth_screen)
        if hasattr(self, "_update_auth_animation_state"):
            self._update_auth_animation_state()
        if hasattr(self, "_set_status"):
            self._set_status("Сессия завершена. Выполните вход.", False)
        return True

    def closeEvent(self, event):
        # A result not processed before shutdown remains on disk and is safe to
        # retry; wait for the short HTTP timeout to avoid destroying a live QThread.
        auth_worker = getattr(self, "worker", None)
        if auth_worker and auth_worker.isRunning():
            QMessageBox.warning(self, "Вход или регистрация выполняется", "Дождитесь завершения запроса и попробуйте закрыть приложение снова.")
            event.ignore()
            return
        screen = getattr(self, "main_screen", None)
        if screen:
            voice_thread = getattr(screen, "_voice_thread", None)
            if getattr(screen, "_is_recording", False) or (voice_thread and voice_thread.is_alive()):
                screen._cancel_voice_recording()
                if voice_thread and voice_thread.is_alive():
                    QMessageBox.warning(self, "Микрофон ещё закрывается", "Дождитесь остановки записи и попробуйте закрыть приложение снова.")
                    event.ignore()
                    return
            playback = getattr(screen, "_voice_playback", None)
            if playback is not None:
                screen._stop_voice_playback()
                if not playback.stop_and_wait(0.3):
                    QMessageBox.warning(self, "Воспроизведение останавливается", "Дождитесь остановки аудиоустройства и попробуйте закрыть приложение снова.")
                    event.ignore()
                    return
            find_worker = getattr(screen, "find_worker", None)
            if find_worker and find_worker.isRunning():
                QMessageBox.warning(self, "Поиск выполняется", "Дождитесь завершения запроса и попробуйте закрыть приложение снова.")
                event.ignore()
                return
            # Upload/grant callbacks must complete while their QThreads and
            # in-memory attachment state are still alive.
            if any(hasattr(w, "recipient_context") for w in screen._net_workers):
                QMessageBox.warning(self, "Вложение ещё обрабатывается", "Дождитесь завершения загрузки и выдачи доступа, затем закройте приложение.")
                event.ignore()
                return
            if any(getattr(w, "group_id", None) and hasattr(w, "account_context") and w.isRunning()
                   for w in screen._net_workers):
                QMessageBox.warning(self, "Запрос группы выполняется", "Дождитесь завершения запроса и попробуйте закрыть приложение снова.")
                event.ignore()
                return
            if any(w.isRunning() for w in screen._net_workers):
                QMessageBox.warning(self, "Сетевой запрос выполняется", "Дождитесь завершения запроса и попробуйте закрыть приложение снова.")
                event.ignore()
                return
            settings_view = getattr(screen, "settings_screen", None)
            if settings_view and any(w.isRunning() for w in getattr(settings_view, "_net_workers", ())):
                QMessageBox.warning(self, "Запрос безопасности выполняется", "Дождитесь завершения обновления или отзыва устройства и закройте приложение снова.")
                event.ignore()
                return
            group_fetch = getattr(self, "groups_fetch_worker", None)
            if group_fetch and group_fetch.isRunning():
                QMessageBox.warning(self, "Загрузка групп выполняется", "Дождитесь завершения запроса и попробуйте закрыть приложение снова.")
                event.ignore()
                return
            if screen._media_queue.active:
                screen._media_queue.reset()  # discard queued work; active HTTP requests must finish
                QMessageBox.warning(self, "Вложения ещё загружаются", "Дождитесь завершения текущих загрузок и попробуйте закрыть приложение снова.")
                event.ignore()
                return
            history_worker = getattr(screen, "_history_worker", None)
            if history_worker:
                # Even a completed worker may have a queued finished callback.
                screen._history_pending = None
                history_worker.cancel()
                if history_worker.isRunning() and not history_worker.wait(300):
                    QMessageBox.warning(self, "История ещё открывается", "Дождитесь остановки чтения истории и попробуйте закрыть приложение снова.")
                    event.ignore()
                    return
            screen._outbox_timer.stop()
            worker = screen._outbox_worker
            if worker and worker.isRunning() and not worker.wait(11000):
                screen._outbox_timer.start()
                QMessageBox.warning(self, "Отправка ещё выполняется", "Подождите завершения запроса и попробуйте закрыть приложение снова.")
                event.ignore()
                return
        for worker in (self.sync_worker, self._ack_worker):
            if worker and worker.isRunning() and not worker.wait(100):
                if screen:
                    screen._outbox_timer.start()
                QMessageBox.warning(self, "Синхронизация выполняется", "Дождитесь завершения сетевого запроса и попробуйте закрыть приложение снова.")
                event.ignore()
                return
        if getattr(self, "ws_worker", None):
            self.ws_worker.stop()
            if not self.ws_worker.wait(5000):
                if screen:
                    screen._outbox_timer.start()
                QMessageBox.warning(self, "Соединение закрывается", "Дождитесь закрытия соединения и попробуйте снова.")
                event.ignore()
                return
        for lw in list(getattr(self, "_logout_workers", ()) or ()):
            if lw and lw.isRunning() and not lw.wait(1000):
                QMessageBox.warning(self, "Завершение сессии", "Дождитесь отзыва сессии на сервере и закройте приложение снова.")
                event.ignore()
                return
        try:
            rtc.shutdown()
        except Exception:
            pass
        _zeroize_fn = getattr(self, "_zeroize_local_vaults", None)
        if callable(_zeroize_fn):
            _zeroize_fn()
        super().closeEvent(event)