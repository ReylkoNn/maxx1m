import random
import sys
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
    QObject, QMetaObject
)
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QPushButton, QStackedWidget, QLineEdit, QSizeGrip,
    QApplication, QGraphicsDropShadowEffect, QGraphicsOpacityEffect
)

from app.crypto_box import crypto
from app.secure_storage import storage
from app.workers import RegisterWorker, LoginWorker, WebSocketWorker, SyncMessagesWorker
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
    def __init__(self):
        super().__init__()
        self.mode = "login"
        self._is_maximized = False
        self._normal_rect = None
        self.ws_worker = None

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
        rtc.on_signal_generated  = self._send_rtc_signal
        rtc.on_state_change      = self._on_rtc_state_change
        rtc.on_screen_share_state = self._on_screen_share_state
        rtc.get_peer_public_key  = self._get_peer_public_key


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
        """
        Входящий кадр демки из WebSocket.
        data = {"type": "screen_frame", "from_device_id": ..., "frame": base64_str}

        Передаём в ScreenShareManager для декодирования,
        он вызовет on_frame_received который мы подключили в _on_incoming_screen_control.
        """
        rtc.screen.handle_incoming_frame(data)

    def _on_incoming_screen_control(self, data: dict):
        """
        Управляющее сообщение демки (start/stop).
        data = {"type": "screen_control", "action": "start"/"stop", "from_device_id": ...}
        """
        action = data.get("action")
        from_id = data.get("from_device_id", "")
        print(f"[AppWindow] 🖥️ screen_control: action={action} from={from_id[:8] if from_id else '?'}")

        if action == "start":
            # Подключаем callback — каждый декодированный кадр идёт в main_screen
            def on_frame_decoded(numpy_frame):
                if hasattr(self, "main_screen") and self.main_screen:
                    handler = getattr(self.main_screen, "_on_screen_frame_numpy", None)
                    if callable(handler):
                        handler(numpy_frame)

            rtc.screen.start_receiving(on_frame_decoded)

            # Уведомляем main_screen что демка началась
            if hasattr(self, "main_screen") and self.main_screen:
                handler = getattr(self.main_screen, "_on_screen_share_started", None)
                if callable(handler):
                    handler(from_id)

        elif action == "stop":
            rtc.screen.stop_receiving()

            # Уведомляем main_screen что демка остановлена
            if hasattr(self, "main_screen") and self.main_screen:
                handler = getattr(self.main_screen, "_on_screen_share_stopped", None)
                if callable(handler):
                    handler(from_id)

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
        local_data = storage.load_local_state()
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

    def _submit(self):
        server = self.server_block["input"].text().strip()
        username = self.username_block["input"].text().strip()
        password = self.password_block["input"].text()
        device_name = self.device_block["input"].text().strip()
        invite_code = self.invite_block["input"].text().strip()

        if not server:
            return self._set_status("Укажи адрес сервера", True)
        if len(username) < 3:
            return self._set_status(
                "Имя пользователя должно быть не короче 3 символов", True
            )
        if len(password) < 8:
            return self._set_status(
                "Пароль должен быть не короче 8 символов", True
            )

        is_returning = bool(state.device_id) and state.username == username
        if not is_returning and not device_name:
            return self._set_status("Укажи название устройства", True)
        if self.mode == "register" and not invite_code:
            return self._set_status("Для регистрации нужен инвайт-код", True)

        state.server_url = server
        self.submit_button.setEnabled(False)

        if self.mode == "register":
            self._start_registration(server, username, password, device_name, invite_code)
        else:
            self._start_login(server, username, password, device_name)

    def _start_registration(self, server, username, password, device_name, invite_code):
        crypto.generate_new_keypair()
        storage.save_private_key(username, crypto.get_private_key_b64())

        payload = {
            "username": username, "password": password,
            "invite_code": invite_code, "device_name": device_name,
            "public_key": crypto.get_public_key_b64(),
            "fingerprint": crypto.get_fingerprint()
        }

        self.worker = RegisterWorker(server_url=server, payload=payload)
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
        self.submit_button.setEnabled(True)
        if success:
            state.device_id = response_data.get("device_id")
            state.username = self.username_block["input"].text().strip()
            state.device_name = self.device_block["input"].text().strip()
            storage.save_local_state({
                "server_url": state.server_url,
                "username": state.username,
                "device_name": state.device_name,
                "device_id": state.device_id
            })
            self.loading_screen.set_status(
                "Успех!", "Устройство успешно зарегистрировано.", "Готово"
            )
            QTimer.singleShot(
                1500, lambda: self.stack.setCurrentWidget(self.main_screen)
            )
            self._update_auth_animation_state()
        else:
            self.stack.setCurrentWidget(self.auth_screen)
            self._update_auth_animation_state()
            self._set_status(response_data, True)

    def _start_login(self, server, username, password, device_name):
        payload = {"username": username, "password": password}

        if state.device_id and state.username == username:
            payload["device_id"] = state.device_id
            priv_key = storage.get_private_key(username)
            if not priv_key:
                self.submit_button.setEnabled(True)
                return self._set_status(
                    "Ключи устройства утеряны. Необходима перерегистрация.", True
                )
            crypto.load_private_key(priv_key)
            status_title = "Проверка устройства"
            status_msg = "Авторизация существующего устройства в сети Max1m."
        else:
            crypto.generate_new_keypair()
            storage.save_private_key(username, crypto.get_private_key_b64())
            payload["device_name"] = device_name
            payload["public_key"] = crypto.get_public_key_b64()
            payload["fingerprint"] = crypto.get_fingerprint()
            status_title = "Регистрация устройства"
            status_msg = (
                f"Генерация ключей для нового устройства.\n"
                f"Ваш Fingerprint:\n{payload['fingerprint']}"
            )

        self.worker = LoginWorker(server_url=server, payload=payload)
        self.worker.finished.connect(self._on_login_finished)
        self.stack.setCurrentWidget(self.loading_screen)
        self._update_auth_animation_state()
        self.loading_screen.set_status(status_title, status_msg, "Авторизация...")
        self.worker.start()

    def _on_login_finished(self, success: bool, response_data: dict | str):
        self.submit_button.setEnabled(True)
        if success:
            state.token = response_data.get("access_token")
            new_device_id = response_data.get("device_id")
            username = self.username_block["input"].text().strip()
            device_name = self.device_block["input"].text().strip()
            state.username = username
            state.device_id = new_device_id

            storage.save_local_state({
                "server_url": state.server_url,
                "username": username,
                "device_name": device_name if device_name else state.device_name,
                "device_id": new_device_id
            })

            print("[UI] Запускаем WebSocketWorker...")
            self.ws_worker = WebSocketWorker(
                state.server_url, state.token, state.device_id
            )

            # ── Личные сообщения ────────────────────────────────────
            self.ws_worker.new_message_received.connect(
                self._on_incoming_message, Qt.QueuedConnection
            )
            self.ws_worker.connection_status.connect(
                self.main_screen.update_connection_status, Qt.QueuedConnection
            )

            # ── Групповые события ────────────────────────────────────
            self.ws_worker.group_message_received.connect(
                self._on_incoming_group_message, Qt.QueuedConnection
            )
            self.ws_worker.group_created_received.connect(
                self._on_group_created_event, Qt.QueuedConnection
            )
            self.ws_worker.group_invited_received.connect(
                self._on_group_invited_event, Qt.QueuedConnection
            )
            self.ws_worker.group_member_joined.connect(
                self._on_group_member_joined, Qt.QueuedConnection
            )
            self.ws_worker.group_member_left.connect(
                self._on_group_member_left, Qt.QueuedConnection
            )
            self.ws_worker.group_deleted_received.connect(
                self._on_group_deleted_event, Qt.QueuedConnection
            )

            # ── WebRTC сигналинг ─────────────────────────────────────
            self.ws_worker.webrtc_signal_received.connect(
                self._on_webrtc_signal, Qt.QueuedConnection
            )
            self.ws_worker.call_offer_received.connect(
                self._on_call_offer, Qt.QueuedConnection
            )
            self.ws_worker.call_accept_received.connect(
                self._on_call_accepted, Qt.QueuedConnection
            )
            self.ws_worker.call_ended_received.connect(
                self._on_call_ended, Qt.QueuedConnection
            )

            # ── Демонстрация экрана ──────────────────────────────────────
            self.ws_worker.screen_frame_received.connect(
                self._on_incoming_screen_frame, Qt.QueuedConnection
            )
            self.ws_worker.screen_control_received.connect(
                self._on_incoming_screen_control, Qt.QueuedConnection
            )

            self.ws_worker.start()

            print("[UI] Запрашиваем пропущенные сообщения (Sync)...")
            self.sync_worker = SyncMessagesWorker(state.server_url, state.token)
            self.sync_worker.finished.connect(self._on_sync_finished)
            self.sync_worker.start()

            from app.workers import SyncGroupMessagesWorker, FetchGroupsWorker
            self.groups_fetch_worker = FetchGroupsWorker(state.server_url, state.token)
            self.groups_fetch_worker.finished.connect(self._on_groups_fetched)
            self.groups_fetch_worker.start()

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

    def _on_group_deleted_event(self, data: dict):
        group_id = data.get("group_id")
        if hasattr(self, "main_screen"):
            self.main_screen.force_remove_group(group_id)

    def _on_sync_finished(self, success: bool, messages: list | str):
        if success:
            if isinstance(messages, list) and messages:
                print(f"[SYNC] Получено {len(messages)} пропущенных сообщений!")
                if hasattr(self, "main_screen") and self.main_screen is not None:
                    self.main_screen.process_sync_messages(messages)
            else:
                print("[SYNC] Пропущенных сообщений нет.")
        else:
            print(f"[SYNC] Ошибка синхронизации: {messages}")

    def _on_incoming_message(self, data: dict):
        print("\n[WS] 🔥 ВХОДЯЩИЙ ПАКЕТ:")
        print(data)
        if hasattr(self, "main_screen") and self.main_screen is not None:
            self.main_screen.process_incoming_message(data)

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

    def show_notification(self, title: str, message: str):
        print(f"[NOTIFY] Показываем: {title} - {message}")
        self.in_app_toast.show_notification(title, message)

    def _on_notification_clicked(self, sender_username: str):
        print(f"[NOTIFY] Клик: {sender_username}")

        if self.isMinimized():
            self.showNormal()

        self.raise_()
        self.activateWindow()

        if self.stack.currentWidget() != self.main_screen:
            self.stack.setCurrentWidget(self.main_screen)

        if hasattr(self.main_screen, "open_chat_by_username"):
            self.main_screen.open_chat_by_username(sender_username)

    def _on_incoming_group_message(self, data: dict):
        print(f"[WS GROUP] Групповое сообщение: {data.get('group_id')}")
        if hasattr(self, "main_screen") and self.main_screen is not None:
            self.main_screen.process_incoming_group_message(data)

    def _on_group_created_event(self, data: dict):
        print(f"[WS GROUP] Создана группа: {data.get('group_name')}")
        if hasattr(self, "main_screen") and self.main_screen is not None:
            self.main_screen.process_group_created_event(data)

    def _on_group_invited_event(self, data: dict):
        print(f"[WS GROUP] Приглашение в группу: {data.get('group_id')}")
        if hasattr(self, "main_screen") and self.main_screen is not None:
            self.main_screen.process_group_created_event(data)

    def _on_group_member_joined(self, data: dict):
        print(f"[WS GROUP] Новый участник: {data.get('new_member_device_id')}")
        group_id = data.get("group_id")
        if group_id and group_id in state.groups:
            new_device_id = data.get("new_member_device_id")
            members = state.groups[group_id].get("members", [])
            if not any(m.get("device_id") == new_device_id for m in members):
                members.append({"device_id": new_device_id, "role": "member"})

    def _on_group_member_left(self, data: dict):
        print(f"[WS GROUP] Участник вышел: {data.get('left_device_id')}")
        group_id = data.get("group_id")
        left_device_id = data.get("left_device_id")
        rotation_required = data.get("rotation_required", False)

        if not group_id or group_id not in state.groups:
            return

        members = state.groups[group_id].get("members", [])
        state.groups[group_id]["members"] = [
            m for m in members if m.get("device_id") != left_device_id
        ]

        state.groups[group_id].get("sender_keys", {}).pop(left_device_id, None)

        if rotation_required:
            from app.group_crypto import group_crypto
            new_key = group_crypto.generate_sender_key()
            state.groups[group_id]["my_sender_key"] = new_key
            print(f"[GROUP SECURITY] 🔄 SenderKey ротирован для группы {group_id}")

    def _on_groups_fetched(self, success: bool, data):
        if not success:
            print(f"[GROUPS] Ошибка загрузки групп: {data}")
            return

        if not isinstance(data, list):
            return

        print(f"[GROUPS] Загружено групп: {len(data)}")

        from app.group_crypto import group_crypto
        from app.workers import FetchGroupSenderKeysWorker, SyncGroupMessagesWorker
        from PySide6.QtCore import Qt

        if not hasattr(self, '_sender_key_workers'):
            self._sender_key_workers = []

        for group_info in data:
            group_id = group_info.get("id")
            if not group_id:
                continue

            if group_id not in state.groups:
                state.groups[group_id] = {
                    "name": group_info.get("name", ""),
                    "created_by_device_id": group_info.get("created_by_device_id", ""),
                    "members": group_info.get("members", []),
                    "my_sender_key": group_crypto.generate_sender_key(),
                    "sender_keys": {}
                }
            else:
                state.groups[group_id]["members"] = group_info.get("members", [])

            if hasattr(self, "main_screen"):
                existing = self.main_screen._get_group_item(group_id)
                if not existing:
                    self.main_screen._add_group_card(
                        group_id,
                        group_info.get("name", "")
                    )

            worker = FetchGroupSenderKeysWorker(
                state.server_url,
                state.token,
                group_id
            )

            worker.finished.connect(
                self._on_sender_keys_fetched,
                Qt.QueuedConnection
            )

            self._sender_key_workers.append(worker)
            worker.start()

        self.group_sync_worker = SyncGroupMessagesWorker(
            state.server_url,
            state.token
        )

        self.group_sync_worker.finished.connect(
            self._on_group_sync_finished,
            Qt.QueuedConnection
        )

        self.group_sync_worker.start()

    def _on_group_sync_finished(self, success: bool, messages):
        if not success:
            print(f"[GROUPS SYNC] Ошибка: {messages}")
            return

        if not isinstance(messages, list) or not messages:
            print("[GROUPS SYNC] Пропущенных групповых сообщений нет.")
            return

        print(f"[GROUPS SYNC] Получено {len(messages)} групповых сообщений.")
        if hasattr(self, "main_screen") and self.main_screen is not None:
            for msg in messages:
                self.main_screen.process_incoming_group_message(msg)

    def _on_sender_keys_fetched(self, success, data, group_id):
        if not success:
            print(f"[GROUPS] Ошибка загрузки SenderKeys для {group_id}: {data}")
            return

        if not isinstance(data, list):
            return

        print(f"[GROUPS] SenderKeys для {group_id}: {len(data)}")

        from app.group_crypto import group_crypto

        for entry in data:
            sender_device_id = entry.get("sender_device_id")
            encrypted_sender_key = entry.get("encrypted_sender_key")
            sender_key_signature = entry.get("sender_key_signature", "")

            if not sender_device_id or not encrypted_sender_key:
                continue

            if group_id not in state.groups:
                continue

            if sender_device_id in state.groups[group_id]["sender_keys"]:
                continue

            sender_pub_key = None
            if hasattr(self, "main_screen"):
                sender_pub_key = self.main_screen._find_public_key_by_device_id(
                    sender_device_id
                )

            if not sender_pub_key:
                continue

            decrypted_key = group_crypto.decrypt_sender_key(
                encrypted_sender_key,
                sender_key_signature,
                sender_pub_key
            )

            if decrypted_key:
                state.groups[group_id]["sender_keys"][sender_device_id] = decrypted_key
                print(f"[GROUPS] ✓ SenderKey: {sender_device_id} → {group_id}")

    def _on_rtc_state_change(self, peer_device_id: str, state: str):
        """Состояние WebRTC peer connection."""
        print(f"[AppWindow] 📡 RTC state: peer={peer_device_id}, state={state}")

        if not hasattr(self, "main_screen") or not self.main_screen:
            return

        handler = getattr(self.main_screen, "_update_rtc_state", None)
        if callable(handler):
            handler(peer_device_id, state)

    def _on_screen_share_state(self, active: bool, quality: str):
        if not hasattr(self, "main_screen") or not self.main_screen:
            return
        handler = getattr(self.main_screen, "_update_screen_share_ui", None)
        if callable(handler):
            handler(active, quality)

    def _on_webrtc_signal(self, data: dict):
        """Входящий зашифрованный WebRTC сигнал."""
        print(
            f"[AppWindow] 🔒 webrtc_signal "
            f"type={data.get('type')} from={data.get('from_device_id')} "
            f"to={data.get('to_device_id')}"
        )
        rtc.handle_encrypted_signal(data)

    def _on_call_accepted(self, data: dict):
        """Собеседник принял звонок."""
        print(f"[AppWindow] ✅ call_accept от {data.get('from_device_id')}")

        if hasattr(self, "main_screen") and self.main_screen:
            handler = getattr(self.main_screen, "_on_call_accepted", None)
            if callable(handler):
                handler(data)

    def _get_peer_public_key(self, device_id: str):
        """
        Жёсткий поиск публичного ключа устройства.
        Не зависит от main_screen helper'ов.
        """
        try:
            # 1. Ищем среди союзников
            for username, ally_data in state.allies.items():
                for dev in ally_data.get("devices", []):
                    if dev.get("device_id") == device_id:
                        pub = dev.get("public_key")
                        if pub:
                            print(f"[AppWindow] 🔑 pubkey найден для {device_id} через ally @{username}")
                            return pub

            # 2. Если текущий чат с этим устройством — дополнительная проверка
            if state.current_chat_type == "ally" and state.current_chat_device_id == device_id:
                ally = state.allies.get(state.current_chat_username)
                if ally:
                    for dev in ally.get("devices", []):
                        if dev.get("device_id") == device_id:
                            pub = dev.get("public_key")
                            if pub:
                                print(f"[AppWindow] 🔑 pubkey найден для current_chat {device_id}")
                                return pub

            print(f"[AppWindow] ❌ pubkey НЕ найден для {device_id}")
            return None

        except Exception as e:
            print(f"[AppWindow] ❌ _get_peer_public_key: {e}")
            return None

    def _on_call_ended(self, data: dict):
        """Удалённая сторона завершила звонок."""
        print(f"[AppWindow] 📴 call_ended от {data.get('from_device_id')}")

        if hasattr(self, "main_screen") and self.main_screen:
            handler = getattr(self.main_screen, "_on_remote_call_ended", None)
            if callable(handler):
                handler(data)


    def _send_rtc_signal(self, data: dict):
        """Отправка WebRTC сигналинга через WebSocketWorker."""
        if hasattr(self, "ws_worker") and self.ws_worker:
            self.ws_worker.send_signal(data)
        else:
            print(f"[AppWindow] ⚠️ ws_worker не готов для сигнала: {data.get('type')}")

    def _on_call_offer(self, data: dict):
        """Входящий вызов."""
        print(f"[AppWindow] 📞 call_offer от {data.get('from_device_id')}")

        if hasattr(self, "main_screen") and self.main_screen:
            handler = getattr(self.main_screen, "_on_incoming_call", None)
            if callable(handler):
                handler(data)
            else:
                print("[AppWindow] ⚠️ main_screen._on_incoming_call отсутствует")

    def closeEvent(self, event):
        try:
            if hasattr(self, "ws_worker") and self.ws_worker:
                self.ws_worker.stop()
                self.ws_worker.wait(2000)
        except Exception:
            pass
        try:
            rtc.shutdown()
        except Exception:
            pass
        super().closeEvent(event)