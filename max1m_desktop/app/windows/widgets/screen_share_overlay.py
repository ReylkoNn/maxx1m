"""
Screen Share Overlay + Viewer — Discord-like
"""

from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGraphicsDropShadowEffect
)
from PySide6.QtCore import Qt, Signal, QPropertyAnimation, QEasingCurve, QRectF
from PySide6.QtGui import QScreen, QGuiApplication, QPixmap, QColor, QPainter, QFontMetrics


class MonitorPreviewCard(QFrame):
    selected = Signal(int)

    def __init__(self, screen: QScreen, index: int, parent=None):
        super().__init__(parent)
        self.screen = screen
        self.index = index
        self.setObjectName("MonitorPreviewCard")
        self.setFixedSize(280, 180)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.NoFocus)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(30)
        shadow.setColor(QColor(0, 0, 0, 120))
        shadow.setOffset(0, 8)
        self.setGraphicsEffect(shadow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.preview_label = QLabel()
        self.preview_label.setObjectName("MonitorPreviewImage")
        self.preview_label.setAlignment(Qt.AlignCenter)
        self.preview_label.setFixedHeight(120)
        self._generate_preview()

        self.name_label = QLabel(screen.name())
        self.name_label.setObjectName("MonitorPreviewName")
        self.name_label.setAlignment(Qt.AlignCenter)

        geo = screen.geometry()
        self.res_label = QLabel(f"{geo.width()}x{geo.height()}")
        self.res_label.setObjectName("MonitorPreviewRes")
        self.res_label.setAlignment(Qt.AlignCenter)

        layout.addWidget(self.preview_label)
        layout.addWidget(self.name_label)
        layout.addWidget(self.res_label)

    def _generate_preview(self):
        try:
            pixmap = self.screen.grabWindow(0)
            if not pixmap.isNull():
                scaled = pixmap.scaled(256, 120, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.preview_label.setPixmap(scaled)
            else:
                self.preview_label.setText("No signal")
        except Exception as e:
            self.preview_label.setText("Error")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.selected.emit(self.index)
        super().mousePressEvent(event)

    def enterEvent(self, event):
        self.setProperty("hovered", True)
        self.style().unpolish(self)
        self.style().polish(self)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setProperty("hovered", False)
        self.style().unpolish(self)
        self.style().polish(self)
        super().leaveEvent(event)


class ScreenShareOverlay(QFrame):
    monitor_selected = Signal(int)
    cancelled = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ScreenShareOverlay")
        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool
        )
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setFocusPolicy(Qt.NoFocus)

        self._cards = []
        self.container = QFrame()
        self.container.setObjectName("ScreenShareOverlayContainer")

        layout = QVBoxLayout(self.container)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)

        title = QLabel("CHOOSE SCREEN")
        title.setObjectName("ScreenShareOverlayTitle")
        title.setAlignment(Qt.AlignCenter)

        self.monitors_layout = QHBoxLayout()
        self.monitors_layout.setSpacing(20)
        self.monitors_layout.setAlignment(Qt.AlignCenter)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("ScreenShareOverlayCancelBtn")
        cancel_btn.setFixedSize(140, 44)
        cancel_btn.setCursor(Qt.PointingHandCursor)
        cancel_btn.setFocusPolicy(Qt.NoFocus)
        cancel_btn.clicked.connect(self._on_cancel)

        layout.addWidget(title)
        layout.addLayout(self.monitors_layout)
        layout.addSpacing(20)
        layout.addWidget(cancel_btn, alignment=Qt.AlignCenter)

        self.fade_anim = QPropertyAnimation(self, b"windowOpacity")
        self.fade_anim.setDuration(200)
        self.fade_anim.setEasingCurve(QEasingCurve.OutCubic)

    def show_overlay(self):
        while self.monitors_layout.count():
            item = self.monitors_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        screens = QGuiApplication.screens()

        for i, screen in enumerate(screens):
            card = MonitorPreviewCard(screen, i)
            card.selected.connect(self._on_monitor_selected)
            self.monitors_layout.addWidget(card)

        if self.parent():
            parent_geo = self.parent().geometry()
            self.setGeometry(parent_geo)
        else:
            screen = QGuiApplication.primaryScreen().geometry()
            self.setGeometry(screen)

        self.container.setParent(self)
        self.container.setGeometry(self.rect().adjusted(40, 40, -40, -40))
        self.container.show()

        self.setWindowOpacity(0.0)
        self.show()
        self.raise_()
        self.activateWindow()

        self.fade_anim.setStartValue(0.0)
        self.fade_anim.setEndValue(1.0)
        self.fade_anim.start()

    def _on_monitor_selected(self, index: int):
        self.monitor_selected.emit(index)
        self._hide()

    def _on_cancel(self):
        self.cancelled.emit()
        self._hide()

    def _hide(self):
        try:
            self.fade_anim.finished.disconnect()
        except (RuntimeError, TypeError):
            pass
        self.fade_anim.setStartValue(self.windowOpacity())
        self.fade_anim.setEndValue(0.0)
        self.fade_anim.finished.connect(self._on_hide_finished)
        self.fade_anim.start()

    def _on_hide_finished(self):
        try:
            self.fade_anim.finished.disconnect(self._on_hide_finished)
        except (RuntimeError, TypeError):
            pass
        self.hide()
        self.container.hide()
        self._cards.clear()


class ScreenShareViewer(QFrame):
    close_requested = Signal()
    maximize_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ScreenShareViewer")
        self.setFocusPolicy(Qt.StrongFocus)
        self._pixmap = None
        self._sender_id = ""
        self._is_maximized = False

        self._fps_label = QLabel(self)
        self._fps_label.setObjectName("ScreenShareFpsLabel")
        self._fps_label.setFixedHeight(20)
        self._fps_label.hide()

        self._close_btn = QPushButton("X", self)
        self._close_btn.setObjectName("ScreenShareCloseBtn")
        self._close_btn.setFixedSize(28, 28)
        self._close_btn.setCursor(Qt.PointingHandCursor)
        self._close_btn.setFocusPolicy(Qt.NoFocus)
        self._close_btn.clicked.connect(self.close_requested.emit)
        self._close_btn.hide()

        self._maximize_btn = QPushButton("[ ]", self)
        self._maximize_btn.setObjectName("ScreenShareMaxBtn")
        self._maximize_btn.setFixedSize(28, 28)
        self._maximize_btn.setCursor(Qt.PointingHandCursor)
        self._maximize_btn.setFocusPolicy(Qt.NoFocus)
        self._maximize_btn.clicked.connect(self._toggle_maximize)
        self._maximize_btn.hide()
        self.hide()

    def start_viewing(self, sender_device_id: str):
        self._sender_id = sender_device_id
        self._pixmap = None
        self.show()
        self.raise_()
        self.update()

    def stop_viewing(self):
        self._pixmap = None
        self._sender_id = ""
        self._is_maximized = False
        self.hide()
        self.update()

    def set_frame(self, pixmap: QPixmap):
        if pixmap and not pixmap.isNull():
            self._pixmap = pixmap
            self.update()

    def set_fps(self, fps: float):
        self._fps_label.setText(f"{fps:.0f} FPS")
        self._fps_label.show()

    def _toggle_maximize(self):
        self._is_maximized = not self._is_maximized
        self.maximize_requested.emit()

    def enterEvent(self, event):
        self._close_btn.show()
        self._maximize_btn.show()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._close_btn.hide()
        self._maximize_btn.hide()
        super().leaveEvent(event)

    def paintEvent(self, event):
        from app.theme import get_theme
        t = get_theme()
        if not self._pixmap or self._pixmap.isNull():
            painter = QPainter(self)
            painter.fillRect(self.rect(), QColor(t.get("bg_panel", "#111317")))
            painter.setPen(QColor(t.get("text_dim", "#777e8e")))
            painter.drawText(self.rect(), Qt.AlignCenter, "Waiting for video...")
            painter.end()
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
        painter.fillRect(self.rect(), QColor(t.get("bg_panel", "#111317")))

        scaled = self._pixmap.scaled(
            self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        x = (self.width() - scaled.width()) // 2
        y = (self.height() - scaled.height()) // 2
        painter.drawPixmap(x, y, scaled)

        if self._sender_id:
            font = painter.font()
            font.setPixelSize(12)
            font.setBold(True)
            painter.setFont(font)

            label = f"Screen share from {self._sender_id[:8]}..."
            fm = painter.fontMetrics()
            text_w = fm.horizontalAdvance(label)
            text_h = fm.height()

            pill_w = text_w + 24
            pill_h = text_h + 10
            pill_x = (self.width() - pill_w) // 2
            pill_y = 8

            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(0, 0, 0, 160))
            painter.drawRoundedRect(pill_x, pill_y, pill_w, pill_h, 8, 8)

            painter.setPen(QColor(t.get("text_main", "#f8fafb")))
            painter.drawText(
                QRectF(pill_x, pill_y, pill_w, pill_h),
                Qt.AlignCenter, label
            )

        painter.end()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._close_btn.move(self.width() - 36, 8)
        self._maximize_btn.move(self.width() - 68, 8)
        self._fps_label.move(8, self.height() - 28)
        self.update()
