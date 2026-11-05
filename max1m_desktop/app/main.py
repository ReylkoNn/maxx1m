import sys

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont

from app.windows.app_window import AppWindow
from app.theme import generate_qss  # ← Уже правильно импортировано


def run():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("Max1m")

    font = QFont("Segoe UI", 10)
    app.setFont(font)

    # ========== ИСПРАВЛЕНИЕ ==========
    app.setStyleSheet(generate_qss())  # ← Было: APP_THEME
    # =================================

    window = AppWindow()
    window.show()

    sys.exit(app.exec())