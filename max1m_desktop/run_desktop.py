import sys
import ctypes
import multiprocessing

# --= PRODUCTION NOTIFICATION FIX =--
# Даем приложению уникальный AppUserModelID (AUMID),
# чтобы Windows доверяла нашим уведомлениям.
if sys.platform == "win32":
    APP_ID = "Max1m.Secure.Messenger.v1"
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
        print(f"[AUMID] Установлен AppUserModelID: {APP_ID}")
    except Exception as e:
        print(f"[AUMID] Не удалось установить AppUserModelID: {e}")


# --= END FIX =--


def main():
    """Основная точка входа в приложение"""

    # ── ВАЖНО: GUARD ДЛЯ MULTIPROCESSING НА WINDOWS ──
    multiprocessing.freeze_support()
    # ─────────────────────────────────────────────────

    from PySide6.QtWidgets import QApplication
    from app.windows.app_window import AppWindow
    from app.theme import generate_qss, set_theme, ACTIVE_THEME
    from app.config import START_MODE

    app = QApplication(sys.argv)

    # Устанавливаем тему и стиль
    set_theme(ACTIVE_THEME)
    app.setStyleSheet(generate_qss(ACTIVE_THEME))

    # Создаем и показываем главное окно
    window = AppWindow()

    # Устанавливаем режим окна при запуске
    if START_MODE == "maximized":
        window.showMaximized()
    else:
        window.show()

    # Запускаем event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    # Если процесс запущен мультипроцессингом (например, для screen share),
    # выполнение не дойдёт до main(), а перехватится внутри freeze_support()
    main()