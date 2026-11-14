import argparse
import ctypes
import multiprocessing
import os
import re
import sys


def _configure_instance_env_from_argv(argv: list[str]) -> tuple[str, list[str]]:
    """
    Parse `--instance <id>` / `--data-dir <path>` BEFORE importing `app.*`
    so two local instances can run side-by-side on one PC (each with its own
    isolated `~/.max1m_inst_<id>`, `desktop.lock`, and OS Keyring namespace)
    for testing calls, screen sharing, and groups through a tunnel or localhost.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--instance", default="", help="Instance slot (e.g. 1, 2) for multi-window local testing")
    parser.add_argument("--data-dir", default="", help="Custom isolated client data directory")
    known, remaining = parser.parse_known_args(argv[1:])

    inst = re.sub(r"[^A-Za-z0-9_-]", "", (known.instance or "").strip())[:32]
    if inst:
        os.environ["MAX1M_INSTANCE"] = inst
    if known.data_dir and known.data_dir.strip():
        os.environ["MAX1M_CLIENT_DATA_DIR"] = known.data_dir.strip()

    eff_inst = os.environ.get("MAX1M_INSTANCE", "").strip()
    return eff_inst, [argv[0], *remaining]


def main():
    """Основная точка входа в приложение"""
    # ── ВАЖНО: GUARD ДЛЯ MULTIPROCESSING НА WINDOWS ──
    multiprocessing.freeze_support()
    # ─────────────────────────────────────────────────

    eff_inst, qt_argv = _configure_instance_env_from_argv(sys.argv)

    if sys.platform == "win32":
        suffix = f".inst_{eff_inst}" if (eff_inst and eff_inst != "1") else ""
        app_id = f"Max1m.Secure.Messenger.v1{suffix}"
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
        except Exception:
            pass

    from PySide6.QtWidgets import QApplication, QMessageBox
    from app.instance_guard import InstanceAlreadyRunning, acquire_instance_lock
    from app.secure_storage import BASE_DIR

    app = QApplication(qt_argv)
    try:
        lock = acquire_instance_lock(BASE_DIR)
    except (InstanceAlreadyRunning, OSError):
        QMessageBox.warning(
            None,
            "Max1m уже запущен или хранилище недоступно",
            "Этот профиль уже открыт в другом окне.\n\n"
            "Совет: для запуска второго независимого окна на одном ПК запустите:\n"
            "Max1m.exe --instance 2   (или файл Запуск_2_окон_для_теста.bat)",
        )
        return 1

    try:
        from app.config import START_MODE
        from app.theme import ACTIVE_THEME, generate_qss, set_theme
        from app.windows.app_window import AppWindow

        set_theme(ACTIVE_THEME)
        app.setStyleSheet(generate_qss(ACTIVE_THEME))
        window = AppWindow()
        if eff_inst and eff_inst != "1":
            window.setWindowTitle(f"Max1m — Окно #{eff_inst}")
            if hasattr(window, "titlebar") and hasattr(window.titlebar, "title_label"):
                window.titlebar.title_label.setText(f"Max1m • Окно #{eff_inst}")
        if START_MODE == "maximized" and not (eff_inst and eff_inst != "1"):
            window.showMaximized()
        else:
            window.show()
        return app.exec()
    finally:
        lock.unlock()


if __name__ == "__main__":
    sys.exit(main())
