"""Privacy-conscious rotating diagnostics for the Max1m desktop client.

The file log intentionally records event categories, error types, and short
one-way identifiers only. It must never be used for message contents, tokens,
keys, signatures, or full device IDs.
"""
from __future__ import annotations

import faulthandler
import hashlib
import logging
import os
import re
import sys
from importlib import metadata
import threading
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path


_LOGGER_NAME = "max1m"
_MAX_LOG_BYTES = 2 * 1024 * 1024
_LOG_BACKUPS = 3
_MAX_CRASH_LOG_BYTES = 1024 * 1024
_logger = logging.getLogger(_LOGGER_NAME)
_lock = threading.Lock()
_initialized = False
_crash_stream = None


def _data_dir() -> Path:
    custom = os.environ.get("MAX1M_CLIENT_DATA_DIR", "").strip()
    if custom:
        return Path(custom).expanduser()
    instance = re.sub(r"[^A-Za-z0-9_-]", "", os.environ.get("MAX1M_INSTANCE", "").strip())[:32]
    if instance and instance != "1":
        return Path.home() / f".max1m_inst_{instance}"
    return Path.home() / ".max1m"


def log_directory() -> Path:
    """Return the per-profile diagnostics directory without creating it."""
    return _data_dir() / "logs"


def get_logger(component: str = "client") -> logging.Logger:
    """Return a child logger. `initialize_diagnostics` is called by run_desktop."""
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", str(component))[:80] or "client"
    return logging.getLogger(f"{_LOGGER_NAME}.{name}")


def safe_identifier_tag(value: object) -> str:
    """Return a stable short tag without placing the original identifier in logs."""
    if not isinstance(value, str) or not value:
        return "-"
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]


def safe_message_kind(value: object) -> str:
    """Keep only known protocol labels; never log arbitrary payload values."""
    if isinstance(value, str) and value in {
        "text", "image", "voice", "file", "delete_msg", "edit_msg", "pin_msg",
        "read_ack", "typing", "webrtc_signal", "dr_already_processed",
    }:
        return value
    return "other"


def _rotate_crash_log(path: Path) -> None:
    try:
        if path.exists() and path.stat().st_size > _MAX_CRASH_LOG_BYTES:
            previous = path.with_name(path.name + ".1")
            try:
                previous.unlink(missing_ok=True)
            except OSError:
                pass
            os.replace(path, previous)
    except OSError:
        pass


def _write_safe_traceback(exc_type, tb) -> None:
    """Record stack locations without exception messages or local variables."""
    try:
        name = getattr(exc_type, "__name__", "Exception")
        _logger.error("uncaught_exception type=%s", name)
        for frame in traceback.extract_tb(tb):
            _logger.error("uncaught_frame file=%s line=%d function=%s",
                          Path(frame.filename).name, frame.lineno, frame.name)
    except Exception:
        pass


def _sys_excepthook(exc_type, exc_value, tb) -> None:
    _write_safe_traceback(exc_type, tb)
    if exc_type is KeyboardInterrupt:
        sys.__excepthook__(exc_type, exc_value, tb)


def _thread_excepthook(args) -> None:
    _write_safe_traceback(args.exc_type, args.exc_traceback)


def initialize_diagnostics() -> logging.Logger:
    """Configure bounded file logging and native-crash trace capture once."""
    global _initialized, _crash_stream
    with _lock:
        if _initialized:
            return _logger
        try:
            directory = log_directory()
            directory.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                try:
                    os.chmod(directory, 0o700)
                except OSError:
                    pass

            handler = next(
                (item for item in _logger.handlers if getattr(item, "_max1m_diagnostics", False)),
                None,
            )
            if handler is None:
                handler = RotatingFileHandler(
                    directory / "client.log",
                    maxBytes=_MAX_LOG_BYTES,
                    backupCount=_LOG_BACKUPS,
                    encoding="utf-8",
                    delay=True,
                )
                handler._max1m_diagnostics = True
                handler.setFormatter(logging.Formatter(
                    "%(asctime)s %(levelname)s %(name)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S",
                ))
                _logger.addHandler(handler)
            _logger.setLevel(logging.INFO)
            _logger.propagate = False
            crash_path = directory / "crash.log"
            _rotate_crash_log(crash_path)
            _crash_stream = crash_path.open("ab", buffering=0)
            if faulthandler.is_enabled():
                faulthandler.disable()
            faulthandler.enable(file=_crash_stream, all_threads=True)

            sys.excepthook = _sys_excepthook
            if hasattr(threading, "excepthook"):
                threading.excepthook = _thread_excepthook
            try:
                pyside_version = metadata.version("PySide6")
            except metadata.PackageNotFoundError:
                pyside_version = "unknown"
            _initialized = True
            _logger.info("diagnostics.ready python=%s pyside6=%s platform=%s",
                         sys.version.split()[0], pyside_version, sys.platform)
        except Exception as exc:
            # Diagnostics must never prevent the chat client from starting.
            try:
                logging.basicConfig(level=logging.INFO)
                _logger.warning("diagnostics.setup_failed type=%s", type(exc).__name__)
            except Exception:
                pass
            _initialized = True
        return _logger
