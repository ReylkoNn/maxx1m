"""Validate attachment metadata and sanitize filenames before influencing URLs, UI, or disk."""
import base64
import binascii
import os
import re
import uuid

MAX_DOCUMENT_BYTES = 20 * 1024 * 1024  # 20 MiB plaintext ceiling

_WIN_RESERVED_STEMS = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})

_DANGEROUS_EXTENSIONS = frozenset({
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".scr", ".msi", ".msp", ".com", ".hta", ".lnk",
    ".jar", ".reg", ".pif", ".cpl", ".dll", ".sys", ".sh", ".AppImage",
})

_UNSAFE_FILENAME_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]+')


def valid_file_id(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except (ValueError, AttributeError):
        return False


def valid_file_key(value):
    if not isinstance(value, str) or len(value) != 44:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
        return len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == value
    except (ValueError, binascii.Error):
        return False


def sanitize_attachment_filename(raw_name: str, fallback: str = "document.bin") -> str:
    """
    Strictly sanitize an untrusted filename:
    - Strip any POSIX/Windows path components (`../`, `C:\\`, UNC)
    - Strip control characters, NUL, and `|` (metadata separator)
    - Neutralize Windows reserved device stems (`CON.txt` -> `_CON.txt`)
    - Strip leading/trailing dots and spaces and cap length at 180 chars
    """
    if not isinstance(raw_name, str):
        return fallback
    normalized = raw_name.replace("\\", "/")
    base = normalized.rsplit("/", 1)[-1]
    cleaned = _UNSAFE_FILENAME_CHARS_RE.sub("_", base).strip(" ._")
    if not cleaned:
        return fallback

    stem, dot, ext = cleaned.rpartition(".")
    if not dot:
        stem, ext = cleaned, ""
    if stem.upper() in _WIN_RESERVED_STEMS:
        stem = f"_{stem}"
    if ext:
        ext = ext[:32]
        max_stem = max(1, 180 - 1 - len(ext))
        cleaned = f"{stem[:max_stem]}.{ext}"
    else:
        cleaned = stem[:180]
    return cleaned or fallback


def is_dangerous_executable_extension(filename: str) -> bool:
    if not isinstance(filename, str) or "." not in filename:
        return False
    lower = filename.strip(" .").lower()
    return any(lower.endswith(ext.lower()) for ext in _DANGEROUS_EXTENSIONS)


def format_file_size(size_bytes: int) -> str:
    try:
        n = max(0, int(size_bytes))
    except (TypeError, ValueError):
        return "0 Б"
    if n < 1024:
        return f"{n} Б"
    if n < 1024 * 1024:
        return f"{n / 1024.0:.1f} КБ"
    return f"{n / (1024.0 * 1024.0):.2f} МБ"


def build_file_meta(file_id: str, secret_key: str, filename: str, size_bytes: int, caption: str = "") -> str:
    if not valid_file_id(file_id) or not valid_file_key(secret_key):
        raise ValueError("Invalid file_id or secret_key")
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or not (0 <= size_bytes <= MAX_DOCUMENT_BYTES):
        raise ValueError("Invalid document size")
    safe_name = sanitize_attachment_filename(filename)
    safe_cap = caption if isinstance(caption, str) else ""
    return f"[FILE_META]|{file_id}|{secret_key}|{safe_name}|{size_bytes}|{safe_cap}"


def parse_file_meta(raw_text: str) -> dict | None:
    if not isinstance(raw_text, str) or not raw_text.startswith("[FILE_META]|"):
        return None
    parts = raw_text.split("|", 5)
    if len(parts) < 5:
        return None
    file_id, secret_key, raw_name, size_str = parts[1], parts[2], parts[3], parts[4]
    caption = parts[5] if len(parts) >= 6 else ""
    if not valid_file_id(file_id) or not valid_file_key(secret_key):
        return None
    if not size_str.isdigit():
        return None
    size_bytes = int(size_str)
    if not (0 <= size_bytes <= MAX_DOCUMENT_BYTES) or len(caption) > 8192 or len(raw_name) > 255:
        return None
    safe_name = sanitize_attachment_filename(raw_name)
    return {
        "file_id": file_id,
        "secret_key": secret_key,
        "filename": safe_name,
        "size_bytes": size_bytes,
        "caption": caption,
    }
