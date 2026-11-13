"""Encrypted, bounded persistent queue for idempotent personal sends.

All methods are called from the Qt main thread. Files contain only encrypted
network envelopes; account, server and device queues are isolated.
"""
import hashlib
import json
import os
import tempfile
import time
import uuid
from pathlib import Path

import nacl.secret
from app.secure_storage import (
    SecureStorage,
    _atomic_replace_file,
    _fsync_directory,
    _restrict_dir_permissions,
    _safe_fsync_fd,
    _unlink_temp_quietly,
)

MAX_QUEUED_MESSAGES = 1000
MAX_ENCRYPTED_RECORD_BYTES = 8 * 1024 * 1024
ALLOWED_RECORD_FIELDS = frozenset({
    "receiver_device_id",
    "encrypted_blob",
    "signature",
    "client_message_id",
    "_local_history",
    "_send_attempted",
})


class QueueRecordError(ValueError):
    """One unreadable record; its path is retained for safe skipping."""
    def __init__(self, path):
        self.path = path
        super().__init__("Cannot read queued record")


def _read_record(path, box):
    with path.open("rb") as f:
        data = f.read(MAX_ENCRYPTED_RECORD_BYTES + 1)
    if len(data) > MAX_ENCRYPTED_RECORD_BYTES:
        raise ValueError("Queued record is too large")
    try:
        record = json.loads(box.decrypt(data).decode())
    except (RecursionError, OverflowError) as exc:
        raise ValueError("Invalid queued record") from exc
    if not isinstance(record, dict):
        raise ValueError("Invalid queued record")
    return record


def _check_encrypted_record_size(encrypted):
    if len(encrypted) > MAX_ENCRYPTED_RECORD_BYTES:
        raise ValueError("Queued record is too large")


def _directory_path(username: str, server_url: str, device_id: str) -> Path:
    if not username or not server_url or not device_id:
        raise ValueError("Missing outbox identity")
    context = json.dumps([server_url.rstrip('/'), device_id], separators=(",", ":"))
    name = hashlib.sha256(context.encode()).hexdigest()
    return SecureStorage._get_user_dir(username) / "outbox" / name


def _directory(username: str, server_url: str, device_id: str) -> Path:
    path = _directory_path(username, server_url, device_id)
    path.mkdir(parents=True, exist_ok=True)
    _restrict_dir_permissions(path.parent)
    _restrict_dir_permissions(path)
    return path


def enqueue(username: str, server_url: str, device_id: str, payload: dict, local_history: dict = None,
            message_id: str = None) -> str:
    directory = _directory(username, server_url, device_id)
    message_id = message_id or str(uuid.uuid4())
    parsed = uuid.UUID(message_id)
    if parsed.version != 4 or str(parsed) != message_id:
        raise ValueError("Invalid outbox identifier")
    record = {**payload, "client_message_id": message_id}
    if local_history is not None:
        record["_local_history"] = local_history
    box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(username))
    files = list(directory.glob("*.enc"))
    existing = [p for p in files if p.name.endswith(f"_{message_id}.enc")]
    if existing:
        if len(existing) != 1 or _read_record(existing[0], box) != record:
            raise ValueError("Conflicting queued message")
        return message_id
    if len(files) >= MAX_QUEUED_MESSAGES:
        raise ValueError("Очередь исходящих сообщений заполнена")
    encrypted = box.encrypt(json.dumps(record, separators=(",", ":")).encode())
    _check_encrypted_record_size(encrypted)
    path = directory / f"{time.time_ns():020d}_{message_id}.enc"
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as output:
            temp_name = output.name
            output.write(encrypted)
            output.flush()
            _safe_fsync_fd(output.fileno())
        _atomic_replace_file(temp_name, path)
        _fsync_directory(directory)
    finally:
        _unlink_temp_quietly(temp_name)
    return message_id


def next_message(username: str, server_url: str, device_id: str, exclude=frozenset()):
    directory = _directory(username, server_url, device_id)
    files = sorted(path for path in directory.glob("*.enc") if path.name not in exclude)
    if not files:
        return None
    path = files[0]
    box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(username))
    try:
        payload = _read_record(path, box)
        parsed_id = uuid.UUID(payload["client_message_id"])
        if parsed_id.version != 4 or str(parsed_id) != payload["client_message_id"]:
            raise ValueError("Invalid outbox identifier")
        if not path.name.endswith(f"_{parsed_id}.enc"):
            raise ValueError("Invalid outbox record")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, nacl.exceptions.CryptoError) as exc:
        raise QueueRecordError(path) from exc
    return path, payload


def acknowledge(path: Path, username: str, server_url: str, device_id: str, message_id: str):
    directory = _directory(username, server_url, device_id)
    if path.parent != directory or not path.name.endswith(f"_{message_id}.enc"):
        raise ValueError("Invalid outbox acknowledgement")
    path.unlink(missing_ok=True)
    _fsync_directory(directory)


def pending_paths(username: str, server_url: str, device_id: str):
    """Snapshot queue files; pending attachment uploads are a separate queue."""
    return sorted(_directory(username, server_url, device_id).glob("*.enc"))


def pending_local_msg_ids(username: str, server_url: str, device_id: str) -> set[str]:
    """Return local msg_id values still waiting in the encrypted send outbox."""
    if not username or not server_url or not device_id:
        return set()
    directory = _directory_path(username, server_url, device_id)
    if not directory.is_dir():
        return set()
    files = sorted(directory.glob("*.enc"))
    if not files:
        return set()
    try:
        box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(username))
    except Exception:
        return set()
    pending = set()
    for path in files:
        try:
            record = _read_record(path, box)
            parsed_id = uuid.UUID(record["client_message_id"])
            if parsed_id.version != 4 or str(parsed_id) != record["client_message_id"]:
                continue
            if not path.name.endswith(f"_{parsed_id}.enc"):
                continue
            history = record.get("_local_history")
            if isinstance(history, dict):
                msg_id = history.get("msg_id")
                if isinstance(msg_id, str) and msg_id:
                    pending.add(msg_id)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, nacl.exceptions.CryptoError):
            continue
    return pending


def mark_send_attempted(path: Path, username: str, server_url: str, device_id: str) -> None:
    """Persist that network transmission is about to start for this queued record."""
    directory = _directory(username, server_url, device_id)
    if path.parent != directory or path.suffix != ".enc" or not path.exists():
        return
    box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(username))
    record = _read_record(path, box)
    if record.get("_send_attempted") is True:
        return
    updated = {**record, "_send_attempted": True}
    encrypted = box.encrypt(json.dumps(updated, separators=(",", ":")).encode())
    _check_encrypted_record_size(encrypted)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as output:
            temp_name = output.name
            output.write(encrypted)
            output.flush()
            _safe_fsync_fd(output.fileno())
        _atomic_replace_file(temp_name, path)
        _fsync_directory(directory)
    finally:
        _unlink_temp_quietly(temp_name)


def cancel_by_local_msg_id(
    username: str, server_url: str, device_id: str, msg_id: str
) -> tuple[list[str], bool]:
    """Remove pending outbox records matching _local_history.msg_id.

    Returns (removed_filenames, any_send_attempted).
    """
    if not username or not server_url or not device_id or not isinstance(msg_id, str) or not msg_id:
        return [], False
    directory = _directory_path(username, server_url, device_id)
    if not directory.is_dir():
        return [], False
    files = sorted(directory.glob("*.enc"))
    if not files:
        return [], False
    box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(username))
    removed_names: list[str] = []
    any_attempted = False
    for path in files:
        try:
            record = _read_record(path, box)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, nacl.exceptions.CryptoError):
            continue
        history = record.get("_local_history")
        if isinstance(history, dict) and history.get("msg_id") == msg_id:
            if record.get("_send_attempted") is True:
                any_attempted = True
            path.unlink(missing_ok=True)
            removed_names.append(path.name)
    if removed_names:
        _fsync_directory(directory)
    return removed_names, any_attempted


def cancel_by_ally(
    username: str,
    server_url: str,
    device_id: str,
    ally_username: str,
    ally_device_ids: set[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Cancel pending outbox records targeting ally_username (or its known device IDs).

    Returns (removed_filenames, cancelled_msg_ids). Corrupt/unreadable records
    are left untouched.
    """
    if not username or not server_url or not device_id or not isinstance(ally_username, str) or not ally_username:
        return [], []
    directory = _directory_path(username, server_url, device_id)
    if not directory.is_dir():
        return [], []
    files = sorted(directory.glob("*.enc"))
    if not files:
        return [], []
    box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(username))
    known_devs = set(ally_device_ids) if ally_device_ids else set()
    removed_names: list[str] = []
    cancelled_msg_ids: list[str] = []
    for path in files:
        try:
            record = _read_record(path, box)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, nacl.exceptions.CryptoError):
            continue
        history = record.get("_local_history")
        matched = False
        msg_id = None
        if isinstance(history, dict):
            if history.get("ally_username") == ally_username:
                matched = True
            mid = history.get("msg_id")
            if isinstance(mid, str) and mid:
                msg_id = mid
        if not matched and known_devs and record.get("receiver_device_id") in known_devs:
            matched = True
        if matched:
            path.unlink(missing_ok=True)
            removed_names.append(path.name)
            if msg_id:
                cancelled_msg_ids.append(msg_id)
    if removed_names:
        _fsync_directory(directory)
    return removed_names, cancelled_msg_ids


def discard_paths(paths, username: str, server_url: str, device_id: str):
    """Explicit user cancellation; never delete files outside this queue."""
    directory = _directory(username, server_url, device_id)
    validated = [Path(path) for path in paths]
    if any(path.parent != directory or path.suffix != ".enc" for path in validated):
        raise ValueError("Invalid outbox cancellation")
    for path in validated:
        path.unlink(missing_ok=True)
    if validated:
        _fsync_directory(directory)


def prepare_network_payload(username: str, record: dict) -> dict:
    """Restore queued history before transmission; never send local plaintext."""
    if not isinstance(record, dict):
        raise ValueError("Invalid queued record")
    if set(record) - ALLOWED_RECORD_FIELDS:
        # Do not transmit extra local metadata or mutate history for an
        # incompatible record. Keep the encrypted record for recovery.
        raise ValueError("Unsupported queued record fields")
    payload = dict(record)
    payload.pop("_send_attempted", None)
    history = payload.pop("_local_history", None)
    if history is not None:
        if not isinstance(history, dict):
            raise ValueError("Invalid queued history")
        extra_hist = {}
        raw_exp = history.get("expires_at")
        if raw_exp is not None:
            if isinstance(raw_exp, bool) or not isinstance(raw_exp, (int, float)) or raw_exp <= 0:
                raise ValueError("Invalid queued expires_at")
            extra_hist["expires_at"] = int(raw_exp)
        SecureStorage.save_message(
            username, history["ally_username"], history["text"],
            is_mine=True, timestamp=history.get("timestamp"),
            msg_id=history["msg_id"], is_read=False,
            reply_to_msg_id=history.get("reply_to_msg_id"),
            reply_to_text=history.get("reply_to_text"),
            reply_to_sender=history.get("reply_to_sender"),
            **extra_hist,
        )
    return payload
