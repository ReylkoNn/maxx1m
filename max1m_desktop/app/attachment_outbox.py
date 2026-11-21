"""Crash-recoverable queue for already encrypted attachment blobs.

The encrypted metadata is the commit marker; blobs have no plaintext key.
All mutations are serialized by the UI thread in a single application process.
"""
import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import asdict
from pathlib import Path

import nacl.secret
from app import outbox
from app.secure_storage import (
    SecureStorage,
    _atomic_replace_file,
    _fsync_directory,
    _restrict_dir_permissions,
    _safe_fsync_fd,
    _unlink_temp_quietly,
)

MAX_ATTACHMENTS = 50
MAX_TOTAL_BYTES = 128 * 1024 * 1024


def _dir_path(username, server_url, device_id):
    return outbox._directory_path(username, server_url, device_id) / "attachments"


def _dir(username, server_url, device_id):
    path = outbox._directory(username, server_url, device_id) / "attachments"
    path.mkdir(parents=True, exist_ok=True)
    _restrict_dir_permissions(path)
    return path


def _atomic_write(path, data):
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
            temp = f.name
            f.write(data)
            f.flush()
            _safe_fsync_fd(f.fileno())
        _atomic_replace_file(temp, path)
        _fsync_directory(path.parent)
    finally:
        _unlink_temp_quietly(temp)


def enqueue(context, blob, file_id, message_id, payload, history):
    directory = _dir(context.owner_username, context.server_url, context.owner_device_id)
    for identifier in (file_id, message_id):
        parsed = uuid.UUID(identifier)
        if parsed.version != 4 or str(parsed) != identifier:
            raise ValueError("Invalid attachment identifier")
    if not isinstance(blob, bytes) or not blob:
        raise ValueError("Invalid encrypted attachment")
    jobs = list(directory.glob("*.job"))
    total = sum(p.stat().st_size for p in directory.glob("*.blob"))
    if len(jobs) >= MAX_ATTACHMENTS or total + len(blob) > MAX_TOTAL_BYTES:
        raise ValueError("Очередь вложений заполнена")
    job_path = directory / f"{file_id}.job"
    blob_path = directory / f"{file_id}.blob"
    if job_path.exists() or blob_path.exists():
        raise ValueError("Conflicting attachment identifier")
    record = {"version": 1, "context": asdict(context), "file_id": file_id,
              "message_id": message_id, "payload": payload, "history": history,
              "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
    box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(context.owner_username))
    encrypted = box.encrypt(json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode())
    outbox._check_encrypted_record_size(encrypted)
    try:
        _atomic_write(blob_path, blob)
        _atomic_write(job_path, encrypted)
    except Exception:
        if not job_path.exists():
            blob_path.unlink(missing_ok=True)
        raise
    return job_path


def next_job(username, server_url, device_id, exclude=frozenset()):
    directory = _dir(username, server_url, device_id)
    files = sorted(p for p in directory.glob("*.job") if p.name not in exclude)
    if not files:
        return None
    path = files[0]
    box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(username))
    try:
        record = outbox._read_record(path, box)
        file_id = record["file_id"]
        parsed = uuid.UUID(file_id)
        if (record.get("version") != 1 or parsed.version != 4 or str(parsed) != file_id
                or path.name != f"{file_id}.job"):
            raise ValueError("Invalid attachment job")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, nacl.exceptions.CryptoError) as exc:
        raise outbox.QueueRecordError(path) from exc
    blob_path = directory / f"{file_id}.blob"
    return path, blob_path, record


def validate_blob(path, record):
    expected = record.get("size") if isinstance(record, dict) else None
    checksum = record.get("sha256") if isinstance(record, dict) else None
    if (type(expected) is not int or not 1 <= expected <= MAX_TOTAL_BYTES
            or not isinstance(checksum, str) or len(checksum) != 64
            or any(char not in '0123456789abcdef' for char in checksum)):
        raise ValueError("Invalid encrypted attachment metadata")
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while chunk := f.read(min(1024 * 1024, expected - size + 1)):
            size += len(chunk)
            if size > expected:
                raise ValueError("Corrupt encrypted attachment")
            digest.update(chunk)
    if size != expected or digest.hexdigest() != checksum:
        raise ValueError("Corrupt encrypted attachment")


# Clients cannot download larger blobs. Old oversized jobs remain on disk.
MAX_AUTHENTICATED_UPLOAD_BYTES = 21 * 1024 * 1024


def _authenticate_and_decrypt(path, size, checksum, key):
    import base64
    from app.media_identity import valid_file_key
    if (type(size) is not int or not 1 <= size <= MAX_AUTHENTICATED_UPLOAD_BYTES
            or not isinstance(checksum, str) or len(checksum) != 64
            or any(c not in '0123456789abcdef' for c in checksum)
            or not valid_file_key(key)):
        raise ValueError("Invalid attachment authentication metadata")
    with open(path, "rb") as stream:
        data = stream.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError("Corrupt encrypted attachment")
    # SecretBox verifies the nonce and Poly1305 tag before releasing plaintext.
    plaintext = nacl.secret.SecretBox(base64.b64decode(key, validate=True)).decrypt(data)
    return data, plaintext


def authenticated_snapshot(path, size, checksum, key):
    """Read, hash and authenticate the exact ciphertext to be uploaded.

    Runs in the upload worker, not the GUI. Plaintext exists only transiently
    in memory; no plaintext copy is written to disk.
    """
    data, _ = _authenticate_and_decrypt(path, size, checksum, key)
    return data


def pending_local_index(username, server_url, device_id):
    """Return (pending_msg_ids, {file_id: (blob_path, size, sha256)}) without creating dirs."""
    if not username or not server_url or not device_id:
        return set(), {}
    directory = _dir_path(username, server_url, device_id)
    if not directory.is_dir():
        return set(), {}
    files = sorted(directory.glob("*.job"))
    if not files:
        return set(), {}
    try:
        box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(username))
    except Exception:
        return set(), {}
    pending_msg_ids = set()
    pending_files = {}
    for path in files:
        try:
            record = outbox._read_record(path, box)
            file_id = record["file_id"]
            parsed = uuid.UUID(file_id)
            if (record.get("version") != 1 or parsed.version != 4 or str(parsed) != file_id
                    or path.name != f"{file_id}.job"):
                continue
            history = record.get("history")
            if isinstance(history, dict):
                msg_id = history.get("msg_id")
                if isinstance(msg_id, str) and msg_id:
                    pending_msg_ids.add(msg_id)
            blob_path = directory / f"{file_id}.blob"
            size = record.get("size")
            sha256 = record.get("sha256")
            if blob_path.is_file() and type(size) is int and isinstance(sha256, str):
                pending_files[file_id] = (blob_path, size, sha256)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, nacl.exceptions.CryptoError):
            continue
    return pending_msg_ids, pending_files


def load_pending_plaintext(username, server_url, device_id, file_id, secret_key):
    """Authenticate and decrypt a locally queued outgoing attachment before upload."""
    from app.media_identity import valid_file_id, valid_file_key
    if not valid_file_id(file_id) or not valid_file_key(secret_key):
        return None
    _, pending_files = pending_local_index(username, server_url, device_id)
    entry = pending_files.get(file_id)
    if entry is None:
        return None
    blob_path, size, checksum = entry
    try:
        _, plaintext = _authenticate_and_decrypt(blob_path, size, checksum, secret_key)
        return plaintext
    except (OSError, ValueError, TypeError, nacl.exceptions.CryptoError):
        return None


def pending_job_paths(username, server_url, device_id):
    """Snapshot queued .job files in the encrypted attachment outbox."""
    if not username or not server_url or not device_id:
        return []
    directory = _dir_path(username, server_url, device_id)
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*.job"))


def discard_jobs(paths, username, server_url, device_id) -> list[str]:
    """Explicit user cancellation of queued attachment jobs and their blobs.

    Returns canonical UUIDv4 file_ids removed so server reservations can be released.
    """
    directory = _dir(username, server_url, device_id)
    validated = [Path(p) for p in paths]
    if any(p.parent != directory or p.suffix != ".job" for p in validated):
        raise ValueError("Invalid attachment outbox cancellation")
    cancelled_file_ids: list[str] = []
    for job_path in validated:
        stem = job_path.stem
        try:
            parsed = uuid.UUID(stem)
            if parsed.version == 4 and str(parsed) == stem:
                cancelled_file_ids.append(stem)
        except ValueError:
            pass
        blob_path = directory / f"{stem}.blob"
        job_path.unlink(missing_ok=True)
        blob_path.unlink(missing_ok=True)
    if validated:
        _fsync_directory(directory)
    return cancelled_file_ids


def cancel_by_local_msg_id(username, server_url, device_id, msg_id: str) -> list[str]:
    """Cancel pending attachment upload jobs matching history.msg_id."""
    if not username or not server_url or not device_id or not isinstance(msg_id, str) or not msg_id:
        return []
    directory = _dir_path(username, server_url, device_id)
    if not directory.is_dir():
        return []
    files = sorted(directory.glob("*.job"))
    if not files:
        return []
    box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(username))
    cancelled_ids: list[str] = []
    for job_path in files:
        try:
            record = outbox._read_record(job_path, box)
            file_id = record.get("file_id")
            parsed = uuid.UUID(file_id)
            if (record.get("version") != 1 or parsed.version != 4 or str(parsed) != file_id
                    or job_path.name != f"{file_id}.job"):
                continue
        except (OSError, ValueError, TypeError, KeyError, AttributeError, nacl.exceptions.CryptoError):
            continue
        history = record.get("history")
        if isinstance(history, dict) and history.get("msg_id") == msg_id:
            blob_path = directory / f"{file_id}.blob"
            job_path.unlink(missing_ok=True)
            blob_path.unlink(missing_ok=True)
            cancelled_ids.append(file_id)
    if cancelled_ids:
        _fsync_directory(directory)
    return cancelled_ids


def cancel_by_ally(
    username,
    server_url,
    device_id,
    ally_username: str,
) -> tuple[list[str], list[str]]:
    """Cancel pending attachment upload jobs targeting ally_username.

    Returns (cancelled_file_ids, cancelled_msg_ids).
    """
    if not username or not server_url or not device_id or not isinstance(ally_username, str) or not ally_username:
        return [], []
    directory = _dir_path(username, server_url, device_id)
    if not directory.is_dir():
        return [], []
    files = sorted(directory.glob("*.job"))
    if not files:
        return [], []
    box = nacl.secret.SecretBox(SecureStorage._get_or_create_local_key(username))
    cancelled_ids: list[str] = []
    cancelled_msg_ids: list[str] = []
    for job_path in files:
        try:
            record = outbox._read_record(job_path, box)
            file_id = record.get("file_id")
            parsed = uuid.UUID(file_id)
            if (record.get("version") != 1 or parsed.version != 4 or str(parsed) != file_id
                    or job_path.name != f"{file_id}.job"):
                continue
        except (OSError, ValueError, TypeError, KeyError, AttributeError, nacl.exceptions.CryptoError):
            continue
        history = record.get("history")
        matched = (
            record.get("ally_username") == ally_username
            or (isinstance(history, dict) and history.get("ally_username") == ally_username)
        )
        if matched:
            blob_path = directory / f"{file_id}.blob"
            job_path.unlink(missing_ok=True)
            blob_path.unlink(missing_ok=True)
            cancelled_ids.append(file_id)
            if isinstance(history, dict):
                mid = history.get("msg_id")
                if isinstance(mid, str) and mid:
                    cancelled_msg_ids.append(mid)
    if cancelled_ids:
        _fsync_directory(directory)
    return cancelled_ids, cancelled_msg_ids


def finish(path, blob_path, username, server_url, device_id, file_id):
    directory = _dir(username, server_url, device_id)
    if path != directory / f"{file_id}.job" or blob_path != directory / f"{file_id}.blob":
        raise ValueError("Invalid attachment acknowledgement")
    path.unlink(missing_ok=True)  # message already in persistent outbox
    blob_path.unlink(missing_ok=True)
    _fsync_directory(directory)
