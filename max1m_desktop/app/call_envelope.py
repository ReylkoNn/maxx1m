"""Authenticated, call-bound control and signaling envelopes.

This is a defense for the existing WebRTC signaling, not a Signal protocol
implementation. The peer's public key must already be authenticated separately.
"""
import json
import os
import tempfile
import time
import uuid

import nacl.secret
from pathlib import Path
from app.secure_storage import SecureStorage, _fsync_directory, _restrict_file_permissions

MAX_SKEW_SECONDS = 300
MAX_REPLAY_ENTRIES = 4096
MAX_REPLAY_FILE_BYTES = 1024 * 1024
MAX_CALL_CIPHERTEXT_CHARS = 128 * 1024
MAX_CALL_SIGNATURE_CHARS = 512
MAX_CALL_JSON_DEPTH = 16
KINDS = frozenset({"call_offer", "call_accept", "call_ended", "webrtc_signal"})


def _reject_non_finite_json(constant: str):
    raise ValueError(f"Unsupported JSON constant: {constant}")


def _depth_ok(obj, max_depth: int = MAX_CALL_JSON_DEPTH) -> bool:
    stack = [(obj, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            return False
        if isinstance(current, dict):
            for k, v in current.items():
                if not isinstance(k, str) or len(k) > 128:
                    return False
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(current, list):
            for item in current:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))
    return True


def _uuid4(value):
    try:
        parsed = uuid.UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except (ValueError, TypeError, AttributeError):
        return False


def seal(crypto, kind, sender, recipient, call_id, public_key, content=None, now=None):
    if kind not in KINDS or not sender or not recipient or not _uuid4(call_id):
        raise ValueError("Invalid call envelope")
    inner = {"v": 1, "kind": kind, "sender": sender, "recipient": recipient,
             "call_id": call_id, "event_id": str(uuid.uuid4()),
             "time": int(time.time() if now is None else now), "content": content}
    encrypted = crypto.encrypt_message(json.dumps(inner, separators=(",", ":")), public_key)
    return {"type": kind, "to_device_id": recipient,
            "encrypted_call": encrypted["encrypted_blob"], "call_signature": encrypted["signature"]}


def open_envelope(crypto, envelope, recipient, public_key, now=None):
    if not isinstance(envelope, dict) or not recipient or not public_key:
        raise ValueError("Invalid call envelope")
    sender, kind = envelope.get("from_device_id"), envelope.get("type")
    enc, sig = envelope.get("encrypted_call"), envelope.get("call_signature")
    if (not isinstance(sender, str) or not 0 < len(sender) <= 64
            or not isinstance(kind, str) or kind not in KINDS
            or not isinstance(enc, str) or not 0 < len(enc) <= MAX_CALL_CIPHERTEXT_CHARS
            or not isinstance(sig, str) or not 0 < len(sig) <= MAX_CALL_SIGNATURE_CHARS):
        raise ValueError("Invalid call envelope")
    if not crypto.verify_signature(enc, sig, public_key):
        raise ValueError("Invalid call signature")
    try:
        inner = json.loads(
            crypto.decrypt_message(enc, public_key),
            parse_constant=_reject_non_finite_json,
        )
    except Exception as exc:
        raise ValueError("Invalid call ciphertext") from exc
    if not _depth_ok(inner, MAX_CALL_JSON_DEPTH):
        raise ValueError("Call envelope exceeds nesting depth")
    now = time.time() if now is None else now
    if (not isinstance(inner, dict) or inner.get("v") != 1 or inner.get("kind") != kind
            or inner.get("sender") != sender or inner.get("recipient") != recipient
            or not _uuid4(inner.get("call_id")) or not _uuid4(inner.get("event_id"))
            or type(inner.get("time")) is not int or abs(now - inner["time"]) > MAX_SKEW_SECONDS):
        raise ValueError("Invalid or expired call envelope")
    return inner


def remember_offer(username, server_url, device_id, sender, call_id, now=None):
    """Persist replay IDs before ringing, failing closed on storage errors.

    Prune only entries outside the full acceptance window; never evict a live
    entry to make space, because that would permit replay while still valid.
    """
    from app.outbox import _directory
    directory = _directory(username, server_url, device_id)
    path = directory.parent / (directory.name + "-call-replay.enc")
    key = SecureStorage._get_or_create_local_key(username)
    box = nacl.secret.SecretBox(key)
    now = int(time.time() if now is None else now)
    if not isinstance(sender, str) or not 0 < len(sender) <= 64 or not _uuid4(call_id):
        raise ValueError("Invalid call replay identifier")
    entries = []
    if path.exists():
        with path.open("rb") as source:
            encrypted = source.read(MAX_REPLAY_FILE_BYTES + 1)
        if len(encrypted) > MAX_REPLAY_FILE_BYTES:
            raise ValueError("Call replay store too large")
        loaded = json.loads(box.decrypt(encrypted).decode())
        if not isinstance(loaded, list) or any(not isinstance(x, list) or len(x) != 3
                                              or not isinstance(x[0], str) or not _uuid4(x[1])
                                              or type(x[2]) is not int for x in loaded):
            raise ValueError("Invalid call replay store")
        entries = [entry for entry in loaded if now - entry[2] <= 2 * MAX_SKEW_SECONDS]
    if any(entry[0] == sender and entry[1] == call_id for entry in entries):
        return False
    if len(entries) >= MAX_REPLAY_ENTRIES:
        raise ValueError("Call replay store full")
    entries.append([sender, call_id, now])
    temp_name = None
    try:
        encrypted = box.encrypt(json.dumps(entries, separators=(",", ":")).encode())
        if len(encrypted) > MAX_REPLAY_FILE_BYTES:
            raise ValueError("Call replay store too large")
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
            temp_name = f.name
            f.write(encrypted)
            f.flush()
            os.fsync(f.fileno())
        _restrict_file_permissions(Path(temp_name))
        os.replace(temp_name, path)
        _restrict_file_permissions(path)
        _fsync_directory(path.parent)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    return True
