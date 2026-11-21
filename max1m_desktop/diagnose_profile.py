#!/usr/bin/env python3
"""Read-only local profile health & integrity diagnostics for Max1m Desktop.

Never creates directories, never generates keyring entries, and never prints
contact names, group names, server URLs, UUIDs, file paths, or plaintext.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import uuid
from pathlib import Path

import keyring
import nacl.exceptions
import nacl.secret

from app import secure_storage
from app.history_activation import read_catalog
from app.outbox import MAX_ENCRYPTED_RECORD_BYTES


_PROFILE_RE = re.compile(r"^[A-Za-z0-9_]{1,50}$")
_MAX_SCAN_FILES = 20_000


def _canonical_uuid4(value: str) -> bool:
    try:
        parsed = uuid.UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except (ValueError, AttributeError, TypeError):
        return False


def _read_secretbox_json(path: Path, box: nacl.secret.SecretBox, max_bytes: int):
    with path.open("rb") as f:
        raw = f.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("Record exceeds size limit")
    return json.loads(box.decrypt(raw).decode("utf-8"))


def diagnose_profile(username: str, base_dir: Path | None = None) -> dict:
    """Inspect a local profile strictly in read-only mode."""
    if not isinstance(username, str) or not _PROFILE_RE.fullmatch(username):
        raise ValueError("Invalid local profile name")

    root = Path(base_dir) if base_dir is not None else Path(secure_storage.BASE_DIR)
    profile_dir = root / "profiles" / username
    profile_exists = profile_dir.is_dir()

    # Read keyring strictly without creating keys if absent.
    local_key: bytes | None = None
    try:
        raw_local = keyring.get_password(
            secure_storage.SERVICE_NAME, f"{username}_local_storage_key"
        )
        if raw_local is None:
            keyring_status = "missing"
        else:
            decoded = base64.b64decode(raw_local, validate=True)
            if len(decoded) == nacl.secret.SecretBox.KEY_SIZE:
                local_key = decoded
                keyring_status = "present"
            else:
                keyring_status = "invalid"
    except Exception:
        keyring_status = "error"

    try:
        raw_priv = keyring.get_password(secure_storage.SERVICE_NAME, f"{username}_privkey")
        if raw_priv is None:
            device_private_key_status = "missing"
        else:
            decoded_priv = base64.b64decode(raw_priv, validate=True)
            device_private_key_status = "present" if len(decoded_priv) == 32 else "invalid"
    except Exception:
        device_private_key_status = "error"

    box = nacl.secret.SecretBox(local_key) if local_key is not None else None

    def _check_envelope(path: Path, max_bytes: int, required_key: str) -> str:
        if not os.path.lexists(path):
            return "missing"
        if box is None:
            return "skipped_no_key"
        try:
            if not path.is_file() or path.is_symlink():
                return "unreadable"
            data = _read_secretbox_json(path, box, max_bytes)
            if (not isinstance(data, dict)
                    or data.get("version") != 1
                    or data.get("owner") != username
                    or required_key not in data):
                return "unreadable"
            return "ok"
        except Exception:
            return "unreadable"

    device_identity_status = _check_envelope(
        profile_dir / "device_identity.enc",
        secure_storage.MAX_DEVICE_IDENTITY_BYTES,
        "device_id",
    )
    allies_enc_status = _check_envelope(
        profile_dir / "allies.enc",
        secure_storage.MAX_ALLIES_INDEX_BYTES,
        "allies",
    )
    groups_enc_status = _check_envelope(
        profile_dir / "groups.enc",
        secure_storage.MAX_GROUPS_INDEX_BYTES,
        "groups",
    )
    legacy_allies_json_present = os.path.lexists(profile_dir / "allies.json")

    msg_dir = profile_dir / "messages"
    legacy_message_files = 0
    if msg_dir.is_dir():
        for idx, entry in enumerate(msg_dir.glob("*.enc")):
            if idx >= _MAX_SCAN_FILES:
                break
            if entry.is_file() and not entry.is_symlink():
                legacy_message_files += 1

    catalog_path = profile_dir / "history_catalog.enc"
    migrated_catalog_chats = 0
    if not os.path.lexists(catalog_path):
        migrated_catalog_status = "missing"
    elif local_key is None:
        migrated_catalog_status = "skipped_no_key"
    else:
        try:
            chats = read_catalog(catalog_path, local_key, username)
            migrated_catalog_chats = len(chats)
            migrated_catalog_status = "ok"
        except Exception:
            migrated_catalog_status = "unreadable"

    outbox_pending = 0
    outbox_unreadable = 0
    attachments_pending = 0
    attachments_unreadable_or_corrupt = 0
    orphan_attachment_blobs = 0

    outbox_root = profile_dir / "outbox"
    if outbox_root.is_dir():
        for scope_dir in sorted(outbox_root.iterdir()):
            if not scope_dir.is_dir() or scope_dir.is_symlink():
                continue
            for enc_file in sorted(scope_dir.glob("*.enc")):
                outbox_pending += 1
                if box is None:
                    outbox_unreadable += 1
                    continue
                try:
                    rec = _read_secretbox_json(enc_file, box, MAX_ENCRYPTED_RECORD_BYTES)
                    cid = rec.get("client_message_id") if isinstance(rec, dict) else None
                    if not _canonical_uuid4(cid) or not enc_file.name.endswith(f"_{cid}.enc"):
                        outbox_unreadable += 1
                except Exception:
                    outbox_unreadable += 1

            attach_dir = scope_dir / "attachments"
            if attach_dir.is_dir() and not attach_dir.is_symlink():
                job_stems = set()
                for job_file in sorted(attach_dir.glob("*.job")):
                    attachments_pending += 1
                    stem = job_file.stem
                    job_stems.add(stem)
                    if box is None or not _canonical_uuid4(stem):
                        attachments_unreadable_or_corrupt += 1
                        continue
                    try:
                        rec = _read_secretbox_json(job_file, box, MAX_ENCRYPTED_RECORD_BYTES)
                        blob_file = attach_dir / f"{stem}.blob"
                        exp_size = rec.get("size") if isinstance(rec, dict) else None
                        exp_sha = rec.get("sha256") if isinstance(rec, dict) else None
                        if (not isinstance(rec, dict)
                                or rec.get("version") != 1
                                or rec.get("file_id") != stem
                                or not blob_file.is_file()
                                or type(exp_size) is not int
                                or exp_size < 1
                                or not isinstance(exp_sha, str)
                                or len(exp_sha) != 64):
                            attachments_unreadable_or_corrupt += 1
                            continue
                        digest = hashlib.sha256()
                        actual_size = 0
                        with blob_file.open("rb") as bf:
                            while chunk := bf.read(1024 * 1024):
                                actual_size += len(chunk)
                                if actual_size > exp_size:
                                    break
                                digest.update(chunk)
                        if actual_size != exp_size or digest.hexdigest() != exp_sha:
                            attachments_unreadable_or_corrupt += 1
                    except Exception:
                        attachments_unreadable_or_corrupt += 1

                for blob_file in sorted(attach_dir.glob("*.blob")):
                    if blob_file.stem not in job_stems:
                        orphan_attachment_blobs += 1

    has_encrypted_files = (
        any(
            st != "missing"
            for st in (
                device_identity_status,
                allies_enc_status,
                groups_enc_status,
                migrated_catalog_status,
            )
        )
        or legacy_message_files > 0
        or outbox_pending > 0
        or attachments_pending > 0
    )

    healthy = (
        keyring_status not in {"invalid", "error"}
        and device_private_key_status not in {"invalid", "error"}
        and (not has_encrypted_files or keyring_status == "present")
        and all(
            st in {"ok", "missing"}
            for st in (
                device_identity_status,
                allies_enc_status,
                groups_enc_status,
                migrated_catalog_status,
            )
        )
        and outbox_unreadable == 0
        and attachments_unreadable_or_corrupt == 0
        and orphan_attachment_blobs == 0
    )

    return {
        "profile_exists": profile_exists,
        "healthy": healthy,
        "keyring_status": keyring_status,
        "device_private_key_status": device_private_key_status,
        "device_identity_status": device_identity_status,
        "allies_enc_status": allies_enc_status,
        "legacy_allies_json_present": legacy_allies_json_present,
        "groups_enc_status": groups_enc_status,
        "legacy_message_files": legacy_message_files,
        "migrated_catalog_status": migrated_catalog_status,
        "migrated_catalog_chats": migrated_catalog_chats,
        "outbox_pending": outbox_pending,
        "outbox_unreadable": outbox_unreadable,
        "attachments_pending": attachments_pending,
        "attachments_unreadable_or_corrupt": attachments_unreadable_or_corrupt,
        "orphan_attachment_blobs": orphan_attachment_blobs,
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="local profile username")
    parser.add_argument(
        "--base-dir",
        default=None,
        help="optional custom base directory (default: ~/.max1m)",
    )
    parser.add_argument(
        "--confirm-read-only",
        action="store_true",
        help="confirm read-only inspection of local profile",
    )
    args = parser.parse_args(argv)
    if not args.confirm_read_only:
        parser.error("explicit --confirm-read-only is required")
    try:
        report = diagnose_profile(args.profile, base_dir=Path(args.base_dir) if args.base_dir else None)
    except Exception as exc:
        print(f"Diagnostics failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0 if report["healthy"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
