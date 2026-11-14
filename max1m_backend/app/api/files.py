import logging
import hashlib
import re
import stat
import tempfile
import time
import os
import uuid
from datetime import datetime, timezone
try:
    import fcntl
except ImportError:
    fcntl = None
from fastapi import APIRouter, UploadFile, HTTPException, Depends, Request
from starlette.datastructures import UploadFile as StarletteUploadFile
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import text, func, delete
from sqlalchemy.exc import IntegrityError

from ..database import get_db
from .. import models, schemas
from ..api.messages import get_current_device_id
from ..rate_limit import limiter
from ..config import settings
from ..upload_limits import admit_upload, run_upload_hash

logger = logging.getLogger("max1m.files")

router = APIRouter(prefix="/files", tags=["files"])

# Создаем папку для хранения зашифрованных файлов в корне бэкенда.
# Сервер видит только зашифрованный блоб — ключ шифрования знает только клиент.
UPLOAD_DIR = "secure_uploads"
os.makedirs(UPLOAD_DIR, mode=0o700, exist_ok=True)
if os.name == "posix" and not os.path.islink(UPLOAD_DIR):
    try:
        os.chmod(UPLOAD_DIR, 0o700)
    except OSError:
        pass

# Жёсткий лимит размера файла.
# Раньше тут было расхождение: комментарий говорил про 15МБ, код проверял 100МБ.
# Приводим к единому значению — 100МБ (поддерживает большие медиа-вложения).
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _try_lock_exclusive_nonblocking(fd: int) -> bool:
    if fcntl is None:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (BlockingIOError, PermissionError, OSError):
        return False


def sweep_orphaned_upload_staging(upload_dir: str = UPLOAD_DIR, min_age_seconds: float = 300.0) -> dict:
    """Safely reclaim dead .upload-* staging files without touching active uploads or published blobs.

    Active uploaders hold an exclusive POSIX flock on the staging file until
    after os.link/os.unlink completes; if the uploader crashes (e.g. SIGKILL),
    the kernel releases that lock automatically.
    """
    summary = {"scanned": 0, "removed": 0, "active_locked": 0, "skipped": 0}
    if fcntl is None or not os.path.isdir(upload_dir):
        return summary
    now = time.time()
    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        entries = list(os.scandir(upload_dir))
    except OSError:
        return summary

    for entry in entries:
        if not entry.name.startswith(".upload-"):
            continue
        summary["scanned"] += 1
        try:
            st_link = os.lstat(entry.path)
        except OSError:
            summary["skipped"] += 1
            continue
        if (not stat.S_ISREG(st_link.st_mode)
                or st_link.st_nlink != 1
                or (now - st_link.st_mtime) < min_age_seconds):
            summary["skipped"] += 1
            continue

        fd = None
        try:
            fd = os.open(entry.path, open_flags)
            if not _try_lock_exclusive_nonblocking(fd):
                summary["active_locked"] += 1
                continue
            st_fd = os.fstat(fd)
            st_cur = os.lstat(entry.path)
            if (not stat.S_ISREG(st_fd.st_mode)
                    or st_fd.st_nlink != 1
                    or st_cur.st_nlink != 1
                    or st_fd.st_ino != st_cur.st_ino
                    or st_fd.st_dev != st_cur.st_dev):
                summary["skipped"] += 1
                continue
            os.unlink(entry.path)
            summary["removed"] += 1
        except FileNotFoundError:
            summary["skipped"] += 1
        except OSError:
            summary["skipped"] += 1
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    if summary["removed"] > 0:
        dir_fd = None
        try:
            dir_fd = os.open(upload_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            if dir_fd is not None:
                try:
                    os.close(dir_fd)
                except OSError:
                    pass
    return summary


async def _upload_admission(device_id: str = Depends(get_current_device_id)):
    # Resolve authentication first; rejected requests never parse a body or
    # acquire a reservation. FastAPI caches the shared device dependency.
    with admit_upload():
        yield


@router.post("/upload")
@limiter.limit(settings.RATE_LIMIT_UPLOAD)
async def upload_file(
        request: Request,
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db),
        _upload_slot: None = Depends(_upload_admission),
):
    """
    Принимает зашифрованный блоб (картинку/голосовое/файл) и сохраняет на диск.

    Авторизация обязательна (JWT). Файл привязывается к загрузившему устройству,
    скачивать его по умолчанию может только сам загрузивший.
    Чтобы получатель тоже мог скачать — клиент должен вызвать /files/{file_id}/grant
    или передать recipient_device_id в этом запросе.
    """
    # Authenticate before multipart parsing, then limit both file and field
    # counts. Starlette spools file data, so an ASGI body cap is also needed.
    async with request.form(max_files=1, max_fields=0) as form:
        file = form.get("file")
        if not isinstance(file, StarletteUploadFile):
            raise HTTPException(status_code=422, detail="Expected one file")
        return await _save_legacy_upload(file, device_id, db)


async def _save_legacy_upload(file: UploadFile, device_id: str, db: AsyncSession):
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id)
    saved = False
    commit_attempted = False
    created = False
    try:
        stmt = select(models.Device).where(
            models.Device.id == device_id, models.Device.is_revoked == False
        )
        result = await db.execute(stmt)
        device = result.scalars().first()
        if not device:
            raise HTTPException(status_code=404, detail="Устройство не найдено")

        size = 0
        # UploadFile may already be spooled to disk by the multipart parser.
        # Read bounded chunks instead of allocating the entire upload in RAM.
        raw_fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(raw_fd, "wb") as output:
            if os.name == "posix":
                try:
                    os.fchmod(output.fileno(), 0o600)
                except OSError:
                    pass
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Файл слишком большой. Максимум {MAX_FILE_SIZE // (1024 * 1024)}MB."
                    )
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())

        await _rollback_if_supported(db)
        await db.execute(text("BEGIN IMMEDIATE"))
        try:
            still_active = (await db.execute(select(models.Device).join(models.User).where(
                models.Device.id == device_id, models.Device.is_revoked == False,
                models.User.is_active == True))).scalars().first()
            if not still_active or still_active.user_id != device.user_id:
                raise HTTPException(status_code=401, detail="Device unavailable")
            reaped_paths = await _enforce_user_storage_quota_locked(
                db, device.user_id, size, UPLOAD_DIR
            )
            db.add(models.FileRecord(
                id=file_id, owner_user_id=device.user_id, size=size,
                uploaded_by_device_id=device_id,
            ))
            db.add(models.FileAccess(file_id=file_id, device_id=device_id))
            # Once commit starts its outcome can be uncertain: an exception may be
            # raised after SQLite committed. Never remove a potentially referenced
            # file in that case; an orphan is safer than losing a committed blob.
            commit_attempted = True
            await db.commit()
            saved = True
        except BaseException:
            await _rollback_if_supported(db)
            raise
        _unlink_reaped_blobs(reaped_paths, UPLOAD_DIR)
        return {"file_id": file_id, "size": size}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Ошибка загрузки файла")
        raise HTTPException(status_code=500, detail="Ошибка при сохранении файла")
    finally:
        if created and not saved and not commit_attempted:
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass
            except OSError:
                logger.exception("Не удалось удалить незавершённую загрузку")


def _canonical_uuid4(value: str) -> bool:
    try:
        parsed = uuid.UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except (ValueError, AttributeError, TypeError):
        return False


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _is_file_record_expired(record: models.FileRecord) -> bool:
    if settings.UPLOADED_FILE_RETENTION_SECONDS <= 0:
        return False
    created_utc = _as_utc(getattr(record, "created_at", None))
    if created_utc is None:
        return False
    return (datetime.now(timezone.utc) - created_utc).total_seconds() >= float(
        settings.UPLOADED_FILE_RETENTION_SECONDS
    )


async def _reap_stale_reservations_locked(
    db: AsyncSession,
    upload_dir: str,
    max_age_seconds: float | None = None,
    device_id: str | None = None,
    max_scan: int = 2000,
) -> dict:
    """Reap expired upload reservations that have NO FileRecord and NO blob on disk.

    Must be called inside an active BEGIN IMMEDIATE transaction so disk-existence
    and DB ownership checks cannot race with concurrent upload publication.
    """
    summary = {
        "scanned": 0,
        "removed": 0,
        "skipped_with_blob": 0,
        "skipped_with_record": 0,
    }
    ttl = (
        float(settings.UPLOAD_RESERVATION_TTL_SECONDS)
        if max_age_seconds is None
        else float(max_age_seconds)
    )
    if ttl < 0:
        return summary

    stmt = select(models.UploadReservation).order_by(models.UploadReservation.created_at.asc())
    if device_id is not None:
        stmt = stmt.where(models.UploadReservation.device_id == device_id)
    stmt = stmt.limit(max(1, int(max_scan)))
    candidates = (await db.execute(stmt)).scalars().all()
    now_utc = datetime.now(timezone.utc)

    for res in candidates:
        summary["scanned"] += 1
        created_utc = _as_utc(res.created_at)
        if created_utc is None or (now_utc - created_utc).total_seconds() < ttl:
            continue
        if not _canonical_uuid4(res.file_id):
            continue
        if await db.get(models.FileRecord, res.file_id) is not None:
            summary["skipped_with_record"] += 1
            continue
        blob_path = os.path.join(upload_dir, res.file_id)
        # Never delete a reservation if a blob is already linked on disk: the
        # reservation binds ownership until the client retries publication.
        if os.path.lexists(blob_path):
            summary["skipped_with_blob"] += 1
            continue
        await db.delete(res)
        summary["removed"] += 1
    if summary["removed"]:
        await db.flush()
    return summary


async def cleanup_stale_upload_reservations(
    db: AsyncSession,
    upload_dir: str = UPLOAD_DIR,
    max_age_seconds: float | None = None,
) -> dict:
    """Safely remove expired UploadReservation rows that never published a blob."""
    ttl = (
        float(settings.UPLOAD_RESERVATION_TTL_SECONDS)
        if max_age_seconds is None
        else float(max_age_seconds)
    )
    if ttl < 0:
        return {"scanned": 0, "removed": 0, "skipped_with_blob": 0, "skipped_with_record": 0}

    # Fast read-only pre-check avoids taking a SQLite writer lock or issuing an
    # empty commit when there are no expired reservations to reap.
    rows = (await db.execute(
        select(models.UploadReservation.created_at)
        .order_by(models.UploadReservation.created_at.asc())
        .limit(1)
    )).scalars().all()
    await db.rollback()
    if not rows:
        return {"scanned": 0, "removed": 0, "skipped_with_blob": 0, "skipped_with_record": 0}
    oldest_utc = _as_utc(rows[0])
    if oldest_utc is not None and (datetime.now(timezone.utc) - oldest_utc).total_seconds() < ttl:
        return {"scanned": 1, "removed": 0, "skipped_with_blob": 0, "skipped_with_record": 0}

    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        summary = await _reap_stale_reservations_locked(
            db, upload_dir=upload_dir, max_age_seconds=max_age_seconds
        )
        if summary["removed"]:
            await db.commit()
        else:
            await db.rollback()
        return summary
    except BaseException:
        await db.rollback()
        raise


def _safe_blob_unlink_path(upload_dir: str, file_id: str) -> str | None:
    if not isinstance(file_id, str) or not _SAFE_ID_RE.fullmatch(file_id) or file_id.startswith("."):
        return None
    base_real = os.path.realpath(upload_dir)
    candidate = os.path.join(upload_dir, file_id)
    if os.path.islink(candidate):
        return None
    resolved = os.path.realpath(candidate)
    if not resolved.startswith(base_real + os.sep):
        return None
    return resolved


def _secure_zero_single_link_file(path: str) -> None:
    """Best-effort overwrite with zeros before unlink when st_nlink == 1."""
    fd = None
    try:
        st_pre = os.lstat(path)
        if not stat.S_ISREG(st_pre.st_mode) or st_pre.st_nlink != 1 or st_pre.st_size <= 0:
            return
        flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        st_fd = os.fstat(fd)
        if not stat.S_ISREG(st_fd.st_mode) or st_fd.st_nlink != 1 or st_fd.st_ino != st_pre.st_ino:
            return
        remaining = min(st_fd.st_size, 32 * 1024 * 1024)
        zero_chunk = b"\x00" * 65536
        os.lseek(fd, 0, os.SEEK_SET)
        while remaining > 0:
            step = min(len(zero_chunk), remaining)
            written = os.write(fd, zero_chunk[:step])
            if written <= 0:
                break
            remaining -= written
        os.fsync(fd)
    except OSError:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _unlink_reaped_blobs(paths: list[str], upload_dir: str) -> int:
    removed = 0
    for p in paths:
        try:
            if not os.path.islink(p) and os.path.isfile(p):
                _secure_zero_single_link_file(p)
                os.unlink(p)
                removed += 1
        except OSError:
            pass
    if removed > 0 and os.path.isdir(upload_dir):
        dir_fd = None
        try:
            dir_fd = os.open(upload_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            if dir_fd is not None:
                try:
                    os.close(dir_fd)
                except OSError:
                    pass
    return removed


async def _reap_expired_files_locked(
    db: AsyncSession,
    upload_dir: str,
    retention_seconds: float | None = None,
    owner_user_id: str | None = None,
    max_scan: int = 200,
) -> tuple[dict, list[str]]:
    """Delete expired FileRecord + FileAccess rows inside BEGIN IMMEDIATE.

    Returns (summary, paths_to_unlink_after_commit) so disk blobs are NEVER
    unlinked before the database transaction commits.
    """
    summary = {"scanned": 0, "expired_records": 0}
    if retention_seconds is None:
        if settings.UPLOADED_FILE_RETENTION_SECONDS <= 0:
            return summary, []
        ret_sec = float(settings.UPLOADED_FILE_RETENTION_SECONDS)
    else:
        if float(retention_seconds) < 0:
            return summary, []
        ret_sec = float(retention_seconds)

    stmt = select(models.FileRecord).order_by(models.FileRecord.created_at.asc())
    if owner_user_id is not None:
        stmt = stmt.where(models.FileRecord.owner_user_id == owner_user_id)
    stmt = stmt.limit(max(1, int(max_scan)))
    candidates = (await db.execute(stmt)).scalars().all()
    now_utc = datetime.now(timezone.utc)
    paths_to_unlink: list[str] = []

    for rec in candidates:
        summary["scanned"] += 1
        created_utc = _as_utc(rec.created_at)
        if created_utc is None or (now_utc - created_utc).total_seconds() < ret_sec:
            continue
        safe_path = _safe_blob_unlink_path(upload_dir, rec.id)
        if safe_path is not None:
            paths_to_unlink.append(safe_path)
        await db.execute(
            delete(models.FileAccess)
            .where(models.FileAccess.file_id == rec.id)
            .execution_options(synchronize_session=False)
        )
        await db.delete(rec)
        summary["expired_records"] += 1

    if summary["expired_records"]:
        await db.flush()
    return summary, paths_to_unlink


async def cleanup_expired_uploaded_files(
    db: AsyncSession,
    upload_dir: str = UPLOAD_DIR,
    retention_seconds: float | None = None,
    batch_size: int = 200,
) -> dict:
    """Prune expired FileRecord rows and unlink their ciphertext blobs after commit."""
    if retention_seconds is None:
        if settings.UPLOADED_FILE_RETENTION_SECONDS <= 0:
            return {"scanned": 0, "expired_records": 0, "unlinked_blobs": 0}
        ret_sec = float(settings.UPLOADED_FILE_RETENTION_SECONDS)
    else:
        if float(retention_seconds) < 0:
            return {"scanned": 0, "expired_records": 0, "unlinked_blobs": 0}
        ret_sec = float(retention_seconds)

    # Read-only pre-check avoids taking a SQLite writer lock or issuing an empty
    # commit when no stored files have reached the retention horizon.
    oldest = (await db.execute(
        select(models.FileRecord.created_at)
        .order_by(models.FileRecord.created_at.asc())
        .limit(1)
    )).scalar_one_or_none()
    await db.rollback()
    if oldest is None:
        return {"scanned": 0, "expired_records": 0, "unlinked_blobs": 0}
    oldest_utc = _as_utc(oldest)
    if oldest_utc is not None and (datetime.now(timezone.utc) - oldest_utc).total_seconds() < ret_sec:
        return {"scanned": 1, "expired_records": 0, "unlinked_blobs": 0}

    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        summary, paths_to_unlink = await _reap_expired_files_locked(
            db,
            upload_dir=upload_dir,
            retention_seconds=retention_seconds,
            max_scan=batch_size,
        )
        if summary["expired_records"]:
            await db.commit()
        else:
            await db.rollback()
            paths_to_unlink = []
    except BaseException:
        await db.rollback()
        raise

    unlinked = _unlink_reaped_blobs(paths_to_unlink, upload_dir)
    return {
        "scanned": summary["scanned"],
        "expired_records": summary["expired_records"],
        "unlinked_blobs": unlinked,
    }


async def _rollback_if_supported(db) -> None:
    rb = getattr(db, "rollback", None)
    if callable(rb):
        await rb()


async def _enforce_user_storage_quota_locked(
    db: AsyncSession,
    owner_user_id: str,
    incoming_bytes: int,
    upload_dir: str,
) -> list[str]:
    """Enforce MAX_STORED_FILES_PER_USER and MAX_STORED_BYTES_PER_USER inside BEGIN IMMEDIATE."""
    max_files = settings.MAX_STORED_FILES_PER_USER
    max_bytes = settings.MAX_STORED_BYTES_PER_USER
    if max_files < 1 or max_bytes < 1:
        raise HTTPException(status_code=503, detail="Invalid file quota configuration")

    usage_res = await db.execute(
        select(
            func.count(models.FileRecord.id),
            func.coalesce(func.sum(models.FileRecord.size), 0),
        ).where(models.FileRecord.owner_user_id == owner_user_id)
    )
    if not hasattr(usage_res, "one"):
        return []
    stored_count, stored_bytes = usage_res.one()
    reaped_paths: list[str] = []
    if stored_count >= max_files or (int(stored_bytes) + max(0, int(incoming_bytes))) > max_bytes:
        reap_summary, reaped_paths = await _reap_expired_files_locked(
            db, upload_dir=upload_dir, owner_user_id=owner_user_id
        )
        if reap_summary["expired_records"]:
            stored_count, stored_bytes = (await db.execute(
                select(
                    func.count(models.FileRecord.id),
                    func.coalesce(func.sum(models.FileRecord.size), 0),
                ).where(models.FileRecord.owner_user_id == owner_user_id)
            )).one()
    if stored_count >= max_files or (int(stored_bytes) + max(0, int(incoming_bytes))) > max_bytes:
        raise HTTPException(status_code=429, detail="Stored file quota exceeded")
    return reaped_paths


async def _reserve_upload(db, file_id, device_id, final_path, declared_size: int = 0):
    # Bind the ID before receiving/publishing any bytes. The SQLite writer lock
    # also serializes reservation, revocation checks and capacity decisions.
    reaped_paths: list[str] = []
    await db.rollback()
    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        device = (await db.execute(select(models.Device).join(models.User).where(
            models.Device.id == device_id, models.Device.is_revoked == False,
            models.User.is_active == True))).scalars().first()
        if not device:
            raise HTTPException(401, "Device unavailable")
        existing = await db.get(models.FileRecord, file_id)
        reservation = await db.get(models.UploadReservation, file_id)
        if ((existing and existing.uploaded_by_device_id != device_id) or
                (reservation and reservation.device_id != device_id)):
            raise HTTPException(409, "File identifier conflict")
        if existing and not os.path.isfile(final_path):
            raise HTTPException(409, "Stored file unavailable")
        upload_dir = os.path.dirname(final_path) or UPLOAD_DIR
        if not existing:
            reaped_paths = await _enforce_user_storage_quota_locked(
                db, device.user_id, max(0, int(declared_size)), upload_dir
            )
        if not existing and not reservation:
            # Older releases could leave an unowned file after a crash; without
            # a durable owner, recovering it automatically permits takeover.
            if os.path.lexists(final_path):
                raise HTTPException(409, "Unowned prior upload requires administration")
            limit = settings.MAX_INCOMPLETE_UPLOADS_PER_DEVICE
            if limit < 1:
                raise HTTPException(503, "Invalid upload limit configuration")
            count = (await db.execute(select(func.count()).select_from(models.UploadReservation)
                                      .where(models.UploadReservation.device_id == device_id))).scalar_one()
            if count >= limit:
                reaped = await _reap_stale_reservations_locked(
                    db,
                    upload_dir=upload_dir,
                    device_id=device_id,
                )
                if reaped["removed"]:
                    count = (await db.execute(
                        select(func.count())
                        .select_from(models.UploadReservation)
                        .where(models.UploadReservation.device_id == device_id)
                    )).scalar_one()
            if count >= limit:
                raise HTTPException(429, "Too many incomplete uploads")
            db.add(models.UploadReservation(file_id=file_id, device_id=device_id))
        owner_user_id = device.user_id
        await db.commit()
    except BaseException:
        await db.rollback()
        raise
    _unlink_reaped_blobs(reaped_paths, os.path.dirname(final_path) or UPLOAD_DIR)
    return owner_user_id


def _hash_published_file(path, expected_size):
    """Hash at most the advertised size plus one byte in a worker thread."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as current:
        while chunk := current.read(min(1024 * 1024, expected_size - size + 1)):
            size += len(chunk)
            if size > expected_size:
                return size, None
            digest.update(chunk)
    return size, digest.digest()


async def _verify_published_file(path, expected_size, expected_digest):
    actual_size, actual_digest = await run_upload_hash(_hash_published_file, path, expected_size)
    if actual_size != expected_size or actual_digest != expected_digest:
        raise HTTPException(status_code=409, detail="File identifier conflict")


@router.post("/upload-reliable/{file_id}")
@limiter.limit(settings.RATE_LIMIT_UPLOAD)
async def upload_file_reliable(
        request: Request, file_id: str,
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db),
        _upload_slot: None = Depends(_upload_admission),
):
    """Store a client UUIDv4 file idempotently for its uploading device.

    A completed identical retry returns the same ID. A conflicting device or
    byte sequence is rejected. A file linked before a crash and DB commit can
    be recovered by a retry with the same UUID and identical bytes. Temp files
    are never used as public file IDs and are cleaned up on ordinary failures.
    """
    try:
        parsed = uuid.UUID(file_id)
        if parsed.version != 4 or str(parsed) != file_id:
            raise ValueError()
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid file identifier")

    final_path = os.path.join(UPLOAD_DIR, file_id)
    raw_cl = request.headers.get("content-length")
    declared_size = int(raw_cl) if (raw_cl and raw_cl.isdigit()) else 0
    owner_user_id = await _reserve_upload(db, file_id, device_id, final_path, declared_size=declared_size)
    temp_path = None
    lock_fd = None
    try:
        size = 0
        digest = hashlib.sha256()
        with tempfile.NamedTemporaryFile(dir=UPLOAD_DIR, prefix=".upload-", delete=False) as output:
            temp_path = output.name
            if os.name == "posix":
                try:
                    os.fchmod(output.fileno(), 0o600)
                except OSError:
                    pass
            if fcntl is not None:
                _try_lock_exclusive_nonblocking(output.fileno())
                lock_fd = os.dup(output.fileno())
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    raise HTTPException(status_code=400, detail="Файл слишком большой")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())

        # Read-only quota recheck for chunked uploads (or concurrent uploads)
        # BEFORE linking final_path, adding zero commits on the normal path.
        existing_pre = await db.get(models.FileRecord, file_id)
        stored_count_pre, stored_bytes_pre = (await db.execute(
            select(
                func.count(models.FileRecord.id),
                func.coalesce(func.sum(models.FileRecord.size), 0),
            ).where(models.FileRecord.owner_user_id == owner_user_id)
        )).one()
        await db.rollback()
        if existing_pre is None and (
            stored_count_pre >= settings.MAX_STORED_FILES_PER_USER
            or int(stored_bytes_pre) + size > settings.MAX_STORED_BYTES_PER_USER
        ):
            reaped_chunked: list[str] = []
            await db.execute(text("BEGIN IMMEDIATE"))
            try:
                reaped_chunked = await _enforce_user_storage_quota_locked(
                    db, owner_user_id, size, UPLOAD_DIR
                )
                await db.commit()
            except HTTPException as exc:
                await db.rollback()
                if exc.status_code == 429 and not os.path.lexists(final_path):
                    await db.execute(text("BEGIN IMMEDIATE"))
                    try:
                        res_drop = await db.get(models.UploadReservation, file_id)
                        if res_drop is not None and res_drop.device_id == device_id and not os.path.lexists(final_path):
                            await db.delete(res_drop)
                            await db.commit()
                        else:
                            await db.rollback()
                    except BaseException:
                        await db.rollback()
                raise
            except BaseException:
                await db.rollback()
                raise
            _unlink_reaped_blobs(reaped_chunked, UPLOAD_DIR)

        try:
            # Hard-link publishes the completed file without overwriting another
            # concurrent request. Staging and destination use the same directory.
            os.link(temp_path, final_path)
        except FileExistsError:
            pass
        # File hashing may take seconds on slow storage. Do not block the ASGI
        # event loop, and stop reading if the published file is oversized.
        await _verify_published_file(final_path, size, digest.digest())
        # Recheck authorization and ownership under the same writer lock as
        # publication in the DB; a device revoked during a slow upload fails.
        await db.rollback()
        await db.execute(text("BEGIN IMMEDIATE"))
        try:
            authorized = (await db.execute(select(models.Device.id).join(models.User).where(
                models.Device.id == device_id, models.Device.is_revoked == False,
                models.User.is_active == True))).scalar_one_or_none()
            if authorized is None:
                raise HTTPException(401, "Device unavailable")
            existing = await db.get(models.FileRecord, file_id)
            reservation = await db.get(models.UploadReservation, file_id)
            if existing:
                if existing.uploaded_by_device_id != device_id or existing.size != size:
                    raise HTTPException(409, "File identifier conflict")
            else:
                if not reservation or reservation.device_id != device_id:
                    raise HTTPException(409, "File reservation unavailable")
                db.add(models.FileRecord(id=file_id, owner_user_id=owner_user_id, size=size,
                                         uploaded_by_device_id=device_id))
                db.add(models.FileAccess(file_id=file_id, device_id=device_id))
            if reservation:
                if reservation.device_id != device_id:
                    raise HTTPException(409, "File identifier conflict")
                await db.delete(reservation)
            await db.commit()
        except BaseException:
            await db.rollback()
            raise
        return {"file_id": file_id, "size": size}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Ошибка надёжной загрузки файла")
        raise HTTPException(status_code=500, detail="Ошибка при сохранении файла")
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass
            except OSError:
                logger.exception("Не удалось удалить временный файл загрузки")
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass


@router.delete("/upload-reliable/{file_id}")
@limiter.limit("60/minute")
async def cancel_upload_reservation(
        request: Request,
        file_id: str,
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db),
):
    """Cancel an unfinished reliable upload reservation that has not published a blob."""
    if not _canonical_uuid4(file_id):
        raise HTTPException(status_code=400, detail="Invalid file identifier")

    final_path = os.path.join(UPLOAD_DIR, file_id)
    await db.rollback()
    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        authorized = (await db.execute(
            select(models.Device.id)
            .join(models.User, models.User.id == models.Device.user_id)
            .where(
                models.Device.id == device_id,
                models.Device.is_revoked == False,
                models.User.is_active == True,
            )
        )).scalar_one_or_none()
        if authorized is None:
            raise HTTPException(status_code=401, detail="Device unavailable")

        existing = await db.get(models.FileRecord, file_id)
        if existing is not None:
            raise HTTPException(status_code=409, detail="Completed upload cannot be cancelled")

        reservation = await db.get(models.UploadReservation, file_id)
        if reservation is None:
            raise HTTPException(status_code=404, detail="Upload reservation not found")
        if reservation.device_id != device_id:
            raise HTTPException(status_code=409, detail="File identifier conflict")
        if os.path.lexists(final_path):
            raise HTTPException(status_code=409, detail="Published upload blob cannot be cancelled")

        await db.delete(reservation)
        await db.commit()
        return {"status": "cancelled", "file_id": file_id}
    except BaseException:
        await db.rollback()
        raise


def _safe_resolved_upload_path(file_id: str) -> str:
    if not isinstance(file_id, str) or not _SAFE_ID_RE.fullmatch(file_id) or file_id.startswith("."):
        raise HTTPException(status_code=404, detail="Файл не найден")
    base_real = os.path.realpath(UPLOAD_DIR)
    candidate = os.path.join(UPLOAD_DIR, file_id)
    if os.path.islink(candidate):
        raise HTTPException(status_code=404, detail="Файл не найден")
    resolved = os.path.realpath(candidate)
    if not resolved.startswith(base_real + os.sep):
        raise HTTPException(status_code=404, detail="Файл не найден")
    return resolved


@router.get("/{file_id}")
@limiter.limit("120/minute")
async def download_file(
        request: Request,
        file_id: str,
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db)
):
    """
    Отдает зашифрованный блоб по ID.

    Авторизация обязательна. Скачать может только устройство, которому
    явно выдан доступ (FileAccess) — либо владелец, либо получатель.
    Раньше эндпоинт был открыт: любой со знанием UUID мог скачать чужое.
    """
    file_path = _safe_resolved_upload_path(file_id)
    # Проверяем существование файла и наличие доступа ОДНИМ запросом.
    # Используем join FileAccess — это и есть проверка полномочий.
    stmt = (
        select(models.FileRecord)
        .join(models.FileAccess, models.FileAccess.file_id == models.FileRecord.id)
        .where(
            models.FileRecord.id == file_id,
            models.FileAccess.device_id == device_id,
        )
    )
    result = await db.execute(stmt)
    record = result.scalars().first()

    if not record or _is_file_record_expired(record):
        # Не раскрываем причину (нет файла, истёк TTL vs нет доступа) — единый ответ,
        # чтобы не дать злоумышленнику информации для перебора.
        raise HTTPException(status_code=404, detail="Файл не найден")

    if not os.path.isfile(file_path) or os.path.islink(file_path):
        logger.warning("Файл %s есть в БД, но отсутствует на диске", file_id)
        raise HTTPException(status_code=404, detail="Файл не найден на сервере")

    return FileResponse(
        file_path,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="encrypted.bin"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/{file_id}/grant")
@limiter.limit("60/minute")
async def grant_file_access(
        request: Request,
        file_id: str,
        recipient_device_id: str,
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db)
):
    """
    Выдаёт устройству-получателю право скачивать файл.

    Вызывает ТОЛЬКО загрузивший файл (проверяем, что device_id — владелец).
    Клиент вызывает это сразу после upload, прямо перед отправкой сообщения
    с метаданными получателю — чтобы получатель гарантированно мог скачать.
    """
    if not isinstance(file_id, str) or not _SAFE_ID_RE.fullmatch(file_id) or file_id.startswith("."):
        raise HTTPException(status_code=404, detail="Файл не найден")
    if not isinstance(recipient_device_id, str) or not _SAFE_ID_RE.fullmatch(recipient_device_id):
        raise HTTPException(status_code=404, detail="Устройство получателя не найдено")
    # Serialize access grants with sender/recipient revocations on SQLite, and
    # always roll back the write lock if validation or authorization fails.
    await db.rollback()
    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        sender = (await db.execute(select(models.Device.id).join(models.User).where(
            models.Device.id == device_id, models.Device.is_revoked == False,
            models.User.is_active == True))).scalar_one_or_none()
        if sender is None:
            raise HTTPException(status_code=401, detail="Device unavailable")

        # 1. Находим файл и проверяем, что запрашивающий — его загрузивший device
        stmt = select(models.FileRecord).where(models.FileRecord.id == file_id)
        result = await db.execute(stmt)
        record = result.scalars().first()
        if not record or _is_file_record_expired(record):
            raise HTTPException(status_code=404, detail="Файл не найден")

        if record.uploaded_by_device_id != device_id:
            # Чужой файл — права выдавать нельзя
            raise HTTPException(status_code=403, detail="Нет прав на этот файл")

        # 2. Проверяем, что получатель существует и не отозван
        stmt_dev = select(models.Device).join(models.User).where(
            models.Device.id == recipient_device_id,
            models.Device.is_revoked == False,
            models.User.is_active == True,
        )
        result = await db.execute(stmt_dev)
        recipient = result.scalars().first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Устройство получателя не найдено")

        # 3. Добавляем доступ (если уже есть — idempotent, не падаем)
        existing = await db.execute(
            select(models.FileAccess).where(
                models.FileAccess.file_id == file_id,
                models.FileAccess.device_id == recipient_device_id,
            )
        )
        if not existing.scalars().first():
            max_grants = settings.MAX_GRANTS_PER_FILE
            if max_grants < 1:
                raise HTTPException(status_code=503, detail="Invalid file grant limit configuration")
            recipient_grants = (await db.execute(
                select(func.count(models.FileAccess.id)).where(
                    models.FileAccess.file_id == file_id,
                    models.FileAccess.device_id != device_id,
                )
            )).scalar_one()
            if recipient_grants >= max_grants:
                raise HTTPException(status_code=429, detail="Too many file access grants")
            db.add(models.FileAccess(file_id=file_id, device_id=recipient_device_id))
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
        return {"status": "ok", "file_id": file_id, "granted_to": recipient_device_id}
    except BaseException:
        await db.rollback()
        raise
