"""Server-side anti-seizure & metadata minimization regression tests (Package I)."""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import uuid

from sqlalchemy import text

from app import models, security
from app.api.files import _secure_zero_single_link_file
from app.config import settings
from app.database import AsyncSessionLocal, DB_PATH, engine, init_models


def test_sqlite_secure_delete_and_memory_temp_store_wipe_deleted_rows_on_disk():
    canary = f"FORENSIC_CANARY_{uuid.uuid4().hex}_DO_NOT_RETAIN_ON_DISK"

    import asyncio

    async def _exercise():
        await init_models()
        async with engine.connect() as conn:
            sec_del = (await conn.execute(text("PRAGMA secure_delete"))).scalar_one()
            temp_st = (await conn.execute(text("PRAGMA temp_store"))).scalar_one()
            assert sec_del == 1
            assert temp_st == 2  # 2 == MEMORY

        gid = f"grp_{uuid.uuid4().hex[:12]}"
        async with AsyncSessionLocal() as db:
            u = models.User(username=f"u_{uuid.uuid4().hex[:10]}", password_hash="unused")
            db.add(u)
            await db.flush()
            d = models.Device(
                user_id=u.id,
                device_name="dev",
                public_key="pub",
                fingerprint=f"fp_{uuid.uuid4().hex}",
            )
            db.add(d)
            await db.flush()
            g = models.Group(id=gid, name=canary, created_by_device_id=d.id, epoch=1)
            db.add(g)
            await db.commit()

        async with engine.begin() as conn:
            await conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))

        raw_before = Path(DB_PATH).read_bytes()
        assert canary.encode("utf-8") in raw_before

        async with AsyncSessionLocal() as db:
            await db.execute(text("DELETE FROM groups WHERE id = :gid"), {"gid": gid})
            await db.commit()

        async with engine.begin() as conn:
            await conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))

        raw_after = Path(DB_PATH).read_bytes()
        assert canary.encode("utf-8") not in raw_after

    asyncio.run(_exercise())


def test_last_seen_coarsening_and_zero_freeze_mode(monkeypatch):
    created = datetime(2026, 11, 5, 14, 23, 47, tzinfo=timezone.utc)
    later_same_hour = datetime(2026, 11, 5, 14, 58, 19, tzinfo=timezone.utc)
    next_hour = datetime(2026, 11, 5, 15, 41, 9, tzinfo=timezone.utc)

    monkeypatch.setattr(settings, "LAST_SEEN_GRANULARITY_SECONDS", 3600)
    # Within creation hour, floor_dt clamp keeps created_at <= last_seen without leaking later_same_hour's minutes/seconds
    c1 = security.coarsen_device_last_seen(later_same_hour, floor_dt=created)
    assert c1 == created
    # Next hour snaps cleanly to exact hour boundary 15:00:00Z (zero minute/second leakage!)
    c2 = security.coarsen_device_last_seen(next_hour, floor_dt=created)
    assert c2 == datetime(2026, 11, 5, 15, 0, 0, tzinfo=timezone.utc)

    # Granularity = 0 freezes last_seen completely at creation timestamp
    monkeypatch.setattr(settings, "LAST_SEEN_GRANULARITY_SECONDS", 0)
    c_frozen = security.coarsen_device_last_seen(
        created + timedelta(days=10), floor_dt=created
    )
    assert c_frozen == created


def test_secure_zero_single_link_file_overwrites_only_unshared_inodes(tmp_path: Path):
    # 1. Single-link file: bytes are zeroed in-place before caller unlinks
    single = tmp_path / "blob_single"
    secret_payload = b"SECRET_CIPHERTEXT_BLOCKS_" * 200
    single.write_bytes(secret_payload)
    _secure_zero_single_link_file(str(single))
    assert single.read_bytes() == b"\x00" * len(secret_payload)
    single.unlink()

    # 2. Multi-hardlink file (st_nlink == 2): MUST NOT zero shared inode!
    src = tmp_path / "staging"
    pub = tmp_path / "published"
    src.write_bytes(secret_payload)
    os.link(src, pub)
    _secure_zero_single_link_file(str(src))
    src.unlink()
    assert pub.read_bytes() == secret_payload
