import base64
import fcntl
import os
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import models
from app.api import files, messages
from app.database import AsyncSessionLocal
from app.main import app
from app.rate_limit import limiter
from app.security import create_access_token


@pytest.fixture(autouse=True)
def _clean_limiter():
    limiter.reset()
    yield
    limiter.reset()


def test_sweep_orphaned_upload_staging_reclaims_only_dead_unlocked_staging_files(tmp_path):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    external_secret = tmp_path / "secret.txt"
    external_secret.write_bytes(b"do-not-delete")

    # 1. Dead orphaned staging file (old mtime, no lock, nlink == 1) -> must be removed
    dead = upload_dir / ".upload-dead123"
    dead.write_bytes(b"partial-dead-cipher")
    old_ts = time.time() - 1200
    os.utime(dead, (old_ts, old_ts))

    # 2. Active in-flight staging file (old mtime, but holds exclusive flock!) -> must be kept
    active = upload_dir / ".upload-active456"
    active.write_bytes(b"streaming-in-progress")
    os.utime(active, (old_ts, old_ts))
    active_fd = os.open(active, os.O_RDONLY)
    fcntl.flock(active_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    # 3. Fresh staging file within grace period -> must be kept
    fresh = upload_dir / ".upload-fresh789"
    fresh.write_bytes(b"just-created")

    # 4. Hard-linked staging file (mid-publication to final UUID) -> must be kept
    linked_staging = upload_dir / ".upload-linked999"
    linked_staging.write_bytes(b"published-bytes")
    published_uuid = upload_dir / str(uuid.uuid4())
    os.link(linked_staging, published_uuid)
    os.utime(linked_staging, (old_ts, old_ts))

    # 5. Symlink named .upload-sym -> must not delete target
    sym = upload_dir / ".upload-symlink"
    sym.symlink_to(external_secret)

    try:
        result = files.sweep_orphaned_upload_staging(str(upload_dir), min_age_seconds=300.0)
        assert result["removed"] == 1
        assert result["active_locked"] == 1
        assert not dead.exists()
        assert active.exists()
        assert fresh.exists()
        assert linked_staging.exists()
        assert published_uuid.exists()
        assert external_secret.exists()
    finally:
        os.close(active_fd)

    # Once the uploader process closes/dies, a subsequent sweep reclaims `active` too!
    second = files.sweep_orphaned_upload_staging(str(upload_dir), min_age_seconds=300.0)
    assert second["removed"] == 1
    assert not active.exists()
    assert published_uuid.exists()


def test_download_and_grant_reject_dot_files_symlinks_and_unsafe_ids(tmp_path, monkeypatch):
    upload_dir = tmp_path / "secure_uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(files, "UPLOAD_DIR", str(upload_dir))

    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret")

    with TestClient(app) as client:
        sym_id = str(uuid.uuid4())
        (upload_dir / sym_id).symlink_to(outside)

        async def _seed():
            async with AsyncSessionLocal() as db:
                u = models.User(username=f"fsec_{uuid.uuid4().hex[:8]}", password_hash="unused")
                db.add(u)
                await db.flush()
                d = models.Device(
                    user_id=u.id,
                    device_name="Dev",
                    public_key=base64.b64encode(os.urandom(32)).decode(),
                    fingerprint=uuid.uuid4().hex,
                )
                db.add(d)
                await db.flush()
                db.add(models.FileRecord(id=sym_id, owner_user_id=u.id, size=6, uploaded_by_device_id=d.id))
                db.add(models.FileAccess(file_id=sym_id, device_id=d.id))
                await db.commit()
                return u.id, d.id

        user_id, dev_id = client.portal.call(_seed)
        hdr = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": dev_id})}

        # Symlink inside UPLOAD_DIR even with DB record must be rejected (404).
        assert client.get(f"/files/{sym_id}", headers=hdr).status_code == 404
        # Dot-prefixed staging names and unsafe characters must be rejected (404).
        assert client.get("/files/.upload-staging", headers=hdr).status_code == 404
        assert client.post(
            "/files/.upload-staging/grant",
            headers=hdr,
            params={"recipient_device_id": dev_id},
        ).status_code == 404
        assert client.post(
            f"/files/{sym_id}/grant",
            headers=hdr,
            params={"recipient_device_id": "../bad"},
        ).status_code == 404


def test_ws_relay_whitelists_fields_blocks_spoofing_and_rate_limits_floods(monkeypatch):
    monkeypatch.setattr(messages, "WS_RECV_MAX_BURST", 4)
    monkeypatch.setattr(messages, "WS_RECV_REFILL_PER_SEC", 0.0)

    with TestClient(app) as client:
        async def _seed_pair():
            async with AsyncSessionLocal() as db:
                u = models.User(username=f"ws_{uuid.uuid4().hex[:8]}", password_hash="unused")
                db.add(u)
                await db.flush()
                d1 = models.Device(user_id=u.id, device_name="A", public_key="k1", fingerprint=uuid.uuid4().hex)
                d2 = models.Device(user_id=u.id, device_name="B", public_key="k2", fingerprint=uuid.uuid4().hex)
                db.add_all([d1, d2])
                await db.commit()
                return u.id, d1.id, d2.id

        uid, dev1, dev2 = client.portal.call(_seed_pair)
        tok1 = create_access_token({"sub": uid, "device_id": dev1})
        tok2 = create_access_token({"sub": uid, "device_id": dev2})

        with client.websocket_connect(f"/messages/ws/{dev2}", headers={"Authorization": f"Bearer {tok2}"}) as ws2:
            with client.websocket_connect(f"/messages/ws/{dev1}", headers={"Authorization": f"Bearer {tok1}"}) as ws1:
                ws1.send_json({
                    "type": "call_offer",
                    "to_device_id": dev2,
                    "from_device_id": "spoofed-device-id",
                    "encrypted_call": "cipher-blob",
                    "call_signature": "sig-blob",
                    "injected_untrusted_field": {"admin": True},
                })
                relayed = ws2.receive_json()
                assert relayed == {
                    "type": "call_offer",
                    "to_device_id": dev2,
                    "from_device_id": dev1,
                    "encrypted_call": "cipher-blob",
                    "call_signature": "sig-blob",
                }

                # Remaining burst is 3 frames; 4th frame triggers WS 1008 flood protection.
                for _ in range(3):
                    ws1.send_json({"type": "webrtc_signal", "to_device_id": dev2})
                    assert ws2.receive_json()["from_device_id"] == dev1

                ws1.send_json({"type": "webrtc_signal", "to_device_id": dev2})
                with pytest.raises(WebSocketDisconnect) as exc_info:
                    ws1.receive_text()
                assert exc_info.value.code == 1008
