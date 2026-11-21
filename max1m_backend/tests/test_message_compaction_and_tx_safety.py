"""Regression tests for Package #5 backend features:
- Delivered message compaction into MessageIdempotencyRecord tombstones
- Preservation of /messages/send-reliable idempotency & 409 conflict checks after compaction
- Preservation of /messages/sync-safe pagination cursors after compaction
- Tombstone TTL expiration and zero eviction of undelivered messages
- SQLite BEGIN IMMEDIATE rollback & idempotency safety in POST /files/{id}/grant and /groups/*
"""
import base64
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import models
from app.api import files as files_api
from app.api import messages as messages_api
from app.config import settings
from app.database import AsyncSessionLocal
from app.main import app
from app.rate_limit import limiter
from app.security import create_access_token


@pytest.fixture(autouse=True)
def _reset_limiter():
    limiter.reset()
    yield
    limiter.reset()


def test_delivered_message_compaction_preserves_idempotency_conflicts_and_cursors():
    with TestClient(app) as client:
        async def _seed_peers():
            async with AsyncSessionLocal() as db:
                u = models.User(username=f"cmp_{uuid.uuid4().hex[:10]}", password_hash="unused")
                db.add(u)
                await db.flush()
                sender = models.Device(
                    user_id=u.id,
                    device_name="Sender",
                    public_key=base64.b64encode(os.urandom(32)).decode("ascii"),
                    fingerprint=f"fp-s-{uuid.uuid4().hex}",
                )
                receiver = models.Device(
                    user_id=u.id,
                    device_name="Receiver",
                    public_key=base64.b64encode(os.urandom(32)).decode("ascii"),
                    fingerprint=f"fp-r-{uuid.uuid4().hex}",
                )
                other = models.Device(
                    user_id=u.id,
                    device_name="Other",
                    public_key=base64.b64encode(os.urandom(32)).decode("ascii"),
                    fingerprint=f"fp-o-{uuid.uuid4().hex}",
                )
                db.add_all([sender, receiver, other])
                await db.commit()
                return u.id, sender.id, receiver.id, other.id

        user_id, sender_id, receiver_id, other_id = client.portal.call(_seed_peers)
        sender_auth = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": sender_id})}
        receiver_auth = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": receiver_id})}
        other_auth = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": other_id})}

        m1_id = str(uuid.uuid4())
        m2_id = str(uuid.uuid4())
        m3_id = str(uuid.uuid4())

        m1_body = {
            "client_message_id": m1_id,
            "receiver_device_id": receiver_id,
            "encrypted_blob": "ciphertext-one-" + ("A" * 2048),
            "signature": "sig-one",
        }
        m2_body = {
            "client_message_id": m2_id,
            "receiver_device_id": receiver_id,
            "encrypted_blob": "ciphertext-two",
            "signature": "sig-two",
        }
        m3_body = {
            "client_message_id": m3_id,
            "receiver_device_id": receiver_id,
            "encrypted_blob": "ciphertext-three",
            "signature": "sig-three",
        }

        assert client.post("/messages/send-reliable", headers=sender_auth, json=m1_body).status_code == 200
        time.sleep(0.01)
        assert client.post("/messages/send-reliable", headers=sender_auth, json=m2_body).status_code == 200
        time.sleep(0.01)
        assert client.post("/messages/send-reliable", headers=sender_auth, json=m3_body).status_code == 200

        # Receiver acknowledges ONLY m1; m2 and m3 stay pending.
        ack = client.post("/messages/ack", headers=receiver_auth, json={"message_ids": [m1_id]})
        assert ack.status_code == 200

        # Compact delivered messages immediately (retention_seconds=0).
        async def _run_compact():
            async with AsyncSessionLocal() as db:
                res = await messages_api.compact_delivered_messages(
                    db, retention_seconds=0.0, tombstone_ttl_seconds=3600.0
                )
                msg_m1 = await db.get(models.Message, m1_id)
                msg_m2 = await db.get(models.Message, m2_id)
                tomb_m1 = await db.get(models.MessageIdempotencyRecord, m1_id)
                return res, msg_m1 is None, msg_m2 is not None, tomb_m1 is not None

        summary, m1_pruned, m2_kept, tomb_created = client.portal.call(_run_compact)
        assert summary["compacted"] >= 1
        assert m1_pruned is True
        assert m2_kept is True
        assert tomb_created is True

        # 1. Sync-safe cursor pointing to compacted m1 STILL resolves cleanly for receiver,
        #    returning [m2, m3], while rejecting foreign device cursor use with 400!
        page = client.get("/messages/sync-safe", headers=receiver_auth, params={"after": m1_id, "limit": 10})
        assert page.status_code == 200, page.text
        assert [row["id"] for row in page.json()] == [m2_id, m3_id]
        assert client.get("/messages/sync-safe", headers=other_auth, params={"after": m1_id}).status_code == 400

        # 2. Idempotent retry of compacted m1 returns 200 with full echoed envelope and does NOT re-enqueue m1!
        retry_ok = client.post("/messages/send-reliable", headers=sender_auth, json=m1_body)
        assert retry_ok.status_code == 200, retry_ok.text
        echoed = retry_ok.json()
        assert echoed["id"] == m1_id
        assert echoed["receiver_device_id"] == receiver_id
        assert echoed["encrypted_blob"] == m1_body["encrypted_blob"]
        assert echoed["signature"] == m1_body["signature"]

        # Receiver still sees only [m2, m3] — m1 was NOT duplicated!
        pending_now = client.get("/messages/sync-safe", headers=receiver_auth).json()
        assert [row["id"] for row in pending_now] == [m2_id, m3_id]

        # 3. Conflicting retries for compacted m1 are rejected with 409!
        assert client.post(
            "/messages/send-reliable",
            headers=sender_auth,
            json={**m1_body, "encrypted_blob": "tampered"},
        ).status_code == 409
        assert client.post(
            "/messages/send-reliable",
            headers=sender_auth,
            json={**m1_body, "signature": "tampered-sig"},
        ).status_code == 409
        assert client.post(
            "/messages/send-reliable",
            headers=sender_auth,
            json={**m1_body, "receiver_device_id": other_id},
        ).status_code == 409
        assert client.post(
            "/messages/send-reliable",
            headers=other_auth,
            json=m1_body,
        ).status_code == 409

        # 4. Tombstone expires cleanly once older than tombstone_ttl_seconds.
        async def _expire_tombstone():
            async with AsyncSessionLocal() as db:
                tomb = await db.get(models.MessageIdempotencyRecord, m1_id)
                tomb.compacted_at = datetime.now(timezone.utc) - timedelta(days=100)
                await db.commit()
            async with AsyncSessionLocal() as db:
                return await messages_api.compact_delivered_messages(
                    db, retention_seconds=3600.0, tombstone_ttl_seconds=60.0
                )

        exp_summary = client.portal.call(_expire_tombstone)
        assert exp_summary["expired_tombstones"] >= 1


def test_file_grant_and_group_mutations_rollback_cleanly_and_remain_idempotent(tmp_path, monkeypatch):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(files_api, "UPLOAD_DIR", str(upload_dir))
    monkeypatch.setattr(settings, "ALLOW_INSECURE_LEGACY_GROUPS", True)

    with TestClient(app) as client:
        async def _seed():
            async with AsyncSessionLocal() as db:
                u = models.User(username=f"tx_{uuid.uuid4().hex[:10]}", password_hash="unused")
                db.add(u)
                await db.flush()
                d1 = models.Device(
                    user_id=u.id,
                    device_name="Owner",
                    public_key=base64.b64encode(os.urandom(32)).decode("ascii"),
                    fingerprint=f"fp-1-{uuid.uuid4().hex}",
                )
                d2 = models.Device(
                    user_id=u.id,
                    device_name="Member",
                    public_key=base64.b64encode(os.urandom(32)).decode("ascii"),
                    fingerprint=f"fp-2-{uuid.uuid4().hex}",
                )
                db.add_all([d1, d2])
                await db.commit()
                return u.id, d1.id, d2.id

        user_id, d1, d2 = client.portal.call(_seed)
        auth1 = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": d1})}
        auth2 = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": d2})}

        fid = str(uuid.uuid4())
        assert client.post(f"/files/upload-reliable/{fid}", headers=auth1, content=b"blob").status_code == 200

        # Error paths in /grant (404 missing file, 403 non-owner, 404 missing recipient) must roll back BEGIN IMMEDIATE cleanly
        assert client.post(
            f"/files/{uuid.uuid4()}/grant", params={"recipient_device_id": d2}, headers=auth1
        ).status_code == 404
        assert client.post(
            f"/files/{fid}/grant", params={"recipient_device_id": d1}, headers=auth2
        ).status_code == 403
        assert client.post(
            f"/files/{fid}/grant", params={"recipient_device_id": "nonexistent-dev"}, headers=auth1
        ).status_code == 404

        # Subsequent valid grant and duplicate idempotent grant both succeed without DB lock errors!
        for _ in range(2):
            g = client.post(f"/files/{fid}/grant", params={"recipient_device_id": d2}, headers=auth1)
            assert g.status_code == 200
            assert g.json()["granted_to"] == d2

        # Group lifecycle endpoints validate group_id and roll back cleanly on 403/409
        created = client.post(
            "/groups/create",
            headers=auth1,
            json={
                "name": "TxGroup",
                "member_device_ids": [d2],
                "sender_keys": [
                    {
                        "recipient_device_id": d2,
                        "encrypted_sender_key": "enc-sk",
                        "sender_key_signature": "sig-sk",
                    }
                ],
            },
        )
        assert created.status_code == 200, created.text
        gid = created.json()["id"]

        # Malformed group_id rejected with 400
        assert client.post("/groups/bad..id/leave", headers=auth2).status_code == 400
        assert client.delete("/groups/bad..id", headers=auth1).status_code == 400

        # Owner cannot leave (409), non-owner cannot delete (403)
        assert client.post(f"/groups/{gid}/leave", headers=auth1).status_code == 409
        assert client.delete(f"/groups/{gid}", headers=auth2).status_code == 403

        # Group ACK, member leave, and owner delete all succeed cleanly under BEGIN IMMEDIATE
        assert client.post("/groups/ack", headers=auth2, json={"message_ids": [str(uuid.uuid4())]}).status_code == 200
        assert client.post(f"/groups/{gid}/leave", headers=auth2).status_code == 200
        assert client.delete(f"/groups/{gid}", headers=auth1).status_code == 200
