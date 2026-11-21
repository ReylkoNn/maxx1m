"""Regression tests for Package #9 backend security & resource hardening:
- Synchronous file expiry check on GET /files/{id} and POST /files/{id}/grant
- Per-file access grant quota (MAX_GRANTS_PER_FILE) and POSIX 0600/0700 modes
- Dynamic HTTP rate limits & cursor/receiver format checks on /messages/*
- Canonical Base64 verification & safe target_device_id checks in prekeys + group schema bounds
"""
import base64
import os
import stat
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import models, schemas
from app.api import files, prekeys
from app.config import settings
from app.database import AsyncSessionLocal
from app.main import app
from app.rate_limit import limiter
from app.security import create_access_token


def _noncanonical_b64_same_bytes(raw: bytes) -> str:
    """Flip an unused trailing padding bit in Base64 while decoding to identical bytes."""
    canonical = base64.b64encode(raw).decode("ascii")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if canonical.endswith("=="):
        # 4 trailing unused bits in the char before '==' (32-byte input -> 44 chars ending '=')
        idx = alphabet.index(canonical[-3])
        mutated_char = alphabet[idx ^ 1]
        cand = canonical[:-3] + mutated_char + "=="
    elif canonical.endswith("="):
        # 2 trailing unused bits in the char before '=' (32-byte -> 43 chars + '=', 64-byte -> 86 chars + '==')
        idx = alphabet.index(canonical[-2])
        mutated_char = alphabet[idx ^ 1]
        cand = canonical[:-2] + mutated_char + "="
    else:
        raise AssertionError("Expected padded base64 length (32 or 64 bytes)")
    assert cand != canonical
    assert base64.b64decode(cand, validate=True) == raw
    return cand


def test_file_grant_quota_read_time_expiry_and_posix_blob_modes(tmp_path, monkeypatch):
    upload_dir = tmp_path / "secure_uploads"
    upload_dir.mkdir(mode=0o755)
    monkeypatch.setattr(files, "UPLOAD_DIR", str(upload_dir))
    monkeypatch.setattr(settings, "MAX_GRANTS_PER_FILE", 2)
    monkeypatch.setattr(settings, "UPLOADED_FILE_RETENTION_SECONDS", 60)
    monkeypatch.setattr(settings, "RATE_LIMIT_UPLOAD", "100/minute")
    limiter.reset()

    with TestClient(app) as client:
        async def seed():
            async with AsyncSessionLocal() as db:
                user = models.User(
                    username="fgrant_" + uuid.uuid4().hex[:12],
                    password_hash="unused",
                )
                db.add(user)
                await db.flush()
                devs = [
                    models.Device(
                        user_id=user.id,
                        device_name=f"d-{i}",
                        public_key="pk",
                        fingerprint=uuid.uuid4().hex,
                    )
                    for i in range(4)
                ]
                db.add_all(devs)
                await db.commit()
                return user.id, [d.id for d in devs]

        user_id, (uploader, r1, r2, r3) = client.portal.call(seed)

        def auth(dev_id: str) -> dict[str, str]:
            return {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": dev_id})}

        # 1. Legacy upload creates blob with 0600 mode on POSIX
        up_resp = client.post(
            "/files/upload",
            headers=auth(uploader),
            files={"file": ("blob.bin", b"encrypted-payload-1", "application/octet-stream")},
        )
        assert up_resp.status_code == 200, up_resp.text
        legacy_fid = up_resp.json()["file_id"]
        if os.name == "posix":
            mode = stat.S_IMODE(os.lstat(upload_dir / legacy_fid).st_mode)
            assert mode == 0o600

        # Reliable upload also results in 0600 mode on POSIX
        rel_fid = str(uuid.uuid4())
        rel_resp = client.post(
            f"/files/upload-reliable/{rel_fid}",
            headers=auth(uploader),
            content=b"encrypted-payload-2",
        )
        assert rel_resp.status_code == 200, rel_resp.text
        if os.name == "posix":
            rel_mode = stat.S_IMODE(os.lstat(upload_dir / rel_fid).st_mode)
            assert rel_mode == 0o600

        # 2. Enforce MAX_GRANTS_PER_FILE=2 (idempotent re-grants remain allowed)
        assert client.post(
            f"/files/{legacy_fid}/grant",
            headers=auth(uploader),
            params={"recipient_device_id": r1},
        ).status_code == 200
        # Repeat grant to r1 is idempotent and does not consume a second slot
        assert client.post(
            f"/files/{legacy_fid}/grant",
            headers=auth(uploader),
            params={"recipient_device_id": r1},
        ).status_code == 200
        assert client.post(
            f"/files/{legacy_fid}/grant",
            headers=auth(uploader),
            params={"recipient_device_id": r2},
        ).status_code == 200
        # Third distinct recipient exceeds MAX_GRANTS_PER_FILE=2 -> 429
        over = client.post(
            f"/files/{legacy_fid}/grant",
            headers=auth(uploader),
            params={"recipient_device_id": r3},
        )
        assert over.status_code == 429

        # Before expiry, authorized device downloads 200
        dl_ok = client.get(f"/files/{legacy_fid}", headers=auth(r1))
        assert dl_ok.status_code == 200 and dl_ok.content == b"encrypted-payload-1"

        # 3. Backdate created_at past UPLOADED_FILE_RETENTION_SECONDS WITHOUT running sweep:
        # both GET /files/{id} and POST /files/{id}/grant must immediately reject with 404.
        async def age_file(fid: str):
            async with AsyncSessionLocal() as db:
                rec = await db.get(models.FileRecord, fid)
                rec.created_at = datetime.now(timezone.utc) - timedelta(seconds=120)
                await db.commit()

        client.portal.call(age_file, legacy_fid)
        assert client.get(f"/files/{legacy_fid}", headers=auth(uploader)).status_code == 404
        assert client.get(f"/files/{legacy_fid}", headers=auth(r1)).status_code == 404
        assert client.post(
            f"/files/{legacy_fid}/grant",
            headers=auth(uploader),
            params={"recipient_device_id": r1},
        ).status_code == 404

    limiter.reset()


def test_messages_rate_limits_and_cursor_receiver_validation(monkeypatch):
    limiter.reset()
    try:
        with TestClient(app) as client:
            async def seed():
                async with AsyncSessionLocal() as db:
                    user = models.User(
                        username="msg_rl_" + uuid.uuid4().hex[:12],
                        password_hash="unused",
                    )
                    db.add(user)
                    await db.flush()
                    d1 = models.Device(user_id=user.id, device_name="d1", public_key="pk1", fingerprint=uuid.uuid4().hex)
                    d2 = models.Device(user_id=user.id, device_name="d2", public_key="pk2", fingerprint=uuid.uuid4().hex)
                    db.add_all([d1, d2])
                    await db.commit()
                    return user.id, d1.id, d2.id

            user_id, sender, receiver = client.portal.call(seed)
            s_auth = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": sender})}
            r_auth = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": receiver})}

            # Unsafe cursor characters rejected before DB lookup
            for bad_cursor in ("../bad", "id with spaces", "bad$cursor"):
                resp = client.get("/messages/sync-safe", headers=r_auth, params={"after": bad_cursor})
                assert resp.status_code == 400

            # Unsafe receiver_device_id rejected with 404
            bad_send = client.post(
                "/messages/send-reliable",
                headers=s_auth,
                json={
                    "client_message_id": str(uuid.uuid4()),
                    "receiver_device_id": "bad/device/id",
                    "encrypted_blob": "cipher",
                    "signature": "sig",
                },
            )
            assert bad_send.status_code == 404

            # Dynamic rate limit on /messages/send-reliable and /messages/sync-safe
            monkeypatch.setattr(settings, "RATE_LIMIT_MESSAGE_SEND", "2/minute")
            monkeypatch.setattr(settings, "RATE_LIMIT_MESSAGE_SYNC", "2/minute")
            limiter.reset()

            for _ in range(2):
                ok = client.post(
                    "/messages/send-reliable",
                    headers=s_auth,
                    json={
                        "client_message_id": str(uuid.uuid4()),
                        "receiver_device_id": receiver,
                        "encrypted_blob": "cipher",
                        "signature": "sig",
                    },
                )
                assert ok.status_code == 200
            throttled_send = client.post(
                "/messages/send-reliable",
                headers=s_auth,
                json={
                    "client_message_id": str(uuid.uuid4()),
                    "receiver_device_id": receiver,
                    "encrypted_blob": "cipher",
                    "signature": "sig",
                },
            )
            assert throttled_send.status_code == 429

            limiter.reset()
            assert client.get("/messages/sync-safe", headers=r_auth).status_code == 200
            assert client.get("/messages/sync-safe", headers=r_auth).status_code == 200
            assert client.get("/messages/sync-safe", headers=r_auth).status_code == 429
    finally:
        limiter.reset()


def test_prekey_canonical_base64_and_target_id_and_group_schema_bounds(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    id_raw = priv.public_key().public_bytes_raw()
    spk_raw = os.urandom(32)
    sig_raw = priv.sign(prekeys.X3DH_CURVE25519_PREFIX + spk_raw)

    id_b64 = base64.b64encode(id_raw).decode("ascii")
    spk_b64 = base64.b64encode(spk_raw).decode("ascii")
    sig_b64 = base64.b64encode(sig_raw).decode("ascii")

    assert prekeys.verify_signed_prekey_signature(id_b64, spk_b64, sig_b64) is True
    assert prekeys.verify_signed_prekey_signature(_noncanonical_b64_same_bytes(id_raw), spk_b64, sig_b64) is False
    assert prekeys.verify_signed_prekey_signature(id_b64, _noncanonical_b64_same_bytes(spk_raw), sig_b64) is False
    assert prekeys.verify_signed_prekey_signature(id_b64, spk_b64, _noncanonical_b64_same_bytes(sig_raw)) is False

    # Unsafe target_device_id rejected with 400 on /experimental/prekeys/{id}/claim
    monkeypatch.setattr(settings, "ENABLE_EXPERIMENTAL_PREKEYS", True)
    limiter.reset()
    try:
        with TestClient(app) as client:
            async def seed():
                async with AsyncSessionLocal() as db:
                    u = models.User(username="pk_chk_" + uuid.uuid4().hex[:12], password_hash="unused")
                    db.add(u)
                    await db.flush()
                    d = models.Device(user_id=u.id, device_name="d", public_key=id_b64, fingerprint=uuid.uuid4().hex)
                    db.add(d)
                    await db.commit()
                    return u.id, d.id

            uid, did = client.portal.call(seed)
            hdr = {"Authorization": "Bearer " + create_access_token({"sub": uid, "device_id": did})}
            for unsafe_target in ("bad$device", "id with space", "bad..id"):
                r = client.post(
                    f"/experimental/prekeys/{unsafe_target}/claim",
                    headers=hdr,
                    json={"request_id": str(uuid.uuid4())},
                )
                assert r.status_code == 400
    finally:
        limiter.reset()

    # Group schema bounds reject oversized SenderKeyEntry / GroupInvite inputs
    with pytest.raises(ValidationError):
        schemas.SenderKeyEntry(
            sender_device_id="s1",
            recipient_device_id="r" * 65,
            encrypted_sender_key="enc",
            sender_key_signature="sig",
        )
    with pytest.raises(ValidationError):
        schemas.SenderKeyEntry(
            sender_device_id="s1",
            recipient_device_id="r1",
            encrypted_sender_key="e" * 16385,
            sender_key_signature="sig",
        )
    with pytest.raises(ValidationError):
        schemas.GroupInvite(
            group_id="g" * 65,
            new_member_device_id="d1",
            sender_keys=[],
        )
