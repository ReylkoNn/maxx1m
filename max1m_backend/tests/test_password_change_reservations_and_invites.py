"""Regression tests for Package #4 backend features:
- POST /auth/change-password (Argon2id check/update, 422 secret redaction, atomic revoke_other_devices + WS close)
- Stale UploadReservation reaping (preserving published blobs) + DELETE /files/upload-reliable/{file_id}
- Ed25519 signature verification for experimental prekey bundles
- Hardened create_invite.py functions & CLI
"""
import base64
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import create_invite
from app import models
from app.api import files as files_api
from app.config import settings
from app.database import AsyncSessionLocal
from app.main import app
from app.rate_limit import limiter
from app.security import create_access_token


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    limiter.reset()
    yield
    limiter.reset()


def _seed_invite(client: TestClient, code: str | None = None) -> str:
    invite_code = code or f"INV-{uuid.uuid4().hex[:12].upper()}"

    async def _insert():
        async with AsyncSessionLocal() as db:
            db.add(models.InviteCode(code=invite_code))
            await db.commit()

    client.portal.call(_insert)
    return invite_code


def test_change_password_redacts_422_and_atomically_revokes_other_devices():
    with TestClient(app) as client:
        code = _seed_invite(client)
        username = f"pwuser_{uuid.uuid4().hex[:10]}"
        old_pw = "OldStrongPass!123"
        new_pw = "NewStrongPass!456"

        reg = client.post(
            "/auth/register",
            json={
                "username": username,
                "password": old_pw,
                "invite_code": code,
                "device_name": "Primary Desktop",
                "public_key": base64.b64encode(os.urandom(32)).decode("ascii"),
                "fingerprint": f"fp1-{uuid.uuid4().hex}",
            },
        )
        assert reg.status_code == 201, reg.text
        dev1_id = reg.json()["device_id"]

        login1 = client.post(
            "/auth/login",
            json={"username": username, "password": old_pw, "device_id": dev1_id},
        )
        assert login1.status_code == 200
        tok1 = login1.json()["access_token"]
        auth1 = {"Authorization": f"Bearer {tok1}"}

        login2 = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": old_pw,
                "device_name": "Secondary Laptop",
                "public_key": base64.b64encode(os.urandom(32)).decode("ascii"),
                "fingerprint": f"fp2-{uuid.uuid4().hex}",
            },
        )
        assert login2.status_code == 200
        dev2_id = login2.json()["device_id"]
        tok2 = login2.json()["access_token"]
        auth2 = {"Authorization": f"Bearer {tok2}"}

        # 422 validation error must never reflect secret password strings.
        leaked_secret = "short!"
        bad_422 = client.post(
            "/auth/change-password",
            headers=auth1,
            json={"current_password": old_pw, "new_password": leaked_secret},
        )
        assert bad_422.status_code == 422
        assert bad_422.json() == {"detail": "Invalid authentication request"}
        assert leaked_secret not in bad_422.text
        assert old_pw not in bad_422.text

        # Wrong current password -> 401
        wrong_cur = client.post(
            "/auth/change-password",
            headers=auth1,
            json={"current_password": "WrongPassword999", "new_password": new_pw},
        )
        assert wrong_cur.status_code == 401

        # Same password -> 400
        same_pw = client.post(
            "/auth/change-password",
            headers=auth1,
            json={"current_password": old_pw, "new_password": old_pw},
        )
        assert same_pw.status_code == 400

        limiter.reset()
        # Open a live WebSocket on dev2 and verify change-password(revoke_other_devices=True)
        # closes dev2's socket and revokes dev2 atomically while keeping dev1 active.
        with client.websocket_connect(
            f"/messages/ws/{dev2_id}",
            headers={"Authorization": f"Bearer {tok2}"},
        ) as ws2:
            changed = client.post(
                "/auth/change-password",
                headers=auth1,
                json={
                    "current_password": old_pw,
                    "new_password": new_pw,
                    "revoke_other_devices": True,
                },
            )
            assert changed.status_code == 200, changed.text
            assert changed.json() == {"status": "ok", "revoked_devices_count": 1}

            with pytest.raises(WebSocketDisconnect):
                ws2.receive_text()

        # dev1 remains authorized; dev2 is revoked.
        assert client.get("/auth/devices", headers=auth1).status_code == 200
        assert client.get("/auth/devices", headers=auth2).status_code == 401

        limiter.reset()
        # Old password no longer works; new password works for dev1, while dev2 gets 403.
        assert client.post(
            "/auth/login",
            json={"username": username, "password": old_pw, "device_id": dev1_id},
        ).status_code == 401
        assert client.post(
            "/auth/login",
            json={"username": username, "password": new_pw, "device_id": dev2_id},
        ).status_code == 403
        relogin = client.post(
            "/auth/login",
            json={"username": username, "password": new_pw, "device_id": dev1_id},
        )
        assert relogin.status_code == 200


def test_stale_upload_reservation_reaper_and_explicit_cancel(tmp_path, monkeypatch):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(files_api, "UPLOAD_DIR", str(upload_dir))
    monkeypatch.setattr(settings, "MAX_INCOMPLETE_UPLOADS_PER_DEVICE", 2)
    monkeypatch.setattr(settings, "UPLOAD_RESERVATION_TTL_SECONDS", 60)

    with TestClient(app) as client:
        async def _seed_devices():
            async with AsyncSessionLocal() as db:
                u = models.User(username=f"up_{uuid.uuid4().hex[:10]}", password_hash="unused")
                db.add(u)
                await db.flush()
                d1 = models.Device(
                    user_id=u.id,
                    device_name="Dev1",
                    public_key=base64.b64encode(os.urandom(32)).decode("ascii"),
                    fingerprint=f"fp-{uuid.uuid4().hex}",
                )
                d2 = models.Device(
                    user_id=u.id,
                    device_name="Dev2",
                    public_key=base64.b64encode(os.urandom(32)).decode("ascii"),
                    fingerprint=f"fp-{uuid.uuid4().hex}",
                )
                db.add_all([d1, d2])
                await db.commit()
                return u.id, d1.id, d2.id

        user_id, dev1, dev2 = client.portal.call(_seed_devices)
        auth1 = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": dev1})}
        auth2 = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": dev2})}

        stale_no_blob = str(uuid.uuid4())
        stale_with_blob = str(uuid.uuid4())
        fresh_cancel_id = str(uuid.uuid4())
        (upload_dir / stale_with_blob).write_bytes(b"linked-before-crash")

        old_ts = datetime.now(timezone.utc) - timedelta(hours=2)

        async def _seed_reservations():
            async with AsyncSessionLocal() as db:
                db.add_all([
                    models.UploadReservation(file_id=stale_no_blob, device_id=dev1, created_at=old_ts),
                    models.UploadReservation(file_id=stale_with_blob, device_id=dev1, created_at=old_ts),
                ])
                await db.commit()

        client.portal.call(_seed_reservations)

        # At limit=2, a new upload triggers lazy reaping inside _reserve_upload:
        # stale_no_blob is reaped, while stale_with_blob is preserved!
        new_file_id = str(uuid.uuid4())
        up_resp = client.post(
            f"/files/upload-reliable/{new_file_id}",
            headers=auth1,
            content=b"ciphertext-payload",
        )
        assert up_resp.status_code == 200, up_resp.text

        # Published blob reservation MUST remain intact and reject DELETE cancellation (409).
        assert client.delete(
            f"/files/upload-reliable/{stale_with_blob}", headers=auth1
        ).status_code == 409

        # Completed FileRecord cannot be cancelled either (409).
        assert client.delete(
            f"/files/upload-reliable/{new_file_id}", headers=auth1
        ).status_code == 409

        # Insert a fresh unpublished reservation and test explicit DELETE cancellation.
        async def _seed_fresh():
            async with AsyncSessionLocal() as db:
                db.add(models.UploadReservation(file_id=fresh_cancel_id, device_id=dev1))
                await db.commit()

        client.portal.call(_seed_fresh)

        # Foreign device cannot cancel dev1's reservation -> 409.
        assert client.delete(
            f"/files/upload-reliable/{fresh_cancel_id}", headers=auth2
        ).status_code == 409
        # Bad UUID -> 400.
        assert client.delete(
            "/files/upload-reliable/not-a-uuid", headers=auth1
        ).status_code == 400
        # Oversized body on DELETE is bounded by GeneralBodyLimitMiddleware -> 413.
        assert client.request(
            "DELETE",
            f"/files/upload-reliable/{fresh_cancel_id}",
            headers={**auth1, "Content-Length": str(3 * 1024 * 1024)},
            content=b"x",
        ).status_code == 413

        # Owning device cancels unpublished reservation -> 200, second call -> 404.
        cancel_ok = client.delete(
            f"/files/upload-reliable/{fresh_cancel_id}", headers=auth1
        )
        assert cancel_ok.status_code == 200
        assert cancel_ok.json() == {"status": "cancelled", "file_id": fresh_cancel_id}
        assert client.delete(
            f"/files/upload-reliable/{fresh_cancel_id}", headers=auth1
        ).status_code == 404


def test_experimental_prekeys_ed25519_signature_verification(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_EXPERIMENTAL_PREKEYS", True)
    signing_key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(signing_key.public_key().public_bytes_raw()).decode("ascii")

    with TestClient(app) as client:
        async def _seed():
            async with AsyncSessionLocal() as db:
                user = models.User(username=f"spk_{uuid.uuid4().hex[:10]}", password_hash="unused")
                db.add(user)
                await db.flush()
                dev = models.Device(
                    user_id=user.id,
                    device_name="Ed25519Dev",
                    public_key=pub_b64,
                    fingerprint=f"fp-{uuid.uuid4().hex}",
                )
                db.add(dev)
                await db.commit()
                return user.id, dev.id

        user_id, dev_id = client.portal.call(_seed)
        auth = {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": dev_id})}

        spk1 = os.urandom(32)
        spk1_b64 = base64.b64encode(spk1).decode("ascii")
        forged_sig = base64.b64encode(os.urandom(64)).decode("ascii")

        # Explicit verify_signature=True rejects forged signature.
        bad = client.put(
            "/experimental/prekeys/bundle",
            headers=auth,
            json={
                "version": 1,
                "signed_prekey": spk1_b64,
                "signature": forged_sig,
                "one_time_keys": [],
                "verify_signature": True,
            },
        )
        assert bad.status_code == 400

        # Domain-separated X3DH signature ("curve_25519:" + spk) is accepted.
        x3dh_sig = base64.b64encode(signing_key.sign(b"curve_25519:" + spk1)).decode("ascii")
        ok1 = client.put(
            "/experimental/prekeys/bundle",
            headers=auth,
            json={
                "version": 1,
                "signed_prekey": spk1_b64,
                "signature": x3dh_sig,
                "one_time_keys": [],
                "verify_signature": True,
            },
        )
        assert ok1.status_code == 200

        # Server-wide REQUIRE_SIGNED_PREKEY_VERIFICATION=True enforces check even without client flag,
        # and raw 32-byte Ed25519 signatures over spk are also accepted.
        monkeypatch.setattr(settings, "REQUIRE_SIGNED_PREKEY_VERIFICATION", True)
        spk2 = os.urandom(32)
        spk2_b64 = base64.b64encode(spk2).decode("ascii")
        assert client.put(
            "/experimental/prekeys/bundle",
            headers=auth,
            json={
                "version": 2,
                "signed_prekey": spk2_b64,
                "signature": forged_sig,
                "one_time_keys": [],
            },
        ).status_code == 400

        raw_sig = base64.b64encode(signing_key.sign(spk2)).decode("ascii")
        assert client.put(
            "/experimental/prekeys/bundle",
            headers=auth,
            json={
                "version": 2,
                "signed_prekey": spk2_b64,
                "signature": raw_sig,
                "one_time_keys": [],
            },
        ).status_code == 200


def test_create_invite_module_lifecycle():
    with TestClient(app) as client:
        # Perpetual and standard invites both appear in list_active_invites.
        code_std = client.portal.call(lambda: create_invite.create_new_invite(7, ensure_schema=False))
        code_inf = client.portal.call(lambda: create_invite.create_new_invite(None, ensure_schema=False))
        expired_code = f"EXP-{uuid.uuid4().hex[:10].upper()}"
        used_expired_code = f"USED-{uuid.uuid4().hex[:10].upper()}"

        async def _seed_special_invites():
            past = datetime.now(timezone.utc) - timedelta(days=2)
            async with AsyncSessionLocal() as db:
                db.add_all([
                    models.InviteCode(code=expired_code, is_used=False, expires_at=past),
                    models.InviteCode(code=used_expired_code, is_used=True, expires_at=past),
                ])
                await db.commit()

        client.portal.call(_seed_special_invites)

        active = client.portal.call(lambda: create_invite.list_active_invites(ensure_schema=False))
        assert code_std in active
        assert code_inf in active
        assert expired_code not in active

        # Invalid TTL rejected cleanly.
        with pytest.raises(ValueError):
            client.portal.call(lambda: create_invite.create_new_invite(0, ensure_schema=False))

        # Revoke removes unused invite, refuses to delete used invite audit record.
        assert client.portal.call(lambda: create_invite.revoke_invite(code_std, ensure_schema=False)) is True
        assert client.portal.call(lambda: create_invite.revoke_invite(code_std, ensure_schema=False)) is False
        assert client.portal.call(lambda: create_invite.revoke_invite(used_expired_code, ensure_schema=False)) is False

        # Purge removes expired unused invites, preserving perpetual and used invites.
        removed = client.portal.call(lambda: create_invite.purge_expired_invites(ensure_schema=False))
        assert removed >= 1
        active_after = client.portal.call(lambda: create_invite.list_active_invites(ensure_schema=False))
        assert code_inf in active_after

        async def _check_used_preserved():
            async with AsyncSessionLocal() as db:
                return await db.get(models.InviteCode, used_expired_code) is not None

        assert client.portal.call(_check_used_preserved) is True
