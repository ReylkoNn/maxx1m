"""Regression tests for Package #6 backend features:
- Server-side JWT session revocation via Device.session_version & POST /auth/logout
  (single-device logout, only_other_devices logout, password-change secondary session invalidation)
- Device.last_seen updates on login
- ALLOW_LEGACY_WS_QUERY_TOKEN=False enforcement on /messages/ws/{device_id}
- GET /auth/find/{username} hiding deactivated accounts (is_active=False)
- Per-account stored file quotas (MAX_STORED_FILES_PER_USER / MAX_STORED_BYTES_PER_USER)
  and expired file GC (cleanup_expired_uploaded_files + lazy quota reaping)
"""
import base64
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import models
from app.api import files as files_api
from app.config import settings
from app.database import AsyncSessionLocal
from app.main import app
from app.rate_limit import limiter


@pytest.fixture(autouse=True)
def _reset_limiter():
    limiter.reset()
    yield
    limiter.reset()


def _seed_invite(client: TestClient) -> str:
    code = f"INV-{uuid.uuid4().hex[:12].upper()}"

    async def _ins():
        async with AsyncSessionLocal() as db:
            db.add(models.InviteCode(code=code))
            await db.commit()

    client.portal.call(_ins)
    return code


def test_session_logout_only_others_password_invalidation_and_ws_query_policy(monkeypatch):
    with TestClient(app) as client:
        code = _seed_invite(client)
        username = f"sess_{uuid.uuid4().hex[:10]}"
        pw1 = "InitialPass!123"
        pw2 = "RotatedPass!456"

        reg = client.post(
            "/auth/register",
            json={
                "username": username,
                "password": pw1,
                "invite_code": code,
                "device_name": "Desktop",
                "public_key": base64.b64encode(os.urandom(32)).decode("ascii"),
                "fingerprint": f"fp-d1-{uuid.uuid4().hex}",
            },
        )
        assert reg.status_code == 201, reg.text
        dev1 = reg.json()["device_id"]

        time.sleep(0.02)
        login1 = client.post(
            "/auth/login",
            json={"username": username, "password": pw1, "device_id": dev1},
        )
        assert login1.status_code == 200
        tok1_v0 = login1.json()["access_token"]
        auth1_v0 = {"Authorization": f"Bearer {tok1_v0}"}

        # Verify Device.last_seen was refreshed on login
        devs_before = client.get("/auth/devices", headers=auth1_v0).json()
        assert devs_before[0]["created_at"] <= devs_before[0]["last_seen"]

        login2 = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": pw1,
                "device_name": "Laptop",
                "public_key": base64.b64encode(os.urandom(32)).decode("ascii"),
                "fingerprint": f"fp-d2-{uuid.uuid4().hex}",
            },
        )
        assert login2.status_code == 200
        dev2 = login2.json()["device_id"]
        tok2_v0 = login2.json()["access_token"]
        auth2_v0 = {"Authorization": f"Bearer {tok2_v0}"}

        # 1. Single-device logout invalidates tok1_v0 + closes dev1 WS without revoking dev1!
        with client.websocket_connect(f"/messages/ws/{dev1}", headers=auth1_v0) as ws1:
            out_resp = client.post("/auth/logout", headers=auth1_v0)
            assert out_resp.status_code == 200
            assert out_resp.json() == {"status": "ok", "invalidated_devices_count": 1}
            with pytest.raises(WebSocketDisconnect):
                ws1.receive_text()

        # Old token tok1_v0 is dead on both HTTP and WS, while dev2 is unaffected
        assert client.get("/auth/devices", headers=auth1_v0).status_code == 401
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/messages/ws/{dev1}", headers=auth1_v0):
                pass
        assert client.get("/auth/devices", headers=auth2_v0).status_code == 200

        # dev1 is NOT revoked: re-login issues fresh tok1_v1 that works cleanly!
        limiter.reset()
        relogin1 = client.post(
            "/auth/login",
            json={"username": username, "password": pw1, "device_id": dev1},
        )
        assert relogin1.status_code == 200
        tok1_v1 = relogin1.json()["access_token"]
        auth1_v1 = {"Authorization": f"Bearer {tok1_v1}"}
        assert client.get("/auth/devices", headers=auth1_v1).status_code == 200
        assert client.get("/auth/devices", headers=auth1_v0).status_code == 401

        # 2. Logout with only_other_devices=True kicks out dev2 while keeping dev1 logged in!
        with client.websocket_connect(f"/messages/ws/{dev2}", headers=auth2_v0) as ws2:
            out_others = client.post(
                "/auth/logout",
                headers=auth1_v1,
                json={"only_other_devices": True},
            )
            assert out_others.status_code == 200
            assert out_others.json() == {"status": "ok", "invalidated_devices_count": 1}
            with pytest.raises(WebSocketDisconnect):
                ws2.receive_text()

        assert client.get("/auth/devices", headers=auth1_v1).status_code == 200
        assert client.get("/auth/devices", headers=auth2_v0).status_code == 401

        # dev2 re-logs in -> gets tok2_v1; then dev1 changes password WITHOUT revoke_other_devices:
        # tok2_v1 is STILL invalidated immediately so dev2 must re-authenticate with the NEW password!
        limiter.reset()
        tok2_v1 = client.post(
            "/auth/login",
            json={"username": username, "password": pw1, "device_id": dev2},
        ).json()["access_token"]
        auth2_v1 = {"Authorization": f"Bearer {tok2_v1}"}
        assert client.get("/auth/devices", headers=auth2_v1).status_code == 200

        limiter.reset()
        pw_res = client.post(
            "/auth/change-password",
            headers=auth1_v1,
            json={
                "current_password": pw1,
                "new_password": pw2,
                "revoke_other_devices": False,
            },
        )
        assert pw_res.status_code == 200
        assert pw_res.json() == {"status": "ok", "revoked_devices_count": 0}
        assert client.get("/auth/devices", headers=auth1_v1).status_code == 200
        assert client.get("/auth/devices", headers=auth2_v1).status_code == 401

        # 3. ALLOW_LEGACY_WS_QUERY_TOKEN=False blocks ?token=... while allowing Authorization header!
        monkeypatch.setattr(settings, "ALLOW_LEGACY_WS_QUERY_TOKEN", False)
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/messages/ws/{dev1}?token={tok1_v1}"):
                pass
        with client.websocket_connect(f"/messages/ws/{dev1}", headers=auth1_v1):
            pass

        # 4. Deactivating user hides them from GET /auth/find/{username} (unified 404)
        limiter.reset()
        tok2_v2 = client.post(
            "/auth/login",
            json={"username": username, "password": pw2, "device_id": dev2},
        ).json()["access_token"]
        auth2_v2 = {"Authorization": f"Bearer {tok2_v2}"}
        assert client.get(f"/auth/find/{username}", headers=auth2_v2).status_code == 200

        code_peer = _seed_invite(client)
        peer_name = f"peer_{uuid.uuid4().hex[:10]}"
        reg_peer = client.post(
            "/auth/register",
            json={
                "username": peer_name,
                "password": pw1,
                "invite_code": code_peer,
                "device_name": "PeerPC",
                "public_key": base64.b64encode(os.urandom(32)).decode("ascii"),
                "fingerprint": f"fp-peer-{uuid.uuid4().hex}",
            },
        )
        peer_uid = reg_peer.json()["user_id"]
        assert client.get(f"/auth/find/{peer_name}", headers=auth1_v1).status_code == 200

        async def _deactivate_peer():
            async with AsyncSessionLocal() as db:
                u = await db.get(models.User, peer_uid)
                u.is_active = False
                await db.commit()

        client.portal.call(_deactivate_peer)
        assert client.get(f"/auth/find/{peer_name}", headers=auth1_v1).status_code == 404


def test_per_user_file_storage_quotas_and_expired_file_reaping(tmp_path, monkeypatch):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(files_api, "UPLOAD_DIR", str(upload_dir))
    monkeypatch.setattr(settings, "MAX_STORED_FILES_PER_USER", 2)
    monkeypatch.setattr(settings, "MAX_STORED_BYTES_PER_USER", 100)
    monkeypatch.setattr(settings, "UPLOADED_FILE_RETENTION_SECONDS", 60)

    with TestClient(app) as client:
        code = _seed_invite(client)
        username = f"fquota_{uuid.uuid4().hex[:10]}"
        pw = "QuotaPass!123"
        reg = client.post(
            "/auth/register",
            json={
                "username": username,
                "password": pw,
                "invite_code": code,
                "device_name": "Uploader",
                "public_key": base64.b64encode(os.urandom(32)).decode("ascii"),
                "fingerprint": f"fp-uq-{uuid.uuid4().hex}",
            },
        )
        dev_id = reg.json()["device_id"]
        tok = client.post(
            "/auth/login", json={"username": username, "password": pw, "device_id": dev_id}
        ).json()["access_token"]
        auth = {"Authorization": f"Bearer {tok}"}

        f1 = str(uuid.uuid4())
        f2 = str(uuid.uuid4())
        f3 = str(uuid.uuid4())
        f_big = str(uuid.uuid4())

        # Single upload exceeding 100-byte user quota -> 429 before linking blob
        r_big = client.post(f"/files/upload-reliable/{f_big}", headers=auth, content=b"x" * 120)
        assert r_big.status_code == 429
        assert not (upload_dir / f_big).exists()

        # Upload 2 files totaling 80 bytes -> hits MAX_STORED_FILES_PER_USER == 2
        assert client.post(f"/files/upload-reliable/{f1}", headers=auth, content=b"a" * 40).status_code == 200
        assert client.post(f"/files/upload-reliable/{f2}", headers=auth, content=b"b" * 40).status_code == 200

        # Idempotent retry of already-stored f1 STILL succeeds even at full quota!
        assert client.post(f"/files/upload-reliable/{f1}", headers=auth, content=b"a" * 40).status_code == 200

        # 3rd distinct file is rejected with 429
        assert client.post(f"/files/upload-reliable/{f3}", headers=auth, content=b"c" * 10).status_code == 429

        # Age f1 past UPLOADED_FILE_RETENTION_SECONDS -> lazy reaping inside _reserve_upload
        # unlinks f1's blob and admits f3!
        async def _age_f1():
            async with AsyncSessionLocal() as db:
                rec = await db.get(models.FileRecord, f1)
                rec.created_at = datetime.now(timezone.utc) - timedelta(seconds=3600)
                await db.commit()

        client.portal.call(_age_f1)
        assert client.post(f"/files/upload-reliable/{f3}", headers=auth, content=b"c" * 10).status_code == 200
        assert not (upload_dir / f1).exists()
        assert client.get(f"/files/{f1}", headers=auth).status_code == 404
        assert (upload_dir / f3).is_file()

        # Explicit cleanup_expired_uploaded_files prunes remaining expired files & unlinks disk blobs
        async def _age_f2_and_cleanup():
            async with AsyncSessionLocal() as db:
                rec2 = await db.get(models.FileRecord, f2)
                rec2.created_at = datetime.now(timezone.utc) - timedelta(seconds=3600)
                await db.commit()
            async with AsyncSessionLocal() as db:
                return await files_api.cleanup_expired_uploaded_files(db, upload_dir=str(upload_dir))

        res = client.portal.call(_age_f2_and_cleanup)
        assert res["expired_records"] == 1
        assert res["unlinked_blobs"] == 1
        assert not (upload_dir / f2).exists()
        assert (upload_dir / f3).is_file()
