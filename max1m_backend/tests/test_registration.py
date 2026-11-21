"""Registration transaction tests with a temporary real database."""
import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import models
from app.api import auth
from app.database import AsyncSessionLocal
from app.main import app
from app.rate_limit import limiter


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(limiter, "enabled", False)
    with TestClient(app) as client:
        yield client


def registration(code, suffix):
    return {"username": "user_" + suffix[:20], "password": "password123", "invite_code": code,
            "device_name": "test", "public_key": "public-key", "fingerprint": "fp_" + suffix}


def test_invite_claim_is_atomic_under_concurrent_registration(client, monkeypatch):
    code = "invite-" + uuid.uuid4().hex
    async def seed():
        async with AsyncSessionLocal() as db:
            db.add(models.InviteCode(code=code, expires_at=datetime.now(timezone.utc) + timedelta(days=1)))
            await db.commit()
    client.portal.call(seed)

    count = 0
    both_hashing = asyncio.Event()
    async def concurrent_hash(func, password):
        nonlocal count
        count += 1
        if count == 2:
            both_hashing.set()
        await asyncio.wait_for(both_hashing.wait(), timeout=3)
        return "hash"
    monkeypatch.setattr(auth, "run_password_job", concurrent_hash)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(client.post, "/auth/register", json=registration(code, uuid.uuid4().hex)) for _ in range(2)]
        results = [f.result(timeout=10) for f in futures]
    assert sorted(response.status_code for response in results) == [201, 400]
    winner = next(r.json()["user_id"] for r in results if r.status_code == 201)
    async def check():
        async with AsyncSessionLocal() as db:
            invite = await db.get(models.InviteCode, code)
            return invite.is_used, invite.used_by_user_id
    assert client.portal.call(check) == (True, winner)


def test_failed_registration_does_not_consume_invite(client, monkeypatch):
    code = "invite-" + uuid.uuid4().hex
    suffix = uuid.uuid4().hex
    payload = registration(code, suffix)
    async def seed():
        async with AsyncSessionLocal() as db:
            user = models.User(username="existing_" + suffix, password_hash="hash")
            db.add(user)
            await db.flush()
            db.add(models.Device(user_id=user.id, device_name="existing", public_key="key", fingerprint=payload["fingerprint"]))
            db.add(models.InviteCode(code=code, expires_at=datetime.now(timezone.utc) + timedelta(days=1)))
            await db.commit()
    client.portal.call(seed)
    async def fake_hash(*args):
        return "hash"
    monkeypatch.setattr(auth, "run_password_job", fake_hash)
    assert client.post("/auth/register", json=payload).status_code == 400
    async def check():
        async with AsyncSessionLocal() as db:
            invite = await db.get(models.InviteCode, code)
            user = (await db.execute(select(models.User).where(models.User.username == payload["username"]))).scalars().first()
            return invite.is_used, invite.used_by_user_id, user is None
    assert client.portal.call(check) == (False, None, True)


def test_expired_invite_never_hashes_password(client, monkeypatch):
    code = "invite-" + uuid.uuid4().hex
    async def seed():
        async with AsyncSessionLocal() as db:
            db.add(models.InviteCode(code=code, expires_at=datetime.now(timezone.utc) - timedelta(days=1)))
            await db.commit()
    client.portal.call(seed)
    async def should_not_run(*args):
        raise AssertionError("Expired invites must be rejected before hashing")
    monkeypatch.setattr(auth, "run_password_job", should_not_run)
    assert client.post("/auth/register", json=registration(code, uuid.uuid4().hex)).status_code == 400


def test_missing_and_disabled_users_use_dummy_password_check(client, monkeypatch):
    from app import security
    suffix = uuid.uuid4().hex[:20]
    username = "disabled_" + suffix
    async def seed():
        async with AsyncSessionLocal() as db:
            db.add(models.User(username=username, password_hash="hash", is_active=False))
            await db.commit()
    client.portal.call(seed)
    seen = []
    async def fake_verify(func, password, password_hash):
        seen.append(password_hash)
        return True  # Must still reject even if a dummy hash verifies.
    monkeypatch.setattr(auth, "run_password_job", fake_verify)
    assert client.post("/auth/login", json={"username": "missing_" + suffix, "password": "test"}).status_code == 401
    assert client.post("/auth/login", json={"username": username, "password": "test"}).status_code == 401
    assert seen == [security.DUMMY_PASSWORD_HASH, security.DUMMY_PASSWORD_HASH]


def test_real_password_registration_and_login(client):
    code = "invite-" + uuid.uuid4().hex
    payload = registration(code, uuid.uuid4().hex)
    async def seed():
        async with AsyncSessionLocal() as db:
            db.add(models.InviteCode(code=code, expires_at=datetime.now(timezone.utc) + timedelta(days=1)))
            await db.commit()
    client.portal.call(seed)
    result = client.post("/auth/register", json=payload)
    assert result.status_code == 201, result.text
    device_id = result.json()["device_id"]
    response = client.post("/auth/login", json={"username": payload["username"],
                            "password": payload["password"], "device_id": device_id})
    assert response.status_code == 200, response.text
    assert response.json()["device_public_key"] == payload["public_key"]
    token = response.json()["access_token"]
    second_key = "new-" + uuid.uuid4().hex
    new_device = client.post("/auth/login", json={"username": payload["username"], "password": payload["password"],
                             "device_name": "second", "public_key": second_key, "fingerprint": uuid.uuid4().hex})
    assert new_device.status_code == 200 and new_device.json()["device_public_key"] == second_key
    assert new_device.json()["device_id"] != device_id
    assert client.get("/messages/sync-safe", headers={"Authorization": "Bearer " + token}).status_code == 200
    assert client.post("/auth/login", json={"username": payload["username"],
                       "password": "wrongpassword", "device_id": device_id}).status_code == 401


def test_desktop_find_user_accepts_actual_server_response(client, monkeypatch):
    import importlib.util
    import sys
    from pathlib import Path
    from app.security import create_access_token
    pytest.importorskip('requests')
    username = 'user_' + uuid.uuid4().hex[:20]
    async def seed():
        async with AsyncSessionLocal() as db:
            user = models.User(username=username, password_hash='unused')
            db.add(user); await db.flush()
            device = models.Device(user_id=user.id, device_name='test', public_key='key', fingerprint=uuid.uuid4().hex)
            db.add(device); await db.commit()
            return user.id, device.id
    user_id, device_id = client.portal.call(seed)
    base = Path(__file__).resolve().parents[2] / 'max1m_desktop/app'
    spec = importlib.util.spec_from_file_location('app.media_identity', base / 'media_identity.py')
    identity = importlib.util.module_from_spec(spec); spec.loader.exec_module(identity)
    monkeypatch.setitem(sys.modules, 'app.media_identity', identity)
    spec = importlib.util.spec_from_file_location('desktop_lookup_api', base / 'client_api.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    token = create_access_token({'sub': user_id, 'device_id': device_id})
    class Adapter:
        def __init__(self, response): self.response, self.status_code = response, response.status_code
        def iter_content(self, size):
            body = self.response.content
            yield from (body[i:i + size] for i in range(0, len(body), size))
        def close(self): pass
    def get(url, headers, **kwargs):
        assert url.endswith('/auth/find/' + username) and kwargs['stream'] and not kwargs['allow_redirects']
        return Adapter(client.get('/auth/find/' + username, headers=headers))
    monkeypatch.setattr(module.requests, 'get', get)
    ok, data = module.APIClient().find_user('https://node', token, '@' + username)
    assert ok and data['username'] == username and data['devices'][0]['device_id'] == device_id
