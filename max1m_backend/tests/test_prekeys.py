"""Tests for the opt-in prekey transport; not end-to-end ratchet tests."""
import base64
import concurrent.futures
import os
import uuid

import pytest
from fastapi.testclient import TestClient
from app import models
from app.config import settings
from app.database import AsyncSessionLocal
from app.main import app
from app.security import create_access_token


def random_key(n): return base64.b64encode(os.urandom(n)).decode()
def opk(): return {"key_id": str(uuid.uuid4()), "public_key": random_key(32)}
def bundle(keys=None, version=1):
    return {"version": version, "signed_prekey": random_key(32), "signature": random_key(64),
            "one_time_keys": [opk()] if keys is None else keys}


@pytest.fixture
def devices(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_EXPERIMENTAL_PREKEYS", True)
    with TestClient(app) as client:
        async def seed():
            async with AsyncSessionLocal() as db:
                user = models.User(username="prekey_" + uuid.uuid4().hex, password_hash="unused")
                db.add(user)
                await db.flush()
                devices = [models.Device(user_id=user.id, device_name=str(i), public_key=random_key(32), fingerprint=uuid.uuid4().hex) for i in range(3)]
                db.add_all(devices)
                await db.commit()
                return user.id, [device.id for device in devices]
        user_id, ids = client.portal.call(seed)
        def auth(device): return {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": device})}
        yield client, ids, auth


def test_disabled_default_and_authentication(devices, monkeypatch):
    client, ids, auth = devices
    monkeypatch.setattr(settings, "ENABLE_EXPERIMENTAL_PREKEYS", False)
    assert client.put('/experimental/prekeys/bundle', headers=auth(ids[0]), json=bundle()).status_code == 503
    assert client.post(f'/experimental/prekeys/{ids[0]}/claim', headers=auth(ids[1]), json={"request_id": str(uuid.uuid4())}).status_code == 503
    assert client.put('/experimental/prekeys/bundle', json=bundle()).status_code == 401
    from app.config import Settings
    monkeypatch.delenv("ENABLE_EXPERIMENTAL_PREKEYS", raising=False)
    assert not Settings(SECRET_KEY="test", _env_file=None).ENABLE_EXPERIMENTAL_PREKEYS


def test_claim_retry_and_rotation_preserves_snapshot(devices):
    client, (target, sender, other), auth = devices
    keys = [opk(), opk()]
    original = bundle(keys)
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=original).json() == {"available": 2}
    claim = {"request_id": str(uuid.uuid4())}
    url = f'/experimental/prekeys/{target}/claim'
    first = client.post(url, headers=auth(sender), json=claim)
    assert first.status_code == 200, first.text
    snapshot = first.json()
    assert snapshot['signed_prekey'] == original['signed_prekey']
    assert client.post(url, headers=auth(sender), json=claim).json() == snapshot
    assert client.post(f'/experimental/prekeys/{other}/claim', headers=auth(sender), json=claim).status_code == 409
    new = bundle([], version=2)
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=new).status_code == 200
    assert client.post(url, headers=auth(sender), json=claim).json() == snapshot
    second = client.post(url, headers=auth(other), json={"request_id": str(uuid.uuid4())})
    assert second.status_code == 200
    assert second.json()['one_time_key'] != snapshot['one_time_key']
    assert second.json()['signed_prekey'] == new['signed_prekey']
    assert client.post(url, headers=auth(sender), json={"request_id": str(uuid.uuid4())}).status_code == 409
    # Re-uploading claimed OPKs is idempotent, never makes them available again.
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json={**new, 'one_time_keys': keys}).json() == {"available": 0}
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=original).status_code == 409


def test_batch_conflicts_are_atomic_and_invalid_data_rejected(devices):
    client, (target, sender, _), auth = devices
    key = opk()
    first = bundle([key])
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=first).status_code == 200
    for bad in ([key, key], [{**key, 'public_key': random_key(32)}], [{**opk(), 'public_key': key['public_key']}]):
        response = client.put('/experimental/prekeys/bundle', headers=auth(target), json={**first, 'one_time_keys': bad})
        assert response.status_code in (409, 422)
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json={**first, 'signature': 'not-a-valid-signature'}).status_code == 422
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json={**first, 'signed_prekey': 'A' * 44}).status_code == 422
    assert client.post(f'/experimental/prekeys/{target}/claim', headers=auth(sender), json={"request_id": str(uuid.uuid4())}).json()['one_time_key'] == key
    assert client.post(f'/experimental/prekeys/{target}/claim', headers=auth(sender), json={"request_id": str(uuid.uuid4())}).status_code == 409


def test_concurrent_claims_never_return_same_key(devices):
    client, (target, sender, _), auth = devices
    keys = [opk() for _ in range(12)]
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=bundle(keys)).status_code == 200
    url = f'/experimental/prekeys/{target}/claim'
    requests = [{"request_id": str(uuid.uuid4())} for _ in keys]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda body: client.post(url, headers=auth(sender), json=body), requests))
    assert [r.status_code for r in responses] == [200] * len(keys), [r.text for r in responses]
    claimed = [r.json()['one_time_key']['key_id'] for r in responses]
    assert len(set(claimed)) == len(keys)
    # Concurrent retries of the same request must all return the same key.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        retries = list(pool.map(lambda _: client.post(url, headers=auth(sender), json=requests[0]), range(6)))
    assert all(r.status_code == 200 and r.json() == responses[0].json() for r in retries)


def test_revoke_owner_or_requester_blocks_claim_and_publication(devices):
    client, (target, sender, other), auth = devices
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=bundle([opk(), opk()])).status_code == 200
    async def revoke(device_id):
        async with AsyncSessionLocal() as db:
            device = await db.get(models.Device, device_id)
            device.is_revoked = True
            await db.commit()
    client.portal.call(revoke, sender)
    url = f'/experimental/prekeys/{target}/claim'
    assert client.post(url, headers=auth(sender), json={"request_id": str(uuid.uuid4())}).status_code == 401
    assert client.put('/experimental/prekeys/bundle', headers=auth(sender), json=bundle()).status_code == 401
    client.portal.call(revoke, target)
    assert client.post(url, headers=auth(other), json={"request_id": str(uuid.uuid4())}).status_code == 404
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=bundle()).status_code == 401


def test_prekey_conflict_rolls_back_signed_key_rotation_and_quota(devices, monkeypatch):
    from app.api import prekeys
    client, (target, sender, _), auth = devices
    oldkey = opk()
    old = bundle([oldkey])
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=old).status_code == 200
    replacement = bundle([{**oldkey, 'public_key': random_key(32)}], version=2)
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=replacement).status_code == 409
    monkeypatch.setattr(prekeys, 'MAX_AVAILABLE', 1)
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=bundle([opk()], version=2)).status_code == 409
    claim = client.post(f'/experimental/prekeys/{target}/claim', headers=auth(sender), json={'request_id': str(uuid.uuid4())})
    assert claim.status_code == 200 and claim.json()['signed_prekey'] == old['signed_prekey']


def test_bundle_forbids_unknown_fields(devices):
    client, (target, sender, _), auth = devices
    data = bundle()
    data['private_key'] = 'should never be sent'
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=data).status_code == 422
    request = {'request_id': str(uuid.uuid4()), 'extra': 'unexpected'}
    assert client.post(f'/experimental/prekeys/{target}/claim', headers=auth(sender), json=request).status_code == 422


def test_concurrent_first_claim_same_id_uses_one_key(devices):
    client, (target, sender, _), auth = devices
    assert client.put('/experimental/prekeys/bundle', headers=auth(target), json=bundle([opk(), opk()])).status_code == 200
    body = {'request_id': str(uuid.uuid4())}
    url = f'/experimental/prekeys/{target}/claim'
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        answers = list(pool.map(lambda _: client.post(url, headers=auth(sender), json=body), range(6)))
    assert all(r.status_code == 200 and r.json() == answers[0].json() for r in answers)
    # Only one of the two keys was used.
    second = client.post(url, headers=auth(sender), json={'request_id': str(uuid.uuid4())})
    assert second.status_code == 200 and second.json()['one_time_key'] != answers[0].json()['one_time_key']
    assert client.post(url, headers=auth(sender), json={'request_id': str(uuid.uuid4())}).status_code == 409
