"""Authorization regressions against a real temporary SQLite database."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from jose import jwt

from app import models
from app.config import settings
from app.database import AsyncSessionLocal
from app.main import app
from app.security import create_access_token
from app.api import messages


@pytest.fixture
def account():
    with TestClient(app) as client:
        async def create():
            async with AsyncSessionLocal() as db:
                user = models.User(username="auth_user", password_hash="unused")
                db.add(user)
                await db.flush()
                device = models.Device(user_id=user.id, device_name="test", public_key="key", fingerprint="auth-fp")
                db.add(device)
                await db.commit()
                return user.id, device.id
        user_id, device_id = client.portal.call(create)
        yield client, user_id, device_id
        async def cleanup():
            async with AsyncSessionLocal() as db:
                device = await db.get(models.Device, device_id)
                user = await db.get(models.User, user_id)
                if device:
                    await db.delete(device)
                if user:
                    await db.delete(user)
                await db.commit()
        client.portal.call(cleanup)


def headers(user_id, device_id):
    return {"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": device_id})}


def test_http_requires_valid_active_owner_and_device(account):
    client, user_id, device_id = account
    assert client.get("/messages/sync-safe", headers=headers(user_id, device_id)).status_code == 200
    assert client.get("/messages/sync", headers=headers("wrong-user", device_id)).status_code == 401
    assert client.get("/messages/sync", headers=headers(user_id, "missing-device")).status_code == 401
    no_exp = jwt.encode({"sub": user_id, "device_id": device_id}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    assert client.get("/messages/sync", headers={"Authorization": "Bearer " + no_exp}).status_code == 401
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/messages/ws/{device_id}?token={no_exp}"):
            pass
    no_subject = create_access_token({"device_id": device_id})
    assert client.get("/files/missing", headers={"Authorization": "Bearer " + no_subject}).status_code == 401
    expired = create_access_token({"sub": user_id, "device_id": device_id}, timedelta(seconds=-10))
    assert client.get("/messages/sync", headers={"Authorization": "Bearer " + expired}).status_code == 401

    async def revoke():
        async with AsyncSessionLocal() as db:
            device = await db.get(models.Device, device_id)
            device.is_revoked = True
            await db.commit()
    client.portal.call(revoke)
    assert client.get("/messages/sync", headers=headers(user_id, device_id)).status_code == 401
    token = create_access_token({"sub": user_id, "device_id": device_id})
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/messages/ws/{device_id}?token={token}"):
            pass


def test_disabled_user_is_denied(account):
    client, user_id, device_id = account
    async def disable():
        async with AsyncSessionLocal() as db:
            user = await db.get(models.User, user_id)
            user.is_active = False
            await db.commit()
    client.portal.call(disable)
    assert client.get("/messages/sync", headers=headers(user_id, device_id)).status_code == 401
    async def username():
        async with AsyncSessionLocal() as db:
            return (await db.get(models.User, user_id)).username
    login = client.post("/auth/login", json={"username": client.portal.call(username),
                                             "password": "irrelevant", "device_id": device_id})
    assert login.status_code == 401
    token = create_access_token({"sub": user_id, "device_id": device_id})
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/messages/ws/{device_id}?token={token}"):
            pass


def test_open_websocket_is_closed_after_revocation(account, monkeypatch):
    client, user_id, device_id = account
    monkeypatch.setattr(messages, "WS_AUTH_CHECK_INTERVAL", 0.05)
    token = create_access_token({"sub": user_id, "device_id": device_id})
    with client.websocket_connect(f"/messages/ws/{device_id}?token={token}") as websocket:
        async def revoke():
            async with AsyncSessionLocal() as db:
                device = await db.get(models.Device, device_id)
                device.is_revoked = True
                await db.commit()
        client.portal.call(revoke)
        with pytest.raises(WebSocketDisconnect) as exc:
            websocket.receive_json()
        assert exc.value.code == 1008


def test_open_websocket_is_closed_when_token_expires(account, monkeypatch):
    client, user_id, device_id = account
    monkeypatch.setattr(messages, "WS_AUTH_CHECK_INTERVAL", 0.05)
    token = create_access_token({"sub": user_id, "device_id": device_id}, timedelta(seconds=1))
    with client.websocket_connect(f"/messages/ws/{device_id}?token={token}") as websocket:
        with pytest.raises(WebSocketDisconnect) as exc:
            websocket.receive_json()
        assert exc.value.code == 1008


def test_safe_sync_retries_until_ack_and_respects_recipient(account):
    from sqlalchemy import select

    client, user_id, device_id = account
    async def seed():
        async with AsyncSessionLocal() as db:
            other = models.Device(user_id=user_id, device_name="other", public_key="key", fingerprint="other-fp")
            db.add(other)
            await db.flush()
            for index in range(103):
                db.add(models.Message(id=f"message-{index:03}", sender_device_id=other.id,
                                      receiver_device_id=device_id, encrypted_blob="ciphertext", signature="signature"))
            db.add(models.Message(id="other-message", sender_device_id=device_id,
                                  receiver_device_id=other.id, encrypted_blob="ciphertext", signature="signature"))
            await db.commit()
            return other.id
    other_id = client.portal.call(seed)
    own_headers = headers(user_id, device_id)
    first = client.get("/messages/sync-safe", headers=own_headers).json()
    assert len(first) == 100
    assert first == client.get("/messages/sync-safe", headers=own_headers).json()
    assert client.post("/messages/ack", headers=own_headers,
                       json={"message_ids": [first[0]["id"], "other-message"]}).status_code == 200
    # Acks are idempotent, and cannot change another device's queue.
    assert client.post("/messages/ack", headers=own_headers,
                       json={"message_ids": [first[0]["id"]]}).status_code == 200
    assert client.get("/messages/sync-safe", headers=headers(user_id, other_id)).json()[0]["id"] == "other-message"
    assert first[0]["id"] not in [m["id"] for m in client.get("/messages/sync-safe", headers=own_headers).json()]
    # A cursor remains usable after its own message was acknowledged.
    assert client.post("/messages/ack", headers=own_headers,
                       json={"message_ids": [first[-1]["id"]]}).status_code == 200
    next_page = client.get("/messages/sync-safe", headers=own_headers, params={"after": first[-1]["id"]}).json()
    assert len(next_page) == 3
    assert client.get("/messages/sync-safe", headers=own_headers, params={"after": "other-message"}).status_code == 400
    assert client.post("/messages/ack", headers=own_headers, json={"message_ids": []}).status_code == 422
    assert client.post("/messages/ack", headers=own_headers, json={"message_ids": ["x"] * 101}).status_code == 422

    async def cleanup():
        async with AsyncSessionLocal() as db:
            from sqlalchemy import delete
            await db.execute(delete(models.Message).where(models.Message.receiver_device_id.in_([device_id, other_id])))
            await db.execute(delete(models.Device).where(models.Device.id == other_id))
            await db.commit()
    client.portal.call(cleanup)


def test_websocket_header_auth_and_no_credential_url(account):
    client, user_id, device_id = account
    token = create_access_token({"sub": user_id, "device_id": device_id})
    with client.websocket_connect(f"/messages/ws/{device_id}", headers={"Authorization": "Bearer " + token}) as ws:
        ws.send_json({"type": "call_offer", "to_device_id": device_id})
        assert ws.receive_json()["type"] == "call_offer"
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/messages/ws/{device_id}"):
            pass
    # An invalid header must not silently fall back to a valid query token.
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/messages/ws/{device_id}?token={token}", headers={"Authorization": "Basic invalid"}):
            pass


def test_personal_message_rejects_oversized_ciphertext(account):
    client, user_id, device_id = account
    payload = {"receiver_device_id": device_id, "encrypted_blob": "x" * (1024 * 1024 + 1), "signature": "sig"}
    response = client.post("/messages/send", headers=headers(user_id, device_id), json=payload)
    assert response.status_code == 422


def test_reliable_send_is_idempotent_and_scoped_to_sender(account):
    import uuid
    client, user_id, sender = account
    async def seed_recipient():
        async with AsyncSessionLocal() as db:
            device = models.Device(user_id=user_id, device_name="receiver", public_key="key", fingerprint="reliable-fp")
            db.add(device)
            await db.commit()
            return device.id
    receiver = client.portal.call(seed_recipient)
    mid = str(uuid.uuid4())
    payload = {"client_message_id": mid, "receiver_device_id": receiver,
               "encrypted_blob": "ciphertext", "signature": "sig"}
    first = client.post("/messages/send-reliable", headers=headers(user_id, sender), json=payload)
    assert first.status_code == 200, first.text
    second = client.post("/messages/send-reliable", headers=headers(user_id, sender), json=payload)
    assert second.status_code == 200 and second.json()["id"] == first.json()["id"] == mid
    assert client.post("/messages/send-reliable", headers=headers(user_id, sender),
                       json={**payload, "encrypted_blob": "different"}).status_code == 409
    assert client.post("/messages/send-reliable", headers=headers(user_id, receiver), json=payload).status_code == 409
    pending = client.get("/messages/sync-safe", headers=headers(user_id, receiver)).json()
    assert [m["id"] for m in pending] == [mid]
    assert client.post("/messages/send-reliable", headers=headers(user_id, sender),
                       json={**payload, "client_message_id": "not-a-uuid"}).status_code == 422
    async def cleanup():
        from sqlalchemy import delete
        async with AsyncSessionLocal() as db:
            await db.execute(delete(models.Message).where(models.Message.id == mid))
            await db.execute(delete(models.Device).where(models.Device.id == receiver))
            await db.commit()
    client.portal.call(cleanup)


def test_concurrent_reliable_retries_create_one_row(account):
    import uuid
    from concurrent.futures import ThreadPoolExecutor
    client, user_id, device_id = account
    mid = str(uuid.uuid4())
    payload = {"client_message_id": mid, "receiver_device_id": device_id,
               "encrypted_blob": "ciphertext", "signature": "sig"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(client.post, "/messages/send-reliable", headers=headers(user_id, device_id), json=payload) for _ in range(2)]
        responses = [future.result(timeout=10) for future in futures]
    assert [response.status_code for response in responses] == [200, 200]
    assert all(response.json()["id"] == mid for response in responses)
    assert [m["id"] for m in client.get("/messages/sync-safe", headers=headers(user_id, device_id)).json()] == [mid]
    async def cleanup():
        from sqlalchemy import delete
        async with AsyncSessionLocal() as db:
            await db.execute(delete(models.Message).where(models.Message.id == mid))
            await db.commit()
    client.portal.call(cleanup)


def test_ack_rechecks_revoked_device_and_disabled_user_under_write_lock(account):
    """Model revocation between authentication dependency and endpoint."""
    client,user_id,device_id=account
    async def seed():
        async with AsyncSessionLocal() as db:
            db.add(models.Message(id='pending-race',sender_device_id=device_id,
                                  receiver_device_id=device_id,encrypted_blob='cipher',signature='sig'))
            await db.commit()
    client.portal.call(seed)
    async def set_state(*,revoked,active):
        async with AsyncSessionLocal() as db:
            (await db.get(models.Device,device_id)).is_revoked=revoked
            (await db.get(models.User,user_id)).is_active=active
            await db.commit()
    async def pending():
        async with AsyncSessionLocal() as db:
            return not (await db.get(models.Message,'pending-race')).is_delivered
    # Bypass only the dependency to reproduce a previously successful auth check.
    app.dependency_overrides[messages.get_current_device_id]=lambda:device_id
    try:
        for revoked,active in [(True,True),(False,False)]:
            client.portal.call(lambda: set_state(revoked=revoked,active=active))
            response=client.post('/messages/ack',json={'message_ids':['pending-race']})
            assert response.status_code==401 and client.portal.call(pending)
        client.portal.call(lambda: set_state(revoked=False,active=True))
        assert client.post('/messages/ack',json={'message_ids':['pending-race']}).status_code==200
        assert not client.portal.call(pending)
    finally:
        app.dependency_overrides.pop(messages.get_current_device_id,None)
        async def cleanup_message():
            async with AsyncSessionLocal() as db:
                message=await db.get(models.Message,'pending-race')
                if message: await db.delete(message)
                await db.commit()
        client.portal.call(cleanup_message)


def test_ack_rejects_empty_and_oversized_ids(account):
    client,user,device=account
    for msg_id in ('','x'*65):
        assert client.post('/messages/ack',headers=headers(user,device),json={'message_ids':[msg_id]}).status_code==422
