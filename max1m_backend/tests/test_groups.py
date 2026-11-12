"""Integration tests for group membership and durable delivery queues."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app import models
from app.database import AsyncSessionLocal
from app.main import app
from app.security import create_access_token
from app.config import settings


def auth(user_id, device_id):
    token = create_access_token({"sub": user_id, "device_id": device_id})
    return {"Authorization": "Bearer " + token}


@pytest.fixture
def group(monkeypatch):
    # Existing regression coverage exercises the explicitly insecure migration mode.
    monkeypatch.setattr(settings, "ALLOW_INSECURE_LEGACY_GROUPS", True)
    with TestClient(app) as client:
        async def seed():
            suffix = uuid.uuid4().hex
            async with AsyncSessionLocal() as db:
                user = models.User(username="group_" + suffix, password_hash="unused")
                db.add(user)
                await db.flush()
                devices = []
                for name in ("owner", "member", "other"):
                    device = models.Device(user_id=user.id, device_name=name, public_key="key", fingerprint=name + suffix)
                    db.add(device)
                    devices.append(device)
                await db.flush()
                owner, member, other = devices
                group = models.Group(name="test", created_by_device_id=owner.id)
                db.add(group)
                await db.flush()
                db.add_all([
                    models.GroupMember(group_id=group.id, device_id=owner.id, role="owner"),
                    models.GroupMember(group_id=group.id, device_id=member.id, role="member"),
                    models.SenderKeyDistribution(group_id=group.id, sender_device_id=owner.id,
                        recipient_device_id=member.id, encrypted_sender_key="key", sender_key_signature="signature"),
                    models.SenderKeyDistribution(group_id=group.id, sender_device_id=member.id,
                        recipient_device_id=owner.id, encrypted_sender_key="key2", sender_key_signature="signature2"),
                ])
                await db.commit()
                return user.id, group.id, owner.id, member.id, other.id
        ids = client.portal.call(seed)
        yield (client, *ids)


def send_payload(group_id):
    return {"group_id": group_id, "encrypted_blob": "encrypted", "signature": "sig", "sender_key_id": "keyid", "chain_index": 0}


def test_online_group_delivery_remains_pending_until_recipient_ack(group):
    client, user, group_id, owner, member, other = group
    owner_headers, member_headers, other_headers = (auth(user, d) for d in (owner, member, other))
    assert client.post("/groups/send", headers=other_headers, json=send_payload(group_id)).status_code == 403
    token = create_access_token({"sub": user, "device_id": member})
    with client.websocket_connect(f"/messages/ws/{member}?token={token}") as ws:
        response = client.post("/groups/send", headers=owner_headers, json=send_payload(group_id))
        assert response.status_code == 200, response.text
        message_id = response.json()["id"]
        assert ws.receive_json()["message_id"] == message_id
        first = client.get("/groups/sync-safe", headers=member_headers).json()
        assert [m["id"] for m in first] == [message_id]
        assert client.get("/groups/sync-safe", headers=member_headers).json() == first
        assert client.post("/groups/ack", headers=other_headers, json={"message_ids": [message_id]}).status_code == 200
        assert len(client.get("/groups/sync-safe", headers=member_headers).json()) == 1
        assert client.post("/groups/ack", headers=member_headers, json={"message_ids": [message_id]}).status_code == 200
        assert client.post("/groups/ack", headers=member_headers, json={"message_ids": [message_id]}).status_code == 200
        assert client.get("/groups/sync-safe", headers=member_headers).json() == []


def test_departed_member_cannot_sync_and_remaining_member_keeps_old_key(group):
    client, user, group_id, owner, member, other = group
    owner_headers, member_headers = auth(user, owner), auth(user, member)
    assert client.post(f"/groups/{group_id}/leave", headers=owner_headers).status_code == 409
    response = client.post("/groups/send", headers=owner_headers, json=send_payload(group_id))
    assert response.status_code == 200
    assert client.post(f"/groups/{group_id}/leave", headers=member_headers).status_code == 200
    assert client.get("/groups/sync-safe", headers=member_headers).json() == []
    assert client.get("/groups/sync", headers=member_headers).json() == []
    assert client.get(f"/groups/{group_id}/sender_keys", headers=member_headers).status_code == 403
    keys = client.get(f"/groups/{group_id}/sender_keys", headers=owner_headers).json()
    assert [key["sender_device_id"] for key in keys] == [member]


def test_group_creation_and_invitation_cannot_forge_key_sender(group):
    client, user, group_id, owner, member, other = group
    owner_headers = auth(user, owner)
    key = {"recipient_device_id": member, "sender_device_id": other,
           "encrypted_sender_key": "key", "sender_key_signature": "sig"}
    bad = {"name": "bad", "member_device_ids": [member], "sender_keys": [key]}
    assert client.post("/groups/create", headers=owner_headers, json=bad).status_code == 400
    key["sender_device_id"] = owner
    valid = client.post("/groups/create", headers=owner_headers, json=bad)
    assert valid.status_code == 200, valid.text
    assert {m["device_id"] for m in valid.json()["members"]} == {owner, member}
    spoofed = {"group_id": group_id, "new_member_device_id": other,
               "sender_keys": [{"sender_device_id": member, "recipient_device_id": other,
                                "encrypted_sender_key": "key", "sender_key_signature": "sig"}]}
    assert client.post("/groups/invite", headers=owner_headers, json=spoofed).status_code == 400
    wrong_target = {**spoofed, "sender_keys": [{**spoofed["sender_keys"][0], "sender_device_id": owner, "recipient_device_id": member}]}
    assert client.post("/groups/invite", headers=owner_headers, json=wrong_target).status_code == 400


def test_group_queue_pagination_and_ack_scope(group):
    client, user, group_id, owner, member, other = group
    async def seed():
        async with AsyncSessionLocal() as db:
            for index in range(105):
                msg = models.GroupMessage(id=f"{group_id}-{index:03}", group_id=group_id,
                    sender_device_id=owner, encrypted_blob="ciphertext", signature="sig",
                    sender_key_id="key", chain_index=index)
                db.add(msg)
                db.add(models.GroupMessageDelivery(message_id=msg.id, device_id=member))
            await db.commit()
    client.portal.call(seed)
    member_headers = auth(user, member)
    first = client.get("/groups/sync-safe", headers=member_headers).json()
    assert len(first) == 100
    assert client.post("/groups/ack", headers=member_headers, json={"message_ids": [first[-1]["id"]]}).status_code == 200
    later = client.get("/groups/sync-safe", headers=member_headers, params={"after": first[-1]["id"]}).json()
    assert len(later) == 5
    assert client.get("/groups/sync-safe", headers=auth(user, other), params={"after": first[-1]["id"]}).status_code == 400
    assert client.post("/groups/ack", headers=member_headers, json={"message_ids": []}).status_code == 422
    assert client.post("/groups/ack", headers=member_headers, json={"message_ids": ["x"] * 101}).status_code == 422


def test_only_owner_can_delete_group_and_related_data(group):
    client, user, group_id, owner, member, other = group
    assert client.delete(f"/groups/{group_id}", headers=auth(user, member)).status_code == 403
    assert client.post("/groups/send", headers=auth(user, owner), json=send_payload(group_id)).status_code == 200
    response = client.delete(f"/groups/{group_id}", headers=auth(user, owner))
    assert response.status_code == 200, response.text
    assert client.get("/groups/sync-safe", headers=auth(user, member)).json() == []


def test_legacy_group_writes_are_disabled_by_default(group, monkeypatch):
    client, user, group_id, owner, member, other = group
    monkeypatch.setattr(settings, "ALLOW_INSECURE_LEGACY_GROUPS", False)
    headers = auth(user, owner)
    assert client.post("/groups/send", headers=headers, json=send_payload(group_id)).status_code == 503
    key = {"recipient_device_id": member, "sender_device_id": owner,
           "encrypted_sender_key": "key", "sender_key_signature": "sig"}
    create = {"name": "blocked", "member_device_ids": [member], "sender_keys": [key]}
    assert client.post("/groups/create", headers=headers, json=create).status_code == 503
    invite = {"group_id": group_id, "new_member_device_id": other,
              "sender_keys": [{**key, "recipient_device_id": other}]}
    assert client.post("/groups/invite", headers=headers, json=invite).status_code == 503
    # Existing data and orderly leave/delete are still available for migration.
    assert client.get("/groups/list", headers=headers).status_code == 200
    assert client.get("/groups/sync-safe", headers=auth(user, member)).json() == []
    assert client.post(f"/groups/{group_id}/leave", headers=auth(user, member)).status_code == 200
    assert client.delete(f"/groups/{group_id}", headers=headers).status_code == 200


def test_legacy_groups_config_defaults_to_disabled(monkeypatch):
    from app.config import Settings
    monkeypatch.delenv("ALLOW_INSECURE_LEGACY_GROUPS", raising=False)
    assert Settings(SECRET_KEY="test", _env_file=None).ALLOW_INSECURE_LEGACY_GROUPS is False


def test_disabled_legacy_group_sync_cannot_consume_pending_messages(group, monkeypatch):
    client, user, group_id, owner, member, other = group
    sender = auth(user, owner)
    receiver = auth(user, member)
    response = client.post("/groups/send", headers=sender, json=send_payload(group_id))
    assert response.status_code == 200
    message_id = response.json()["id"]
    monkeypatch.setattr(settings, "ALLOW_INSECURE_LEGACY_GROUPS", False)
    assert client.get("/groups/sync", headers=receiver).status_code == 503
    assert [item["id"] for item in client.get("/groups/sync-safe", headers=receiver).json()] == [message_id]
    assert client.get("/groups/sync", headers=receiver).status_code == 503
    assert [item["id"] for item in client.get("/groups/sync-safe", headers=receiver).json()] == [message_id]
    monkeypatch.setattr(settings, "ALLOW_INSECURE_LEGACY_GROUPS", True)
    assert [item["id"] for item in client.get("/groups/sync", headers=receiver).json()] == [message_id]
    assert client.get("/groups/sync-safe", headers=receiver).json() == []


def test_desktop_group_list_worker_accepts_real_server_response(group, monkeypatch):
    import importlib.util
    import sys
    from pathlib import Path
    pytest.importorskip('PySide6.QtCore')
    pytest.importorskip('requests')
    client, user, group_id, owner, member, other = group
    base = Path(__file__).resolve().parents[2] / 'max1m_desktop/app'
    def load(name, file):
        spec = importlib.util.spec_from_file_location(name, base / file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        monkeypatch.setitem(sys.modules, name, module)
        return module
    load('app.media_identity', 'media_identity.py')
    load('app.client_api', 'client_api.py')
    load('app.delivery', 'delivery.py')
    workers = load('desktop_test_workers', 'workers.py')
    class Adapter:
        def __init__(self, response): self.response, self.status_code = response, response.status_code
        def iter_content(self, size):
            body = self.response.content
            yield from (body[i:i + size] for i in range(0, len(body), size))
        def close(self): pass
    def get(url, **kwargs):
        assert kwargs['stream'] and not kwargs['allow_redirects']
        return Adapter(client.get('/groups/list', headers=auth(user, member)))
    monkeypatch.setattr(workers.requests, 'get', get)
    worker = workers.FetchGroupsWorker('https://node', 'token')
    results = []
    worker.finished.connect(lambda *args: results.append(args))
    worker.run()
    assert results[0][0] and any(item['id'] == group_id for item in results[0][1])
