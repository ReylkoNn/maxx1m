"""Durable queue admission, migration guard and concurrency regressions."""
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from app import models
from app.config import settings
from app.database import AsyncSessionLocal
from app.main import app
from app.security import create_access_token


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(settings, 'MAX_PENDING_PER_DEVICE', 3)
    monkeypatch.setattr(settings, 'MAX_PENDING_PER_SENDER', 3)
    monkeypatch.setattr(settings, 'MAX_PENDING_BYTES_PER_DEVICE', 1024)
    monkeypatch.setattr(settings, 'MAX_MESSAGE_PAYLOAD_BYTES', 1024)
    with TestClient(app) as client:
        async def seed():
            async with AsyncSessionLocal() as db:
                user = models.User(username='quota_' + uuid.uuid4().hex, password_hash='x')
                db.add(user); await db.flush()
                devices = [models.Device(user_id=user.id, device_name=str(i), public_key='key',
                                         fingerprint=uuid.uuid4().hex) for i in range(3)]
                db.add_all(devices); await db.commit()
                return user.id, [device.id for device in devices]
        user, devices = client.portal.call(seed)
        def auth(dev):
            return {'Authorization': 'Bearer ' + create_access_token({'sub': user, 'device_id': dev})}
        yield client, devices, auth


def reliable(receiver, ciphertext='cipher'):
    return {'client_message_id': str(uuid.uuid4()), 'receiver_device_id': receiver,
            'encrypted_blob': ciphertext, 'signature': 'sig'}


def test_both_routes_share_quota_with_safe_retry_and_ack(env):
    client, (sender, receiver, other), auth = env
    first = reliable(receiver)
    assert client.post('/messages/send-reliable', headers=auth(sender), json=first).status_code == 200
    legacy = {'receiver_device_id': receiver, 'encrypted_blob': 'x', 'signature': 'sig'}
    assert client.post('/messages/send', headers=auth(sender), json=legacy).status_code == 200
    last = reliable(receiver)
    assert client.post('/messages/send-reliable', headers=auth(other), json=last).status_code == 200
    assert client.post('/messages/send', headers=auth(other), json=legacy).status_code == 429
    assert client.post('/messages/send-reliable', headers=auth(sender), json=reliable(receiver)).status_code == 429
    assert client.post('/messages/send-reliable', headers=auth(sender), json=first).status_code == 200
    conflict = {**first, 'encrypted_blob': 'different'}
    assert client.post('/messages/send-reliable', headers=auth(sender), json=conflict).status_code == 409
    messages = client.get('/messages/sync-safe', headers=auth(receiver)).json()
    assert len(messages) == 3
    assert client.post('/messages/ack', headers=auth(receiver), json={'message_ids': [first['client_message_id']]}).status_code == 200
    assert client.post('/messages/send-reliable', headers=auth(sender), json=reliable(receiver)).status_code == 200
    assert len(client.get('/messages/sync-safe', headers=auth(receiver)).json()) == 3


def test_concurrent_writers_do_not_overfill(env):
    client, (sender, receiver, other), auth = env
    items = [reliable(receiver) for _ in range(10)]
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda item: client.post('/messages/send-reliable', headers=auth(sender), json=item).status_code, items))
    assert results.count(200) == 3 and results.count(429) == 7
    assert len(client.get('/messages/sync-safe', headers=auth(receiver)).json()) == 3


def test_sender_fairness_and_utf8_byte_quotas(env, monkeypatch):
    client, (sender, receiver, other), auth = env
    monkeypatch.setattr(settings, 'MAX_PENDING_PER_SENDER', 1)
    monkeypatch.setattr(settings, 'MAX_PENDING_BYTES_PER_DEVICE', 10)
    monkeypatch.setattr(settings, 'MAX_MESSAGE_PAYLOAD_BYTES', 10)
    a = reliable(receiver, 'я')  # 2 bytes + 3-byte signature
    assert client.post('/messages/send-reliable', headers=auth(sender), json=a).status_code == 200
    assert client.post('/messages/send-reliable', headers=auth(sender), json=reliable(receiver, 'a')).status_code == 429
    assert client.post('/messages/send-reliable', headers=auth(other), json=reliable(receiver, 'яя')).status_code == 429
    assert client.post('/messages/send-reliable', headers=auth(other), json=reliable(receiver, 'яяяя')).status_code == 413
    assert client.post('/messages/send-reliable', headers=auth(other), json=reliable(receiver, 'я')).status_code == 200


def test_legacy_sync_is_fail_closed_and_explicit_opt_in(env, monkeypatch):
    client, (sender, receiver, other), auth = env
    item = reliable(receiver)
    assert client.post('/messages/send-reliable', headers=auth(sender), json=item).status_code == 200
    assert client.get('/messages/sync', headers=auth(receiver)).status_code == 503
    assert [m['id'] for m in client.get('/messages/sync-safe', headers=auth(receiver)).json()] == [item['client_message_id']]
    monkeypatch.setattr(settings, 'ALLOW_DESTRUCTIVE_LEGACY_SYNC', True)
    assert len(client.get('/messages/sync', headers=auth(receiver)).json()) == 1
    assert client.get('/messages/sync-safe', headers=auth(receiver)).json() == []


def test_safe_sync_client_can_request_smaller_pages(env):
    client, (sender, receiver, other), auth = env
    for _ in range(3):
        assert client.post('/messages/send-reliable', headers=auth(sender), json=reliable(receiver)).status_code == 200
    first = client.get('/messages/sync-safe', headers=auth(receiver), params={'limit': 2}).json()
    assert len(first) == 2
    following = client.get('/messages/sync-safe', headers=auth(receiver), params={'limit': 2, 'after': first[-1]['id']}).json()
    assert len(following) == 1
    assert not set(x['id'] for x in first) & set(x['id'] for x in following)
    assert client.get('/messages/sync-safe', headers=auth(receiver), params={'limit': 0}).status_code == 422
    assert client.get('/messages/sync-safe', headers=auth(receiver), params={'limit': 101}).status_code == 422


def test_desktop_outbox_recovery_against_real_server(env, tmp_path, monkeypatch):
    """Real desktop Box/signature and queue + server retry and recipient ACK."""
    import importlib.util
    import json
    import sys
    from pathlib import Path
    pytest.importorskip('nacl')
    pytest.importorskip('keyring')
    client, (sender, receiver, other), auth = env
    desktop = Path(__file__).resolve().parents[2] / 'max1m_desktop' / 'app'
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    storage = load('desktop_test_storage', desktop / 'secure_storage.py')
    monkeypatch.setattr(storage, 'BASE_DIR', tmp_path)
    keys = {}
    monkeypatch.setattr(storage.keyring, 'get_password', lambda svc, key: keys.get(key))
    monkeypatch.setattr(storage.keyring, 'set_password', lambda svc, key, value: keys.__setitem__(key, value))
    monkeypatch.setitem(sys.modules, 'app.secure_storage', storage)
    # Backend and desktop both use the top-level app package. Register the
    # desktop history modules explicitly for this cross-project integration test.
    for name in ('delivery', 'history_paging', 'history_store', 'experimental_history_adapter', 'history_activation'):
        qualified = f'app.{name}'
        spec = importlib.util.spec_from_file_location(qualified, desktop / f'{name}.py')
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, qualified, module)
        spec.loader.exec_module(module)
    queue = load('desktop_test_outbox', desktop / 'outbox.py')
    crypto = load('desktop_test_crypto', desktop / 'crypto_box.py')
    alice, bob = crypto.CryptoManager(), crypto.CryptoManager()
    alice.generate_new_keypair(); bob.generate_new_keypair()
    text = json.dumps({'type': 'text', 'msg_id': 'user-id', 'text': 'integration test'})
    sealed = alice.encrypt_message(text, bob.get_public_key_b64())
    payload = {'receiver_device_id': receiver, **sealed}
    history = {'ally_username': 'bob', 'text': 'integration test', 'msg_id': 'user-id'}
    mid = queue.enqueue('alice', 'https://server', sender, payload, local_history=history)
    path, record = queue.next_message('alice', 'https://server', sender)
    wire = queue.prepare_network_payload('alice', record)
    first = client.post('/messages/send-reliable', headers=auth(sender), json=wire)
    assert first.status_code == 200 and first.json()['id'] == mid
    # Model a committed server response lost before queue acknowledgement.
    recovered_path, recovered = queue.next_message('alice', 'https://server', sender)
    assert recovered_path == path and recovered == record
    retry = client.post('/messages/send-reliable', headers=auth(sender), json=queue.prepare_network_payload('alice', recovered))
    assert retry.status_code == 200 and retry.json()['id'] == mid
    received = client.get('/messages/sync-safe', headers=auth(receiver), params={'limit': 20}).json()
    assert len(received) == 1 and received[0]['id'] == mid
    envelope = received[0]
    assert bob.verify_signature(envelope['encrypted_blob'], envelope['signature'], alice.get_public_key_b64())
    assert bob.decrypt_message(envelope['encrypted_blob'], alice.get_public_key_b64()) == text
    save = storage.SecureStorage._save_messages_to_file
    def fail_save(*args):
        raise OSError('simulated disk failure')
    monkeypatch.setattr(storage.SecureStorage, '_save_messages_to_file', fail_save)
    with pytest.raises(OSError):
        storage.SecureStorage.save_message('bob', 'alice', 'integration test', False, msg_id='user-id')
    assert len(client.get('/messages/sync-safe', headers=auth(receiver)).json()) == 1
    monkeypatch.setattr(storage.SecureStorage, '_save_messages_to_file', save)
    storage.SecureStorage.save_message('bob', 'alice', 'integration test', False, msg_id='user-id')
    assert client.post('/messages/ack', headers=auth(receiver), json={'message_ids': [mid]}).status_code == 200
    queue.acknowledge(path, 'alice', 'https://server', sender, mid)
    assert queue.next_message('alice', 'https://server', sender) is None
    assert client.post('/messages/send-reliable', headers=auth(sender), json=wire).status_code == 200
    assert client.get('/messages/sync-safe', headers=auth(receiver)).json() == []


def test_invalid_unicode_is_rejected_without_queue_write(env):
    client, (sender, receiver, _), auth = env
    payload = reliable(receiver, '\ud800')
    import json
    response = client.post('/messages/send-reliable', headers={**auth(sender), 'Content-Type': 'application/json'}, content=json.dumps(payload).encode('ascii'))
    assert response.status_code == 422
    assert client.get('/messages/sync-safe', headers=auth(receiver)).json() == []


def test_desktop_send_accepts_actual_large_server_confirmation(env, monkeypatch):
    import importlib.util
    from pathlib import Path
    pytest.importorskip('requests')
    client, (sender, receiver, _), auth = env
    # Both projects use an `app` package; load this desktop dependency under
    # its qualified name without replacing the backend package under test.
    import sys
    desktop_app = Path(__file__).resolve().parents[2] / 'max1m_desktop/app'
    identity_spec = importlib.util.spec_from_file_location('app.media_identity', desktop_app / 'media_identity.py')
    identity = importlib.util.module_from_spec(identity_spec)
    identity_spec.loader.exec_module(identity)
    monkeypatch.setitem(sys.modules, 'app.media_identity', identity)
    spec = importlib.util.spec_from_file_location('desktop_test_api', desktop_app / 'client_api.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(settings, 'MAX_PENDING_BYTES_PER_DEVICE', 1024 * 1024)
    monkeypatch.setattr(settings, 'MAX_MESSAGE_PAYLOAD_BYTES', 1024 * 1024)
    payload = reliable(receiver, 'x' * (128 * 1024))
    class ResponseAdapter:
        def __init__(self, result): self.result = result; self.status_code = result.status_code
        def iter_content(self, size):
            body = self.result.content
            yield from (body[i:i + size] for i in range(0, len(body), size))
        def close(self): pass
    def post(url, json, **kwargs):
        return ResponseAdapter(client.post('/messages/send-reliable', headers=auth(sender), json=json))
    monkeypatch.setattr(module.requests, 'post', post)
    api = module.APIClient()
    ok, result = api.send_reliable_message('https://node', 'token', payload, sender)
    assert ok and result['id'] == payload['client_message_id']
    assert result['sender_device_id'] == sender and result['encrypted_blob'] == payload['encrypted_blob']
    assert result['signature'] == payload['signature']
    assert result['receiver_device_id'] == receiver
    # A different expected sender is not a valid confirmation, even when the
    # server idempotently returns the same committed envelope.
    ok, _ = api.send_reliable_message('https://node', 'token', payload, 'other-device')
    assert not ok
    assert len(client.get('/messages/sync-safe', headers=auth(receiver)).json()) == 1


def test_migrated_desktop_outbox_and_inbox_against_real_server(env, tmp_path, monkeypatch):
    """Actual server retry/ACK with activated row storage and real desktop crypto."""
    import app
    import importlib.util
    import json
    import sys
    from pathlib import Path
    pytest.importorskip('nacl')
    pytest.importorskip('keyring')
    pytest.importorskip('PySide6.QtCore')
    client, (sender, receiver, _), auth = env
    desktop = Path(__file__).resolve().parents[2] / 'max1m_desktop' / 'app'
    def register(name):
        qualified = f'app.{name}'
        spec = importlib.util.spec_from_file_location(qualified, desktop / f'{name}.py')
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, qualified, module)
        spec.loader.exec_module(module)
        return module
    storage = register('secure_storage')
    monkeypatch.setattr(app, 'secure_storage', storage, raising=False)
    monkeypatch.setattr(storage, 'BASE_DIR', tmp_path)
    keys = {}
    monkeypatch.setattr(storage.keyring, 'get_password', lambda svc, key: keys.get(key))
    monkeypatch.setattr(storage.keyring, 'set_password', lambda svc, key, value: keys.__setitem__(key, value))
    for module in ('delivery', 'history_paging', 'history_store', 'experimental_history_adapter', 'instance_guard'):
        register(module)
    activation = register('history_activation')
    queue = register('outbox')
    crypto = register('crypto_box')
    alice, bob = crypto.CryptoManager(), crypto.CryptoManager()
    alice.generate_new_keypair(); bob.generate_new_keypair()
    store = storage.SecureStorage
    store.save_message('alice', 'bob', 'old alice', True, msg_id='old-a')
    store.save_message('bob', 'alice', 'old bob', False, msg_id='old-b')
    alice_old = store._get_messages_file('alice','bob').read_bytes()
    bob_old = store._get_messages_file('bob','alice').read_bytes()
    assert activation.migrate_chat('alice','bob') and activation.migrate_chat('bob','alice')
    text = json.dumps({'type':'text', 'msg_id':'user-id', 'text':'row integration'})
    sealed = alice.encrypt_message(text, bob.get_public_key_b64())
    payload = {'receiver_device_id':receiver, **sealed}
    mid = queue.enqueue('alice', 'https://server', sender, payload,
                        local_history={'ally_username':'bob','text':'row integration','msg_id':'user-id'})
    path, record = queue.next_message('alice', 'https://server', sender)
    wire = queue.prepare_network_payload('alice', record)
    assert client.post('/messages/send-reliable', headers=auth(sender), json=wire).status_code == 200
    assert client.post('/messages/send-reliable', headers=auth(sender), json=wire).status_code == 200
    messages = client.get('/messages/sync-safe', headers=auth(receiver)).json()
    assert len(messages) == 1 and messages[0]['id'] == mid
    assert bob.verify_signature(messages[0]['encrypted_blob'], messages[0]['signature'], alice.get_public_key_b64())
    assert bob.decrypt_message(messages[0]['encrypted_blob'], alice.get_public_key_b64()) == text
    row_store = sys.modules['app.history_store'].EncryptedHistory
    original_encrypt = row_store._encrypt
    monkeypatch.setattr(row_store, '_encrypt', lambda *a, **kw: (_ for _ in ()).throw(OSError('disk failed')))
    with pytest.raises(OSError): store.save_message('bob', 'alice', 'row integration', False, msg_id='user-id')
    assert len(client.get('/messages/sync-safe', headers=auth(receiver)).json()) == 1
    monkeypatch.setattr(row_store, '_encrypt', original_encrypt)
    assert store.save_message('bob', 'alice', 'row integration', False, msg_id='user-id')
    assert not store.save_message('bob', 'alice', 'row integration', False, msg_id='user-id')
    assert client.post('/messages/ack', headers=auth(receiver), json={'message_ids':[mid]}).status_code == 200
    queue.acknowledge(path, 'alice', 'https://server', sender, mid)
    assert client.get('/messages/sync-safe', headers=auth(receiver)).json() == []
    assert store.load_history_page('alice','bob').messages[-1]['text'] == 'row integration'
    assert store.load_history_page('bob','alice').messages[-1]['text'] == 'row integration'
    assert store._get_messages_file('alice','bob').read_bytes() == alice_old
    assert store._get_messages_file('bob','alice').read_bytes() == bob_old


def test_busy_live_socket_drops_only_notification_not_durable_message(env, monkeypatch):
    import asyncio
    from app.api import messages
    client, (sender, receiver, other), auth = env
    monkeypatch.setattr(messages, 'MAX_WS_PENDING_SENDS', 1)
    class SlowSocket:
        def __init__(self): self.started=asyncio.Event(); self.release=asyncio.Event()
        async def accept(self): pass
        async def close(self,code): pass
        async def send_json(self,data): self.started.set(); await self.release.wait()
    async def open_busy():
        socket=SlowSocket()
        await messages.manager.connect(socket,receiver)
        task=asyncio.create_task(messages.manager.send_personal_message({'type':'hold'},receiver))
        await socket.started.wait()
        return socket,task
    socket,task=client.portal.call(open_busy)
    try:
        item=reliable(receiver)
        assert client.post('/messages/send-reliable',headers=auth(sender),json=item).status_code == 200
        pending=client.get('/messages/sync-safe',headers=auth(receiver)).json()
        assert [entry['id'] for entry in pending]==[item['client_message_id']]
        assert client.post('/messages/ack',headers=auth(receiver),json={'message_ids':[item['client_message_id']]}).status_code==200
        assert client.get('/messages/sync-safe',headers=auth(receiver)).json()==[]
    finally:
        async def cleanup():
            socket.release.set()
            await task
            if messages.manager.active_connections.get(receiver) is socket:
                messages.manager.disconnect(receiver)
        client.portal.call(cleanup)


def test_ack_waits_for_concurrent_revocation_and_preserves_message(env):
    import asyncio
    import threading
    import time
    from sqlalchemy import text
    client,(sender,receiver,other),auth=env
    item=reliable(receiver)
    assert client.post('/messages/send-reliable',headers=auth(sender),json=item).status_code==200
    acquired=threading.Event()
    async def revoke_locked():
        async with AsyncSessionLocal() as db:
            await db.execute(text('BEGIN IMMEDIATE'))
            device=await db.get(models.Device,receiver)
            device.is_revoked=True
            await db.flush()
            release=asyncio.Event()
            shared.append(release)
            acquired.set()
            await release.wait()
            await db.commit()
    shared=[]
    revocation=client.portal.start_task_soon(revoke_locked)
    assert acquired.wait(3)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            ack=executor.submit(client.post,'/messages/ack',headers=auth(receiver),
                                json={'message_ids':[item['client_message_id']]})
            time.sleep(.1)
            assert not ack.done()
            client.portal.call(shared[0].set)
            revocation.result(timeout=3)
            assert ack.result(timeout=3).status_code==401
        async def still_pending():
            async with AsyncSessionLocal() as db:
                message=await db.get(models.Message,item['client_message_id'])
                return not message.is_delivered
        assert client.portal.call(still_pending)
    finally:
        if not revocation.done():
            client.portal.call(shared[0].set)
            revocation.result(timeout=3)


def test_concurrent_ack_and_sends_preserve_quota_and_message_identity(env):
    client,(sender,receiver,_),auth=env
    existing=[reliable(receiver, 'old-'+str(i)) for i in range(3)]
    for item in existing:
        assert client.post('/messages/send-reliable',headers=auth(sender),json=item).status_code==200
    candidates=[reliable(receiver,'new-'+str(i)) for i in range(8)]
    def ack():
        return client.post('/messages/ack',headers=auth(receiver),
                           json={'message_ids':[existing[0]['client_message_id']]}).status_code
    def send(item): return client.post('/messages/send-reliable',headers=auth(sender),json=item).status_code
    with ThreadPoolExecutor(max_workers=9) as pool:
        ack_future=pool.submit(ack)
        futures=[pool.submit(send,item) for item in candidates]
        ack_status=ack_future.result()
        statuses=[future.result() for future in futures]
    assert ack_status==200
    assert set(statuses).issubset({200,429}) and statuses.count(200)<=1
    page=client.get('/messages/sync-safe',headers=auth(receiver)).json()
    actual={item['id'] for item in page}
    expected={item['client_message_id'] for item in existing[1:]}
    expected.update(item['client_message_id'] for item,status in zip(candidates,statuses) if status==200)
    assert actual==expected and len(actual)<=3
    # The rejected requests remain independently retryable after more ACKs.
    rejected=next((item for item,status in zip(candidates,statuses) if status==429),None)
    assert rejected is not None
    assert client.post('/messages/ack',headers=auth(receiver),json={'message_ids':[existing[1]['client_message_id']]}).status_code==200
    assert client.post('/messages/send-reliable',headers=auth(sender),json=rejected).status_code==200
