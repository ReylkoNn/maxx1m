import pytest
from app import outbox, secure_storage
from app.client_api import APIClient


@pytest.fixture
def setup_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    store = {}
    monkeypatch.setattr(secure_storage.keyring, "get_password", lambda svc, key: store.get(key))
    monkeypatch.setattr(secure_storage.keyring, "set_password", lambda svc, key, value: store.__setitem__(key, value))
    return tmp_path


def test_queue_survives_restart_and_is_isolated(setup_storage):
    payload = {"receiver_device_id": "receiver", "encrypted_blob": "private ciphertext", "signature": "sig"}
    mid = outbox.enqueue("alice", "https://node/", "device1", payload)
    assert outbox.next_message("alice", "https://node", "other-device") is None
    assert outbox.next_message("alice", "https://other", "device1") is None
    path, loaded = outbox.next_message("alice", "https://node", "device1")
    assert loaded == {**payload, "client_message_id": mid}
    assert b"private ciphertext" not in path.read_bytes()
    with pytest.raises(ValueError):
        outbox.acknowledge(path, "alice", "https://node", "device1", "wrong")
    assert path.exists()
    outbox.acknowledge(path, "alice", "https://node", "device1", mid)
    assert outbox.next_message("alice", "https://node", "device1") is None


def test_queue_failure_does_not_overwrite_or_delete(setup_storage, monkeypatch):
    payload = {"receiver_device_id": "receiver", "encrypted_blob": "cipher", "signature": "sig"}
    mid = outbox.enqueue("alice", "https://node", "device", payload)
    path, _ = outbox.next_message("alice", "https://node", "device")
    original = path.read_bytes()
    def fail(*args):
        raise OSError("disk failure")
    monkeypatch.setattr(outbox.os, "replace", fail)
    with pytest.raises(OSError):
        outbox.enqueue("alice", "https://node", "device", payload)
    assert path.read_bytes() == original
    assert len(list(path.parent.iterdir())) == 1
    assert outbox.next_message("alice", "https://node", "device")[1]["client_message_id"] == mid


def test_queue_can_skip_failure_without_losing_it(setup_storage):
    payload = {"receiver_device_id": "receiver", "encrypted_blob": "cipher", "signature": "sig"}
    outbox.enqueue("alice", "https://node", "device", payload)
    outbox.enqueue("alice", "https://node", "device", payload)
    first, _ = outbox.next_message("alice", "https://node", "device")
    second, _ = outbox.next_message("alice", "https://node", "device", {first.name})
    assert first != second and first.exists() and second.exists()


def test_client_never_accepts_wrong_or_old_server_response(monkeypatch):
    from types import SimpleNamespace
    payload = {"client_message_id": "client-id"}
    responses = [SimpleNamespace(status_code=200, iter_content=lambda _: [b'{"id":"other"}'], close=lambda: None),
                 SimpleNamespace(status_code=404, close=lambda: None)]
    monkeypatch.setattr("app.client_api.requests.post", lambda *args, **kwargs: responses.pop(0))
    api = APIClient()
    assert not api.send_reliable_message("https://node", "token", payload)[0]
    assert not api.send_reliable_message("https://node", "token", payload)[0]


def test_history_recovered_before_network_and_not_in_envelope(setup_storage):
    payload = {"receiver_device_id": "receiver", "encrypted_blob": "cipher", "signature": "sig"}
    history = {"ally_username": "bob", "text": "local secret", "msg_id": "msg_recovery",
               "timestamp": "2026-01-01T12:00:00", "reply_to_msg_id": "prior",
               "reply_to_text": "quoted secret", "reply_to_sender": "bob"}
    outbox.enqueue("alice", "https://node", "device", payload, local_history=history)
    path, record = outbox.next_message("alice", "https://node", "device")
    assert b"local secret" not in path.read_bytes()
    assert secure_storage.SecureStorage.load_messages("alice", "bob") == []
    network = outbox.prepare_network_payload("alice", record)
    assert "_local_history" not in network
    assert "local secret" not in str(network) and "quoted secret" not in str(network)
    outbox.prepare_network_payload("alice", record)
    messages = secure_storage.SecureStorage.load_messages("alice", "bob")
    assert len(messages) == 1
    assert messages[0]["text"] == "local secret" and messages[0]["reply_to_msg_id"] == "prior"


def test_history_write_failure_keeps_queue_for_retry(setup_storage, monkeypatch):
    payload = {"receiver_device_id": "receiver", "encrypted_blob": "cipher", "signature": "sig"}
    history = {"ally_username": "bob", "text": "hello", "msg_id": "msg_retry"}
    outbox.enqueue("alice", "https://node", "device", payload, local_history=history)
    path, record = outbox.next_message("alice", "https://node", "device")
    save = secure_storage.SecureStorage._save_messages_to_file
    def fail(*args):
        raise OSError("disk failure")
    monkeypatch.setattr(secure_storage.SecureStorage, "_save_messages_to_file", fail)
    with pytest.raises(OSError):
        outbox.prepare_network_payload("alice", record)
    assert path.exists()
    monkeypatch.setattr(secure_storage.SecureStorage, "_save_messages_to_file", save)
    assert "_local_history" not in outbox.prepare_network_payload("alice", record)
    assert len(secure_storage.SecureStorage.load_messages("alice", "bob")) == 1


def test_legacy_record_prepares_without_history(setup_storage):
    payload = {"receiver_device_id": "receiver", "encrypted_blob": "cipher", "signature": "sig"}
    outbox.enqueue("alice", "https://node", "device", payload)
    _, record = outbox.next_message("alice", "https://node", "device")
    assert outbox.prepare_network_payload("alice", record) == record


def test_missing_storage_key_does_not_replace_existing_encrypted_queue(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda svc, key: keys.get(key))
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda svc, key, value: keys.__setitem__(key, value))
    mid = outbox.enqueue('alice', 'https://node', 'device', {'receiver_device_id': 'r', 'encrypted_blob': 'x', 'signature': 's'})
    path, _ = outbox.next_message('alice', 'https://node', 'device')
    before = path.read_bytes()
    previous = keys.pop('alice_local_storage_key')
    with pytest.raises(ValueError, match='key is missing'):
        outbox.next_message('alice', 'https://node', 'device')
    assert not keys and path.read_bytes() == before
    keys['alice_local_storage_key'] = previous
    assert outbox.next_message('alice', 'https://node', 'device')[1]['client_message_id'] == mid


def test_missing_key_does_not_replace_existing_attachment_or_history(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    written = []
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda *args: None)
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda *args: written.append(args))
    history = secure_storage.SecureStorage._get_messages_file('alice', 'bob')
    history.write_bytes(b'old')
    with pytest.raises(ValueError, match='key is missing'):
        secure_storage.SecureStorage._get_or_create_local_key('alice')
    assert not written and history.read_bytes() == b'old'
    history.unlink()
    attachments = tmp_path / 'profiles' / 'alice' / 'outbox' / 'scope' / 'attachments'
    attachments.mkdir(parents=True)
    (attachments / 'old.job').write_bytes(b'old')
    with pytest.raises(ValueError, match='key is missing'):
        secure_storage.SecureStorage._get_or_create_local_key('alice')
    assert not written


def test_corrupt_contact_store_not_silently_overwritten(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    path = secure_storage.SecureStorage._get_allies_file('alice')
    for invalid in ('{bad-json', '[]'):
        path.write_text(invalid, encoding='utf-8')
        with pytest.raises(Exception): secure_storage.SecureStorage.load_allies('alice')
        with pytest.raises(Exception): secure_storage.SecureStorage.save_allies('alice', {'bob': {}})
        assert path.read_text(encoding='utf-8') == invalid


def test_oversized_or_corrupt_record_is_preserved_and_can_be_skipped(setup_storage, monkeypatch):
    payload = {'receiver_device_id': 'r', 'encrypted_blob': 'x', 'signature': 's'}
    outbox.enqueue('alice', 'https://node', 'device', payload)
    outbox.enqueue('alice', 'https://node', 'device', payload)
    first, _ = outbox.next_message('alice', 'https://node', 'device')
    first.write_bytes(b'x' * 1025)
    monkeypatch.setattr(outbox, 'MAX_ENCRYPTED_RECORD_BYTES', 1024)
    with pytest.raises(outbox.QueueRecordError) as exc:
        outbox.next_message('alice', 'https://node', 'device')
    assert exc.value.path == first and first.stat().st_size == 1025
    second, _ = outbox.next_message('alice', 'https://node', 'device', {first.name})
    assert second != first and first.exists()
    first.write_bytes(b'corrupt')
    with pytest.raises(outbox.QueueRecordError):
        outbox.next_message('alice', 'https://node', 'device')
    assert first.read_bytes() == b'corrupt'


def test_malformed_authenticated_records_are_retained_and_skippable(setup_storage):
    import uuid
    import nacl.secret
    directory=outbox._directory('alice','https://node','device')
    box=nacl.secret.SecretBox(secure_storage.SecureStorage._get_or_create_local_key('alice'))
    valid_id=outbox.enqueue('alice','https://node','device',{'receiver_device_id':'r','encrypted_blob':'c','signature':'s'})
    bad=directory/('00000000000000000000_'+str(uuid.uuid4())+'.enc')
    for encoded in (b'{"client_message_id":123}', b'['*1200+b'0'+b']'*1200, b'null'):
        bad.write_bytes(box.encrypt(encoded))
        with pytest.raises(outbox.QueueRecordError) as exc:
            outbox.next_message('alice','https://node','device')
        assert exc.value.path==bad and bad.exists()
        assert outbox.next_message('alice','https://node','device',{bad.name})[1]['client_message_id']==valid_id


def test_discard_validates_whole_selection_before_deleting(setup_storage):
    outbox.enqueue('alice','https://node','device',{'receiver_device_id':'r','encrypted_blob':'c','signature':'s'})
    path,_=outbox.next_message('alice','https://node','device')
    with pytest.raises(ValueError):
        outbox.discard_paths([path,setup_storage/'outside.enc'],'alice','https://node','device')
    assert path.exists()


def test_unknown_queue_fields_cannot_leak_or_modify_history(setup_storage):
    history={'ally_username':'bob','text':'private','msg_id':'id'}
    record={'receiver_device_id':'bob','encrypted_blob':'cipher','signature':'sig',
            '_local_history':history,'_unknown_private':'local secret'}
    outbox.enqueue('alice','https://node','mine',record)
    path,loaded=outbox.next_message('alice','https://node','mine'); before=path.read_bytes()
    with pytest.raises(ValueError,match='Unsupported'):
        outbox.prepare_network_payload('alice',loaded)
    assert path.read_bytes()==before
    assert secure_storage.SecureStorage.load_messages_strict('alice','bob')==[]
