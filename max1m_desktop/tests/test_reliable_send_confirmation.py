"""A UUID-only success must never discard the queued ciphertext."""
import json
import pytest
from app import client_api, outbox, secure_storage


class Response:
    status_code = 200
    def __init__(self, body):
        self.body = json.dumps(body).encode()
        self.closed = False
    def iter_content(self, _size):
        yield self.body
    def close(self):
        self.closed = True


@pytest.mark.parametrize('change', [
    {'encrypted_blob': 'other'}, {'signature': 'other'}, {'sender_device_id': 'wrong'},
    {'id': 'wrong'}, {'encrypted_blob': None}, {'signature': None}, {'sender_device_id': None},
    {'receiver_device_id': 'wrong'}, {'receiver_device_id': None},
])
def test_mismatched_echo_keeps_record_for_retry(tmp_path, monkeypatch, change):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda svc, key: keys.get(key))
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda svc, key, value: keys.__setitem__(key, value))
    payload = {'receiver_device_id': 'receiver', 'encrypted_blob': 'ciphertext', 'signature': 'signature'}
    mid = outbox.enqueue('alice', 'https://node', 'sender', payload)
    path, record = outbox.next_message('alice', 'https://node', 'sender')
    original = path.read_bytes()
    response = Response({**record, 'id': mid, 'sender_device_id': 'sender', **change})
    monkeypatch.setattr(client_api.requests, 'post', lambda *args, **kwargs: response)
    ok, _ = client_api.APIClient().send_reliable_message('https://node', 'token', record, 'sender')
    if ok:
        outbox.acknowledge(path, 'alice', 'https://node', 'sender', mid)
    assert not ok and response.closed and path.read_bytes() == original
    assert outbox.next_message('alice', 'https://node', 'sender')[1] == record
    response = Response({**record, 'id': mid, 'sender_device_id': 'sender'})
    ok, _ = client_api.APIClient().send_reliable_message('https://node', 'token', record, 'sender')
    assert ok and response.closed
    outbox.acknowledge(path, 'alice', 'https://node', 'sender', mid)
    assert not path.exists()


def test_legacy_response_without_receiver_is_accepted_but_not_verified(monkeypatch):
    payload = {'client_message_id': 'id', 'receiver_device_id': 'receiver',
               'encrypted_blob': 'cipher', 'signature': 'sig'}
    response = Response({'id': 'id', 'sender_device_id': 'sender',
                         'encrypted_blob': 'cipher', 'signature': 'sig'})
    monkeypatch.setattr(client_api.requests, 'post', lambda *args, **kwargs: response)
    assert client_api.APIClient().send_reliable_message('https://node', 'token', payload, 'sender')[0]
    assert response.closed


def test_worker_without_sender_identity_fails_closed(monkeypatch):
    from app.workers import ReliableSendWorker
    from app import workers
    monkeypatch.setattr(workers.api, 'send_reliable_message', lambda *args: pytest.fail('unexpected send'))
    worker = ReliableSendWorker('https://node', 'token', {})
    emitted = []
    worker.finished.connect(lambda success, data: emitted.append((success, data)))
    worker.run()
    assert emitted and emitted[0][0] is False


def test_reliable_send_logs_correlatable_tags_without_payload_or_credentials(monkeypatch, caplog):
    import logging
    from app.diagnostics import safe_identifier_tag

    client_id = "12345678-1234-4234-8234-123456789abc"
    sender_id = "sender-device-private-id"
    recipient_id = "recipient-device-private-id"
    token = "never-log-this-token"
    ciphertext = "never-log-this-ciphertext"
    signature = "never-log-this-signature"
    payload = {
        "client_message_id": client_id,
        "receiver_device_id": recipient_id,
        "encrypted_blob": ciphertext,
        "signature": signature,
    }
    response = Response({
        "id": client_id,
        "sender_device_id": sender_id,
        "receiver_device_id": recipient_id,
        "encrypted_blob": ciphertext,
        "signature": signature,
    })
    monkeypatch.setattr(client_api.requests, "post", lambda *args, **kwargs: response)

    with caplog.at_level(logging.INFO, logger="max1m.delivery"):
        ok, _ = client_api.APIClient().send_reliable_message(
            "https://node.example", token, payload, sender_id
        )

    assert ok and response.closed
    assert safe_identifier_tag(client_id) in caplog.text
    assert safe_identifier_tag(sender_id) in caplog.text
    assert safe_identifier_tag(recipient_id) in caplog.text
    for sensitive in (client_id, sender_id, recipient_id, token, ciphertext, signature):
        assert sensitive not in caplog.text
    assert "send.http.started" in caplog.text and "send.http.accepted" in caplog.text
