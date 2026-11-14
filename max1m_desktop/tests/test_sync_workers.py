from types import SimpleNamespace
import json

from app.workers import SyncMessagesWorker, AcknowledgeMessagesWorker


def test_sync_uses_safe_endpoint_and_cursor(monkeypatch):
    calls = []
    def get(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(status_code=200, iter_content=lambda _: [json.dumps([{"id": "m1"}]).encode()], close=lambda: None)
    monkeypatch.setattr("app.workers.requests.get", get)
    worker = SyncMessagesWorker("https://example.test/", "token", "cursor")
    results = []
    worker.finished.connect(lambda success, data: results.append((success, data)))
    worker.run()
    assert calls[0][0] == "https://example.test/messages/sync-safe"
    assert calls[0][1]["params"] == {"after": "cursor", "limit": 20}
    assert results == [(True, [{"id": "m1"}])]


def test_ack_sends_only_processed_ids(monkeypatch):
    calls = []
    def post(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(status_code=200, iter_content=lambda _: [b'{"status":"ok"}'], close=lambda: None)
    monkeypatch.setattr("app.workers.requests.post", post)
    worker = AcknowledgeMessagesWorker("https://example.test", "token", ["m1", "m2"])
    results = []
    worker.finished.connect(lambda success, data: results.append((success, data)))
    worker.run()
    assert calls[0][0] == "https://example.test/messages/ack"
    assert calls[0][1]["json"] == {"message_ids": ["m1", "m2"]}
    assert calls[0][1]["stream"] is True and calls[0][1]["allow_redirects"] is False
    assert results == [(True, 200)]


def test_old_server_does_not_fall_back_to_destructive_sync(monkeypatch):
    calls = []
    def get(url, **kwargs):
        calls.append(url)
        return SimpleNamespace(status_code=404, close=lambda: None)
    monkeypatch.setattr("app.workers.requests.get", get)
    worker = SyncMessagesWorker("https://example.test", "token")
    results = []
    worker.finished.connect(lambda success, data: results.append((success, data)))
    worker.run()
    assert calls == ["https://example.test/messages/sync-safe"]
    assert results[0][0] is False


def test_group_sync_never_uses_destructive_legacy_endpoint(monkeypatch):
    from app.workers import SyncGroupMessagesWorker
    calls = []
    def get(url, **kwargs):
        calls.append(url)
        return SimpleNamespace(status_code=200, json=lambda: [{"id": "g1"}])
    monkeypatch.setattr("app.workers.requests.get", get)
    worker = SyncGroupMessagesWorker("https://example.test", "token")
    results = []
    worker.finished.connect(lambda success, data: results.append((success, data)))
    worker.run()
    assert calls == ["https://example.test/groups/sync-safe"]
    assert results == [(True, [{"id": "g1"}])]


def test_websocket_url_does_not_expose_token():
    from app.workers import WebSocketWorker
    worker = WebSocketWorker("https://example.test/", "secret.jwt", "device-id")
    assert worker.ws_url == "wss://example.test/messages/ws/device-id"
    assert "secret.jwt" not in worker.ws_url


def test_websocket_worker_sends_bearer_header_with_new_and_legacy_library(monkeypatch):
    import asyncio
    from app.workers import WebSocketWorker
    for modern in (True, False):
        worker = WebSocketWorker("https://example.test", "secret.jwt", "device-id")
        calls = []
        class Connection:
            async def __aenter__(self):
                worker._is_running = False
                return self
            async def __aexit__(self, *args):
                return False
        def modern_connect(url, *, additional_headers=None, **kwargs):
            calls.append((url, additional_headers))
            return Connection()
        def legacy_connect(url, *, extra_headers=None, **kwargs):
            calls.append((url, extra_headers))
            return Connection()
        monkeypatch.setattr("app.workers.websockets.connect", modern_connect if modern else legacy_connect)
        asyncio.run(worker._connect_loop())
        assert calls == [("wss://example.test/messages/ws/device-id", {"Authorization": "Bearer secret.jwt"})]


def test_websocket_ignores_legacy_screen_traffic_and_bounds_queue(monkeypatch):
    import asyncio
    from app.workers import WebSocketWorker
    worker = WebSocketWorker('https://example.test', 'token', 'device')
    events, options = [], []
    worker.screen_frame_received.connect(lambda value: events.append(value))
    worker.screen_control_received.connect(lambda value: events.append(value))
    messages = iter([b'legacy-frame', json.dumps({'type': 'screen_frame', 'frame': 'abc'}),
                     json.dumps({'type': 'screen_control', 'action': 'start'})])
    class Connection:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def recv(self):
            msg = next(messages)
            if isinstance(msg, str) and 'screen_control' in msg:
                worker._is_running = False
            return msg
    def connect(url, *, additional_headers=None, **kwargs):
        options.append(kwargs)
        return Connection()
    monkeypatch.setattr('app.workers.websockets.connect', connect)
    assert not worker.send_signal({'type': 'screen_frame', 'frame': b'raw'})
    assert not worker.send_signal({'type': 'screen_control', 'action': 'start'})
    asyncio.run(worker._connect_loop())
    assert not events
    assert options[0]['max_size'] == 2 * 1024 * 1024 and options[0]['max_queue'] == 8


def test_sync_rejects_more_than_requested_page(monkeypatch):
    payload = json.dumps([{'id': str(i)} for i in range(21)]).encode()
    response = SimpleNamespace(status_code=200, iter_content=lambda _: [payload], close=lambda: None)
    monkeypatch.setattr('app.workers.requests.get', lambda *a, **kw: response)
    worker = SyncMessagesWorker('https://example.test', 'token')
    events = []
    worker.finished.connect(lambda *args: events.append(args))
    worker.run()
    assert len(events) == 1 and not events[0][0]


def test_websocket_connection_errors_never_print_credentials(monkeypatch, capsys):
    import asyncio
    from app.workers import WebSocketWorker
    secret='bearer-secret-do-not-print'
    worker=WebSocketWorker('https://example.test',secret,'device')
    def connect(url,*,additional_headers=None,**kwargs):
        worker._is_running=False
        raise RuntimeError('sensitive authorization: '+secret)
    monkeypatch.setattr('app.workers.websockets.connect',connect)
    asyncio.run(worker._connect_loop())
    captured=capsys.readouterr()
    assert 'RuntimeError' in captured.out and secret not in captured.out+captured.err


def test_sync_and_ack_close_exception_emit_exactly_one_failure(monkeypatch):
    def bad_close(): raise RuntimeError('secret token')
    sync_response=SimpleNamespace(status_code=200,iter_content=lambda _: [b'[]'],close=bad_close)
    ack_response=SimpleNamespace(status_code=200,iter_content=lambda _: [b'{"status":"ok"}'],close=bad_close)
    monkeypatch.setattr('app.workers.requests.get',lambda *a,**kw:sync_response)
    monkeypatch.setattr('app.workers.requests.post',lambda *a,**kw:ack_response)
    for worker in (SyncMessagesWorker('https://node','secret token'),
                   AcknowledgeMessagesWorker('https://node','secret token',['id'])):
        results=[]; worker.finished.connect(lambda ok,data:results.append((ok,data)))
        worker.run()
        assert len(results)==1 and results[0][0] is False and 'secret token' not in str(results)


def test_upload_and_grant_worker_exception_always_reports_failure(monkeypatch, tmp_path):
    from app.workers import ReliableUploadFileWorker, GrantFileAccessWorker
    def fail(*args): raise RuntimeError('secret bearer token')
    monkeypatch.setattr('app.workers.api.upload_file_reliable',fail)
    monkeypatch.setattr('app.workers.api.grant_file_access',fail)
    from app.crypto_box import CryptoManager
    import hashlib
    crypto=CryptoManager(); key=crypto.generate_file_key(); blob=crypto.encrypt_file(b'data',key)
    path=tmp_path/'blob'; path.write_bytes(blob)
    for worker in (ReliableUploadFileWorker('https://node','token','id',path,len(blob),hashlib.sha256(blob).hexdigest(),key),
                   GrantFileAccessWorker('https://node','token','id','device')):
        results=[]; worker.finished.connect(lambda ok,data:results.append((ok,data)))
        worker.run()
        assert len(results)==1 and results[0][0] is False and 'secret bearer token' not in str(results)


def test_transient_worker_catches_unexpected_failure_without_logging_token(monkeypatch):
    from app.workers import SendMessageWorker
    def fail(*args): raise RuntimeError('private token')
    monkeypatch.setattr('app.workers.api.send_message',fail)
    worker=SendMessageWorker('https://node','token',{}); results=[]
    worker.finished.connect(lambda ok,data:results.append((ok,data))); worker.run()
    assert results==[(False,'Ошибка отправки: RuntimeError')]
