import asyncio
import pytest
from app.body_limits import MessageBodyLimitMiddleware
from fastapi.testclient import TestClient
from app.main import app


def test_server_rejects_oversized_message_body_before_json_parsing():
    with TestClient(app) as client:
        response = client.post('/messages/send', content=b'x' * (2 * 1024 * 1024 + 1))
        assert response.status_code == 413


def test_chunked_body_is_bounded_before_inner_app(monkeypatch):
    from app import body_limits
    monkeypatch.setattr(body_limits, 'MAX_MESSAGE_BODY_BYTES', 5)
    calls, sent = [], []
    async def inner(scope, receive, send):
        calls.append('called')
    async def send(event): sent.append(event)
    events = iter([{'type': 'http.request', 'body': b'123', 'more_body': True},
                   {'type': 'http.request', 'body': b'456', 'more_body': False}])
    async def receive(): return next(events)
    scope = {'type': 'http', 'method': 'POST', 'path': '/messages/send', 'headers': []}
    asyncio.run(MessageBodyLimitMiddleware(inner)(scope, receive, send))
    assert calls == [] and sent[0]['status'] == 413


def test_accepted_chunks_replayed_without_modification(monkeypatch):
    from app import body_limits
    monkeypatch.setattr(body_limits, 'MAX_MESSAGE_BODY_BYTES', 5)
    calls = []
    async def inner(scope, receive, send):
        calls.append(await receive())
    async def send(event): pass
    chunks = [{'type': 'http.request', 'body': b'12', 'more_body': True},
              {'type': 'http.request', 'body': b'345', 'more_body': False}]
    events = iter(chunks)
    async def receive(): return next(events)
    scope = {'type': 'http', 'method': 'POST', 'path': '/messages/send', 'headers': []}
    asyncio.run(MessageBodyLimitMiddleware(inner)(scope, receive, send))
    assert calls == [{'type': 'http.request', 'body': b'12345', 'more_body': False}]


def test_upload_content_length_rejected_before_endpoint(monkeypatch):
    from app import body_limits
    monkeypatch.setattr(body_limits, 'RAW_UPLOAD_BODY_BYTES', 5)
    with TestClient(app) as client:
        response = client.post('/files/upload-reliable/id', content=b'123456')
        assert response.status_code == 413


def test_chunked_upload_cap_and_cleanup(monkeypatch, tmp_path):
    from app import body_limits
    from app.api import files, messages
    from app.database import get_db
    monkeypatch.setattr(body_limits, 'MULTIPART_UPLOAD_BODY_BYTES', 100)
    monkeypatch.setattr(files, 'UPLOAD_DIR', str(tmp_path))
    # Override auth so the multipart parser can consume a chunked request.
    app.dependency_overrides[messages.get_current_device_id] = lambda: 'device'
    try:
        with TestClient(app) as client:
            body = (b'--x\r\nContent-Disposition: form-data; name="file"; filename="f"\r\n\r\n' + b'a' * 50 + b'\r\n--x--\r\n')
            response = client.post('/files/upload', headers={'content-type': 'multipart/form-data; boundary=x'}, content=iter([body[:80], body[80:]]))
            assert response.status_code == 413
            assert list(tmp_path.iterdir()) == []
    finally:
        app.dependency_overrides.clear()


def test_upload_middleware_checks_each_stream_chunk(monkeypatch):
    from app import body_limits
    from fastapi import HTTPException
    monkeypatch.setattr(body_limits, 'RAW_UPLOAD_BODY_BYTES', 5)
    seen = []
    async def inner(scope, receive, send):
        seen.append((await receive())['body'])
        with pytest.raises(HTTPException) as exc:
            await receive()
        assert exc.value.status_code == 413
    chunks = iter([{'type': 'http.request', 'body': b'123', 'more_body': True},
                   {'type': 'http.request', 'body': b'456', 'more_body': False}])
    async def receive(): return next(chunks)
    async def send(event): pass
    scope = {'type': 'http', 'method': 'POST', 'path': '/files/upload-reliable/id', 'headers': []}
    asyncio.run(body_limits.UploadBodyLimitMiddleware(inner)(scope, receive, send))
    assert seen == [b'123']


def test_other_json_endpoints_are_bounded_before_auth_and_validation(monkeypatch):
    from app import body_limits
    monkeypatch.setattr(body_limits, 'MAX_OTHER_BODY_BYTES', 64)
    with TestClient(app) as client:
        for method, path in [('POST','/auth/login'), ('POST','/messages/ack'),
                             ('POST','/groups/create'), ('PUT','/experimental/prekeys/bundle')]:
            response=client.request(method,path,content=b'x'*65)
            assert response.status_code == 413
        # The independent 2 MiB message cap is not replaced by this smaller cap.
        response=client.post('/messages/send',content=b'x'*65)
        assert response.status_code != 413


def test_general_chunked_body_rejected_before_inner_app(monkeypatch):
    from app import body_limits
    monkeypatch.setattr(body_limits,'MAX_OTHER_BODY_BYTES',5)
    calls=[]; sent=[]
    async def inner(scope,receive,send): calls.append('inner')
    async def send(event): sent.append(event)
    events=iter([{'type':'http.request','body':b'123','more_body':True},
                 {'type':'http.request','body':b'456','more_body':False}])
    async def receive(): return next(events)
    scope={'type':'http','method':'PUT','path':'/experimental/prekeys/bundle','headers':[]}
    asyncio.run(body_limits.GeneralBodyLimitMiddleware(inner)(scope,receive,send))
    assert calls==[] and sent[0]['status']==413


def test_auth_validation_does_not_reflect_credentials():
    password='secret-do-not-reflect'
    invitation='invite-do-not-reflect'
    with TestClient(app) as client:
        # Wrong type or excessive length forces Pydantic to include input in errors by default.
        response=client.post('/auth/login',json={'username':'u','password':password*100})
        assert response.status_code==422 and password not in response.text
        response=client.post('/auth/register',json={'username':'a','password':password,
             'invite_code':invitation*5,'device_name':'d','public_key':'k','fingerprint':'f'})
        assert response.status_code==422 and invitation not in response.text and password not in response.text
