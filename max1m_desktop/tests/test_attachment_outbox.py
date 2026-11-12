import uuid
import json
from types import SimpleNamespace
import pytest
from app import attachment_outbox as attachments, outbox, secure_storage
from app.recipient_context import capture_recipient


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, "get_password", lambda svc, key: keys.get(key))
    monkeypatch.setattr(secure_storage.keyring, "set_password", lambda svc, key, value: keys.__setitem__(key, value))
    state = SimpleNamespace(username="alice", device_id="mine", server_url="https://node", current_chat_type="ally",
                            current_chat_username="bob", current_chat_device_id="b",
                            allies={"bob": {"devices": [{"device_id": "b", "public_key": "key"}]}})
    return capture_recipient(state)


def test_restart_and_idempotent_transfer_to_outbox(setup):
    ctx = setup
    fid, mid = str(uuid.uuid4()), str(uuid.uuid4())
    payload = {"receiver_device_id": "b", "encrypted_blob": "envelope", "signature": "sig"}
    hist = {"ally_username": "bob", "text": "[IMAGE_META]|file|secret", "msg_id": "msg1"}
    job_path = attachments.enqueue(ctx, b"encrypted file", fid, mid, payload, hist)
    assert b"secret" not in job_path.read_bytes()
    job, blob, record = attachments.next_job("alice", "https://node", "mine")
    assert job == job_path and record["file_id"] == fid
    assert attachments.next_job("alice", "https://other", "mine") is None
    attachments.validate_blob(blob, record)
    # Crash after this enqueue, before job removal: repeat is locally idempotent.
    for _ in range(2):
        outbox.enqueue("alice", "https://node", "mine", payload, hist, message_id=mid)
    assert len(list(outbox._directory("alice", "https://node", "mine").glob("*.enc"))) == 1
    with pytest.raises(ValueError):
        outbox.enqueue("alice", "https://node", "mine", {**payload, "signature": "different"}, hist, message_id=mid)
    attachments.finish(job, blob, "alice", "https://node", "mine", fid)
    assert not job.exists() and not blob.exists()
    assert outbox.next_message("alice", "https://node", "mine")[1]["client_message_id"] == mid


def test_failure_does_not_leave_uncommitted_job_and_corruption_is_rejected(setup, monkeypatch):
    ctx = setup
    fid, mid = str(uuid.uuid4()), str(uuid.uuid4())
    original = attachments._atomic_write
    def fail_job(path, data):
        if path.suffix == ".job": raise OSError("disk full")
        original(path, data)
    monkeypatch.setattr(attachments, "_atomic_write", fail_job)
    with pytest.raises(OSError): attachments.enqueue(ctx, b"cipher", fid, mid, {}, {})
    assert not list(attachments._dir("alice", "https://node", "mine").iterdir())
    monkeypatch.setattr(attachments, "_atomic_write", original)
    attachments.enqueue(ctx, b"cipher", fid, mid, {}, {})
    job, blob, record = attachments.next_job("alice", "https://node", "mine")
    blob.write_bytes(b"changed")
    with pytest.raises(ValueError): attachments.validate_blob(blob, record)
    assert job.exists()


def test_queue_bounded_by_count_and_bytes(setup, monkeypatch):
    ctx = setup
    monkeypatch.setattr(attachments, "MAX_TOTAL_BYTES", 5)
    with pytest.raises(ValueError): attachments.enqueue(ctx, b"123456", str(uuid.uuid4()), str(uuid.uuid4()), {}, {})
    attachments.enqueue(ctx, b"12345", str(uuid.uuid4()), str(uuid.uuid4()), {}, {})
    with pytest.raises(ValueError): attachments.enqueue(ctx, b"1", str(uuid.uuid4()), str(uuid.uuid4()), {}, {})


FILE_ID = '123e4567-e89b-42d3-a456-426614174000'


def test_reliable_upload_streams_and_checks_server_response(tmp_path, monkeypatch):
    from app.client_api import APIClient
    from types import SimpleNamespace
    path = tmp_path / "blob"
    path.write_bytes(b"ciphertext")
    calls = []
    responses = [{"file_id": "other", "size": 10}, {"file_id": FILE_ID, "size": 9},
                 {"file_id": FILE_ID, "size": 10}]
    def post(url, **kwargs):
        assert url.endswith(f"/files/upload-reliable/{FILE_ID}")
        assert kwargs["data"].read() == b"ciphertext"
        calls.append(url)
        return SimpleNamespace(status_code=200, iter_content=lambda _: [json.dumps(responses.pop(0)).encode()], close=lambda: None)
    monkeypatch.setattr("app.client_api.requests.post", post)
    api = APIClient()
    assert not api.upload_file_reliable("https://node", "token", FILE_ID, path)[0]
    assert not api.upload_file_reliable("https://node", "token", FILE_ID, path)[0]
    assert api.upload_file_reliable("https://node", "token", FILE_ID, path)[0]
    assert len(calls) == 3


def test_grant_requires_matching_response(monkeypatch):
    from app.client_api import APIClient
    responses = [{"status": "ok", "file_id": FILE_ID, "granted_to": "wrong"},
                 {"status": "ok", "file_id": FILE_ID, "granted_to": "device"}]
    monkeypatch.setattr("app.client_api.requests.post", lambda *a, **kw:
                        SimpleNamespace(status_code=200, iter_content=lambda _: [json.dumps(responses.pop(0)).encode()], close=lambda: None))
    api = APIClient()
    assert not api.grant_file_access("https://node", "token", FILE_ID, "device")[0]
    assert api.grant_file_access("https://node", "token", FILE_ID, "device")[0]


@pytest.mark.parametrize('method', ['upload', 'grant'])
def test_attachment_responses_are_bounded(tmp_path, monkeypatch, method):
    from app.client_api import APIClient
    from types import SimpleNamespace
    blob = tmp_path / 'blob'
    blob.write_bytes(b'cipher')
    closed = []
    response = SimpleNamespace(status_code=200, iter_content=lambda _: [b'x' * (16 * 1024 + 1)], close=lambda: closed.append(True))
    monkeypatch.setattr('app.client_api.requests.post', lambda *a, **kw: response)
    api = APIClient()
    result = (api.upload_file_reliable('https://node', 'token', FILE_ID, blob) if method == 'upload'
              else api.grant_file_access('https://node', 'token', FILE_ID, 'device'))
    assert not result[0] and closed == [True]


def test_corrupt_attachment_job_is_retained_and_can_be_skipped(setup, monkeypatch):
    ctx = setup
    first = attachments.enqueue(ctx, b'blob', str(uuid.uuid4()), str(uuid.uuid4()), {}, {})
    second = attachments.enqueue(ctx, b'other', str(uuid.uuid4()), str(uuid.uuid4()), {}, {})
    first, second = sorted((first, second))
    first.write_bytes(b'x' * 1025)
    monkeypatch.setattr(outbox, 'MAX_ENCRYPTED_RECORD_BYTES', 1024)
    with pytest.raises(outbox.QueueRecordError) as exc:
        attachments.next_job('alice', 'https://node', 'mine')
    assert exc.value.path == first and first.exists()
    assert attachments.next_job('alice', 'https://node', 'mine', {first.name})[0] == second


def test_deep_or_non_object_job_is_preserved_and_skipped(setup):
    import nacl.secret
    ctx=setup
    job=attachments.enqueue(ctx,b'blob',str(uuid.uuid4()),str(uuid.uuid4()),{}, {})
    good=attachments.enqueue(ctx,b'blob2',str(uuid.uuid4()),str(uuid.uuid4()),{}, {})
    first,second=sorted((job,good))
    key=secure_storage.SecureStorage._get_or_create_local_key('alice')
    box=nacl.secret.SecretBox(key)
    for encoded in (b'['*1200+b'0'+b']'*1200,b'null'):
        first.write_bytes(box.encrypt(encoded))
        with pytest.raises(outbox.QueueRecordError): attachments.next_job('alice','https://node','mine')
        assert first.exists() and attachments.next_job('alice','https://node','mine',{first.name})[0]==second


def test_blob_validation_stops_reading_at_declared_size_plus_one(setup, monkeypatch):
    ctx=setup
    job_path=attachments.enqueue(ctx,b'good',str(uuid.uuid4()),str(uuid.uuid4()),{}, {})
    job,blob,record=attachments.next_job('alice','https://node','mine')
    blob.write_bytes(b'x'*(4*1024*1024))
    import builtins
    real_open=builtins.open; reads=[]
    class Tracked:
        def __init__(self,stream): self.stream=stream
        def __enter__(self): return self
        def __exit__(self,*args): self.stream.close()
        def read(self,n): reads.append(n); return self.stream.read(n)
    def tracking_open(path,*args,**kwargs): return Tracked(real_open(path,*args,**kwargs))
    monkeypatch.setattr(builtins,'open',tracking_open)
    with pytest.raises(ValueError,match='Corrupt'): attachments.validate_blob(blob,record)
    assert reads==[5] and job_path.exists() and blob.exists()


@pytest.mark.parametrize('size,checksum', [(True,'a'*64), (0,'a'*64), (1,'x'*64), (1,'a'*63), (129*1024*1024,'a'*64)])
def test_invalid_attachment_metadata_rejected_before_read(setup,size,checksum):
    with pytest.raises(ValueError,match='metadata'):
        attachments.validate_blob('does-not-exist',{'size':size,'sha256':checksum})


def test_upload_authenticates_snapshot_and_sends_exact_verified_bytes(tmp_path, monkeypatch):
    import hashlib
    from app.crypto_box import CryptoManager
    from app.workers import ReliableUploadFileWorker
    crypto=CryptoManager(); key=crypto.generate_file_key()
    ciphertext=crypto.encrypt_file(b'private content',key)
    path=tmp_path/'queued.blob'; path.write_bytes(ciphertext)
    calls=[]
    def post(url,**kw):
        # Replacing the file after authentication cannot change the outgoing bytes.
        path.write_bytes(b'changed on disk')
        calls.append(kw['data'].read())
        body=json.dumps({'file_id':FILE_ID,'size':len(ciphertext)}).encode()
        return SimpleNamespace(status_code=200,iter_content=lambda _: [body],close=lambda:None)
    monkeypatch.setattr('app.client_api.requests.post',post)
    worker=ReliableUploadFileWorker('https://node','token',FILE_ID,path,len(ciphertext),hashlib.sha256(ciphertext).hexdigest(),key)
    results=[]; worker.finished.connect(lambda ok,data:results.append((ok,data))); worker.run()
    assert calls==[ciphertext] and results[0][0] is True and worker.file_key is None
    assert path.read_bytes()==b'changed on disk'


def test_invalid_key_or_ciphertext_never_starts_upload(tmp_path, monkeypatch):
    import hashlib
    from app.crypto_box import CryptoManager
    from app.workers import ReliableUploadFileWorker
    crypto=CryptoManager(); key=crypto.generate_file_key(); wrong=crypto.generate_file_key()
    ciphertext=crypto.encrypt_file(b'private content',key)
    path=tmp_path/'queued.blob'; calls=[]
    monkeypatch.setattr('app.client_api.requests.post',lambda *a,**kw:calls.append(1))
    for content,used_key,checksum in ((ciphertext,wrong,hashlib.sha256(ciphertext).hexdigest()),
                                      (ciphertext[:-1]+bytes([ciphertext[-1]^1]),key,hashlib.sha256(ciphertext).hexdigest()),
                                      (ciphertext,key,'bad')):
        path.write_bytes(content)
        worker=ReliableUploadFileWorker('https://node','token','f',path,len(content),checksum,used_key)
        results=[]; worker.finished.connect(lambda ok,data:results.append((ok,data))); worker.run()
        assert results==[(False,'ATTACHMENT_INVALID')] and worker.file_key is None
        assert path.read_bytes()==content
    assert not calls


def test_oversized_attachment_snapshot_is_rejected_without_open(monkeypatch):
    monkeypatch.setattr('builtins.open',lambda *a,**kw:pytest.fail('oversized data must not be read'))
    with pytest.raises(ValueError,match='metadata'):
        attachments.authenticated_snapshot('unused',attachments.MAX_AUTHENTICATED_UPLOAD_BYTES+1,'a'*64,'key')


def test_oversized_queued_file_reports_specific_error_and_is_retained(tmp_path, monkeypatch):
    from app.workers import ReliableUploadFileWorker
    from app.crypto_box import CryptoManager
    path=tmp_path/'blob'; path.write_bytes(b'preserved')
    monkeypatch.setattr('app.client_api.requests.post',lambda *a,**kw:pytest.fail('must not upload'))
    worker=ReliableUploadFileWorker('https://node','token','id',path,
                                   attachments.MAX_AUTHENTICATED_UPLOAD_BYTES+1,'a'*64,
                                   CryptoManager().generate_file_key())
    result=[]; worker.finished.connect(lambda ok,data:result.append((ok,data))); worker.run()
    assert result==[(False,'ATTACHMENT_TOO_LARGE')] and path.read_bytes()==b'preserved'
    assert worker.file_key is None


def test_attachment_authentication_runs_in_real_qthread(tmp_path, monkeypatch):
    import hashlib
    import threading
    from PySide6.QtCore import QCoreApplication, QEventLoop, QTimer
    from app.crypto_box import CryptoManager
    from app.workers import ReliableUploadFileWorker
    app=QCoreApplication.instance() or QCoreApplication([])
    manager=CryptoManager(); key=manager.generate_file_key(); blob=manager.encrypt_file(b'hello',key)
    path=tmp_path/'blob'; path.write_bytes(blob)
    original=attachments.authenticated_snapshot; threads=[]
    def wrapped(*args):
        threads.append(threading.get_ident())
        return original(*args)
    monkeypatch.setattr(attachments,'authenticated_snapshot',wrapped)
    monkeypatch.setattr('app.workers.api.upload_file_reliable',lambda *args:(True,{'ok':True}))
    worker=ReliableUploadFileWorker('https://node','token','id',path,len(blob),hashlib.sha256(blob).hexdigest(),key)
    loop=QEventLoop(); results=[]
    def finished(ok,data): results.append((ok,data)); loop.quit()
    worker.finished.connect(finished); worker.start()
    QTimer.singleShot(4000,loop.quit); loop.exec()
    assert worker.wait(4000)
    assert results==[(True,{'ok':True})] and threads and threads[0] != threading.get_ident()
