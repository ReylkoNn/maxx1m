"""Idempotent raw upload regressions against a temporary SQLite DB."""
import uuid
import pytest
from fastapi.testclient import TestClient
from app import models
from app.api import files
from app.database import AsyncSessionLocal
from app.main import app
from app.security import create_access_token


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(files, "UPLOAD_DIR", str(tmp_path))
    monkeypatch.setattr(files, "MAX_FILE_SIZE", 1024)
    monkeypatch.setattr(app.state.limiter, "enabled", False)
    with TestClient(app) as client:
        async def seed():
            async with AsyncSessionLocal() as db:
                user = models.User(username="file-" + uuid.uuid4().hex, password_hash="unused")
                db.add(user)
                await db.flush()
                devices = [models.Device(user_id=user.id, device_name=str(i), public_key="key",
                                         fingerprint=uuid.uuid4().hex) for i in range(2)]
                db.add_all(devices)
                await db.commit()
                return user.id, [d.id for d in devices]
        user_id, ids = client.portal.call(seed)
        headers = [{"Authorization": "Bearer " + create_access_token({"sub": user_id, "device_id": device})}
                   for device in ids]
        yield client, tmp_path, headers, ids


def upload(client, fid, headers, body):
    return client.post(f"/files/upload-reliable/{fid}", headers=headers, content=body)


def test_retry_and_conflicts(setup):
    client, path, headers, ids = setup
    fid = str(uuid.uuid4())
    result = upload(client, fid, headers[0], b"ciphertext")
    assert result.status_code == 200 and result.json() == {"file_id": fid, "size": 10}
    assert upload(client, fid, headers[0], b"ciphertext").json() == result.json()
    assert upload(client, fid, headers[0], b"different!").status_code == 409
    assert upload(client, fid, headers[1], b"ciphertext").status_code == 409
    assert (path / fid).read_bytes() == b"ciphertext"
    assert [p.name for p in path.iterdir()] == [fid]
    assert client.get(f"/files/{fid}", headers=headers[0]).content == b"ciphertext"
    assert client.get(f"/files/{fid}", headers=headers[1]).status_code == 404
    assert client.post(f"/files/{fid}/grant", headers=headers[0], params={"recipient_device_id": ids[1]}).status_code == 200
    assert client.post(f"/files/{fid}/grant", headers=headers[0], params={"recipient_device_id": ids[1]}).status_code == 200
    assert client.get(f"/files/{fid}", headers=headers[1]).content == b"ciphertext"


def test_recovers_crash_after_file_publish(setup):
    client, path, headers, ids = setup
    fid = str(uuid.uuid4())
    # New servers reserve the owner before bytes are linked.
    async def reserve():
        async with AsyncSessionLocal() as db:
            await files._reserve_upload(db, fid, ids[0], str(path / fid))
    client.portal.call(reserve)
    (path / fid).write_bytes(b"encrypted")  # linked before process crashed, DB not committed
    assert upload(client, fid, headers[1], b"encrypted").status_code == 409
    assert upload(client, fid, headers[0], b"wrong data").status_code == 409
    assert upload(client, fid, headers[0], b"encrypted").status_code == 200
    assert client.get(f"/files/{fid}", headers=headers[0]).content == b"encrypted"


def test_invalid_size_and_missing_committed_file_fail_closed(setup):
    client, path, headers, _ = setup
    fid = str(uuid.uuid4())
    assert upload(client, "not-a-uuid", headers[0], b"secret").status_code == 400
    assert upload(client, fid, headers[0], b"x" * 1025).status_code == 400
    assert list(path.iterdir()) == []
    assert upload(client, fid, headers[0], b"data").status_code == 200
    (path / fid).unlink()
    assert upload(client, fid, headers[0], b"evil").status_code == 409
    assert not (path / fid).exists()


def test_concurrent_identical_retries_converge(setup):
    from concurrent.futures import ThreadPoolExecutor
    client, path, headers, _ = setup
    fid = str(uuid.uuid4())
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: upload(client, fid, headers[0], b"cipher" * 1000), range(2)))
    # The fixture limit is 1 KiB, so exercise a bounded payload instead.
    assert all(r.status_code == 400 for r in responses)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: upload(client, fid, headers[0], b"cipher" * 100), range(2)))
    assert [r.status_code for r in responses] == [200, 200]
    assert responses[0].json() == responses[1].json()
    assert (path / fid).read_bytes() == b"cipher" * 100


def test_commit_failure_can_resume_after_server_restart(setup, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession
    client, path, headers, _ = setup
    fid = str(uuid.uuid4())
    original = AsyncSession.commit
    commits = 0
    async def fail_commit(self):
        nonlocal commits
        commits += 1
        if commits == 2:
            raise RuntimeError("simulated DB failure after link")
        return await original(self)
    monkeypatch.setattr(AsyncSession, "commit", fail_commit)
    assert upload(client, fid, headers[0], b"cipher").status_code == 500
    assert (path / fid).read_bytes() == b"cipher"
    monkeypatch.setattr(AsyncSession, "commit", original)
    assert upload(client, fid, headers[0], b"cipher").status_code == 200
    assert client.get(f"/files/{fid}", headers=headers[0]).content == b"cipher"


def test_legacy_orphan_cannot_be_claimed_by_any_device(setup):
    client, path, headers, _ = setup
    fid = str(uuid.uuid4())
    (path / fid).write_bytes(b"unowned")
    assert upload(client, fid, headers[0], b"unowned").status_code == 409
    assert upload(client, fid, headers[1], b"unowned").status_code == 409
    assert (path / fid).read_bytes() == b"unowned"


def test_incomplete_reservations_limited_but_existing_retry_allowed(setup, monkeypatch):
    from app.config import settings
    client, path, headers, _ = setup
    monkeypatch.setattr(settings, "MAX_INCOMPLETE_UPLOADS_PER_DEVICE", 1)
    first, second = str(uuid.uuid4()), str(uuid.uuid4())
    assert upload(client, first, headers[0], b"x" * 1025).status_code == 400
    assert upload(client, second, headers[0], b"okay").status_code == 429
    assert upload(client, first, headers[1], b"okay").status_code == 409
    assert upload(client, first, headers[0], b"okay").status_code == 200
    assert upload(client, second, headers[0], b"okay").status_code == 200



def test_competing_devices_cannot_claim_same_upload(setup):
    from concurrent.futures import ThreadPoolExecutor
    client, path, headers, ids = setup
    fid = str(uuid.uuid4())
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda i: upload(client, fid, headers[i], b'identical'), range(2)))
    assert sorted(r.status_code for r in responses) == [200, 409]
    winner = next(i for i, r in enumerate(responses) if r.status_code == 200)
    assert client.get(f'/files/{fid}', headers=headers[winner]).status_code == 200
    assert client.get(f'/files/{fid}', headers=headers[1 - winner]).status_code == 404


@pytest.mark.parametrize('deactivate_account', [True, False])
def test_revocation_during_stream_prevents_commit(setup, monkeypatch, deactivate_account):
    from starlette.requests import Request
    client, path, headers, ids = setup
    fid = str(uuid.uuid4())
    original = Request.stream
    async def stream_with_revocation(self):
        async for chunk in original(self):
            yield chunk
        async with AsyncSessionLocal() as db:
            device = await db.get(models.Device, ids[0])
            if deactivate_account:
                user = await db.get(models.User, device.user_id)
                user.is_active = False
            else:
                device.is_revoked = True
            await db.commit()
    monkeypatch.setattr(Request, 'stream', stream_with_revocation)
    assert upload(client, fid, headers[0], b'ciphertext').status_code == 401
    async def inspect():
        async with AsyncSessionLocal() as db:
            return (await db.get(models.FileRecord, fid), await db.get(models.UploadReservation, fid))
    record, reservation = client.portal.call(inspect)
    assert record is None and reservation.device_id == ids[0]
    assert (path / fid).read_bytes() == b'ciphertext'


def test_grant_rejects_device_of_inactive_account(setup):
    client, path, headers, ids = setup
    fid = str(uuid.uuid4())
    assert upload(client, fid, headers[0], b'ciphertext').status_code == 200
    async def inactive_recipient():
        async with AsyncSessionLocal() as db:
            user = models.User(username='inactive-' + uuid.uuid4().hex, password_hash='unused', is_active=False)
            db.add(user)
            await db.flush()
            recipient = models.Device(user_id=user.id, device_name='other', public_key='key', fingerprint=uuid.uuid4().hex)
            db.add(recipient)
            await db.commit()
            return recipient.id
    target = client.portal.call(inactive_recipient)
    assert client.post(f'/files/{fid}/grant', headers=headers[0], params={'recipient_device_id': target}).status_code == 404
    async def has_access():
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(models.FileAccess).where(models.FileAccess.file_id == fid,
                                      models.FileAccess.device_id == target))).scalars().first()
    assert client.portal.call(has_access) is None


def test_legacy_upload_works_with_real_database(setup):
    client, path, headers, ids = setup
    response = client.post('/files/upload', headers=headers[0], files={'file': ('blob', b'encrypted')})
    assert response.status_code == 200, response.text
    assert (path / response.json()['file_id']).read_bytes() == b'encrypted'


def test_legacy_upload_device_revoked_during_copy_removes_partial(setup, monkeypatch):
    from starlette.datastructures import UploadFile
    client, path, headers, ids = setup
    original = UploadFile.read
    changed = False
    async def revoke_during_read(self, size=-1):
        nonlocal changed
        data = await original(self, size)
        if data and not changed:
            changed = True
            async with AsyncSessionLocal() as db:
                device = await db.get(models.Device, ids[0])
                device.is_revoked = True
                await db.commit()
        return data
    monkeypatch.setattr(UploadFile, 'read', revoke_during_read)
    response = client.post('/files/upload', headers=headers[0], files={'file': ('blob', b'encrypted')})
    assert response.status_code == 401, response.text
    assert list(path.iterdir()) == []


def test_legacy_blob_preserved_if_commit_succeeds_then_raises(setup, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import select
    client, path, headers, ids = setup
    original = AsyncSession.commit
    calls = 0
    async def committed_then_failed(self):
        nonlocal calls
        await original(self)
        calls += 1
        if calls == 1:
            raise RuntimeError('simulated lost commit result')
    monkeypatch.setattr(AsyncSession, 'commit', committed_then_failed)
    response = client.post('/files/upload', headers=headers[0], files={'file': ('blob', b'encrypted')})
    assert response.status_code == 500
    async def lookup():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(models.FileRecord).where(
                models.FileRecord.uploaded_by_device_id == ids[0]))).scalars().all()
    records = client.portal.call(lookup)
    assert len(records) == 1 and (path / records[0].id).read_bytes() == b'encrypted'
    assert client.get('/files/' + records[0].id, headers=headers[0]).content == b'encrypted'


def test_published_hash_is_bounded_for_oversized_file(tmp_path, monkeypatch):
    import builtins
    original=builtins.open; calls=[]
    path=tmp_path/'oversized'; path.write_bytes(b'x'*(2*1024*1024))
    class Tracked:
        def __init__(self, stream): self.stream=stream
        def __enter__(self): return self
        def __exit__(self,*args): self.stream.close()
        def read(self,n): calls.append(n); return self.stream.read(n)
    monkeypatch.setattr(builtins,'open',lambda *args,**kw:Tracked(original(*args,**kw)))
    size,digest=files._hash_published_file(path,4)
    assert (size,digest)==(5,None) and calls==[5]


def test_published_hash_does_not_block_event_loop(monkeypatch):
    import asyncio
    import threading
    entered=threading.Event(); release=threading.Event()
    def slow_hash(*args):
        entered.set()
        assert release.wait(5)
        return 4,b'digest'
    monkeypatch.setattr(files,'_hash_published_file',slow_hash)
    async def scenario():
        task=asyncio.create_task(files._verify_published_file('unused',4,b'digest'))
        try:
            assert await asyncio.to_thread(entered.wait,2)
            # This coroutine runs before hashing is released.
            assert not task.done()
        finally:
            release.set()
        await task
    asyncio.run(scenario())


def test_upload_admission_bounds_concurrent_authenticated_requests_and_allows_retry(setup, monkeypatch):
    import asyncio
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from starlette.requests import Request
    from app.config import settings
    client,path,headers,ids=setup
    monkeypatch.setattr(settings,'MAX_CONCURRENT_UPLOADS_PER_PROCESS',1)
    first_id,second_id=str(uuid.uuid4()),str(uuid.uuid4())
    entered=threading.Event(); release=threading.Event(); original=Request.stream
    async def slow_stream(self):
        if self.url.path.endswith(first_id):
            entered.set()
            if not await asyncio.to_thread(release.wait,5):
                raise RuntimeError('test timed out')
        async for chunk in original(self):
            yield chunk
    monkeypatch.setattr(Request,'stream',slow_stream)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first=pool.submit(upload,client,first_id,headers[0],b'cipher')
        try:
            assert entered.wait(3)
            rejected=upload(client,second_id,headers[0],b'second')
            assert rejected.status_code==503 and rejected.headers['retry-after']=='5'
            assert client.get('/').status_code==200
            unauthenticated=client.post('/files/upload',files={'file':('x',b'abc')})
            assert unauthenticated.status_code in (401,403)
            async def reservation():
                async with AsyncSessionLocal() as db:
                    return await db.get(models.UploadReservation,second_id)
            assert client.portal.call(reservation) is None
            assert not (path/second_id).exists()
        finally:
            release.set()
        assert first.result(timeout=5).status_code==200
    assert upload(client,second_id,headers[0],b'second').status_code==200


def test_multipart_and_reliable_share_admission_and_release_on_failure(setup, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from starlette.datastructures import UploadFile
    from app.config import settings
    client,path,headers,ids=setup
    monkeypatch.setattr(settings,'MAX_CONCURRENT_UPLOADS_PER_PROCESS',1)
    entered=threading.Event(); release=threading.Event(); original=UploadFile.read
    async def slow_read(self,size=-1):
        import asyncio
        entered.set()
        if not await asyncio.to_thread(release.wait,5): raise RuntimeError('test timeout')
        return await original(self,size)
    monkeypatch.setattr(UploadFile,'read',slow_read)
    fid=str(uuid.uuid4())
    with ThreadPoolExecutor(max_workers=1) as pool:
        legacy=pool.submit(client.post,'/files/upload',headers=headers[0],files={'file':('x',b'legacy')})
        try:
            assert entered.wait(3)
            assert upload(client,fid,headers[0],b'raw').status_code==503
        finally:
            release.set()
        assert legacy.result(timeout=5).status_code==200
    assert upload(client,fid,headers[0],b'raw').status_code==200
    # A rejected oversized request must not leak a slot.
    assert upload(client,str(uuid.uuid4()),headers[0],b'x'*1025).status_code==400
    assert upload(client,str(uuid.uuid4()),headers[0],b'ok').status_code==200


def test_hash_admission_busy_keeps_reserved_published_file_for_retry(setup, monkeypatch):
    from fastapi import HTTPException
    client,path,headers,ids=setup
    file_id=str(uuid.uuid4()); original=files.run_upload_hash
    async def busy(*args):
        raise HTTPException(503,'Upload verification temporarily busy',headers={'Retry-After':'5'})
    monkeypatch.setattr(files,'run_upload_hash',busy)
    result=upload(client,file_id,headers[0],b'cipher')
    assert result.status_code==503 and result.headers['retry-after']=='5'
    assert (path/file_id).read_bytes()==b'cipher'
    async def records():
        async with AsyncSessionLocal() as db:
            return await db.get(models.FileRecord,file_id), await db.get(models.UploadReservation,file_id)
    record,reservation=client.portal.call(records)
    assert record is None and reservation.device_id==ids[0]
    monkeypatch.setattr(files,'run_upload_hash',original)
    assert upload(client,file_id,headers[0],b'cipher').status_code==200
    assert client.get('/files/'+file_id,headers=headers[0]).content==b'cipher'


def test_interrupted_stream_releases_slot_and_keeps_reservation_for_owner(setup, monkeypatch):
    from starlette.requests import Request, ClientDisconnect
    from app.config import settings
    client,path,headers,ids=setup
    monkeypatch.setattr(settings,'MAX_CONCURRENT_UPLOADS_PER_PROCESS',1)
    file_id=str(uuid.uuid4()); original=Request.stream
    async def interrupted(self):
        yield b'partial'
        raise ClientDisconnect()
    monkeypatch.setattr(Request,'stream',interrupted)
    assert upload(client,file_id,headers[0],b'ignored').status_code==500
    assert not (path/file_id).exists() and not list(path.glob('.upload-*'))
    async def reservation():
        async with AsyncSessionLocal() as db:
            return await db.get(models.UploadReservation,file_id)
    assert client.portal.call(reservation).device_id==ids[0]
    monkeypatch.setattr(Request,'stream',original)
    assert upload(client,file_id,headers[0],b'complete').status_code==200
