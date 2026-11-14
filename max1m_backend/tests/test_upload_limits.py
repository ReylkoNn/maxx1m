import asyncio
import threading
import pytest
from fastapi import HTTPException
from app import upload_limits


def test_upload_admission_releases_on_exception_and_fails_closed(monkeypatch):
    monkeypatch.setattr(upload_limits.settings,'MAX_CONCURRENT_UPLOADS_PER_PROCESS',1)
    with pytest.raises(RuntimeError):
        with upload_limits.admit_upload():
            with pytest.raises(HTTPException) as exc:
                with upload_limits.admit_upload(): pass
            assert exc.value.status_code==503
            raise RuntimeError('failure')
    with upload_limits.admit_upload(): pass
    monkeypatch.setattr(upload_limits.settings,'MAX_CONCURRENT_UPLOADS_PER_PROCESS',0)
    with pytest.raises(HTTPException) as exc:
        with upload_limits.admit_upload(): pass
    assert exc.value.status_code==503


def test_hash_jobs_are_bounded_even_if_requests_are_cancelled(monkeypatch):
    # Small independent semaphore makes the test deterministic without changing
    # the executor used by other tests.
    monkeypatch.setattr(upload_limits,'_hash_slots',threading.BoundedSemaphore(2))
    entered=threading.Event(); release=threading.Event(); lock=threading.Lock(); started=0
    def slow():
        nonlocal started
        with lock:
            started += 1
            if started == 2:
                entered.set()
        assert release.wait(5)
        return 'ok'
    async def scenario():
        first=asyncio.create_task(upload_limits.run_upload_hash(slow))
        second=asyncio.create_task(upload_limits.run_upload_hash(slow))
        try:
            assert await asyncio.to_thread(entered.wait,2)
            with pytest.raises(HTTPException) as exc:
                await upload_limits.run_upload_hash(lambda:None)
            assert exc.value.status_code==503
            first.cancel(); await asyncio.gather(first,return_exceptions=True)
            with pytest.raises(HTTPException):
                await upload_limits.run_upload_hash(lambda:None)
        finally:
            release.set()
            await asyncio.gather(first,second,return_exceptions=True)
        assert await upload_limits.run_upload_hash(lambda:'after')=='after'
    asyncio.run(scenario())
