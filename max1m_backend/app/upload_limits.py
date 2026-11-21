"""Per-process admission and bounded disk-hash workers for uploads.

These limits do not coordinate multiple ASGI processes or replace reverse-proxy
connection, timeout, and disk quotas.
"""
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

from fastapi import HTTPException
from app.config import settings

_lock = threading.Lock()
_active = 0
_hash_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='upload-hash')
_hash_slots = threading.BoundedSemaphore(8)


@contextmanager
def admit_upload():
    global _active
    with _lock:
        limit = settings.MAX_CONCURRENT_UPLOADS_PER_PROCESS
        if type(limit) is not int or limit < 1:
            raise HTTPException(503, 'Invalid upload concurrency configuration')
        if _active >= limit:
            raise HTTPException(503, 'Upload capacity temporarily exhausted', headers={'Retry-After': '5'})
        _active += 1
    try:
        yield
    finally:
        with _lock:
            _active -= 1


async def run_upload_hash(func, *args):
    # Cancellation cannot release a slot until the underlying disk job has
    # finished (or has been cancelled while still waiting in the executor).
    slots = _hash_slots
    if not slots.acquire(blocking=False):
        raise HTTPException(503, 'Upload verification temporarily busy', headers={'Retry-After': '5'})
    try:
        future = _hash_executor.submit(func, *args)
    except BaseException:
        slots.release()
        raise
    future.add_done_callback(lambda _: slots.release())
    return await asyncio.wrap_future(future)
