"""Bound costly password operations without blocking the ASGI event loop."""
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi import HTTPException

# At most two 64 MiB Argon2 operations, plus a small bounded waiting queue.
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="password-hash")
_slots = threading.BoundedSemaphore(10)


async def run_password_job(func, *args):
    if not _slots.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="Сервер занят, попробуйте позже.", headers={"Retry-After": "5"})
    try:
        future = _executor.submit(func, *args)
    except BaseException:
        _slots.release()
        raise
    # The slot is released only when the underlying job actually finishes or
    # is cancelled before starting. Request cancellation cannot overrun the cap.
    future.add_done_callback(lambda _: _slots.release())
    return await asyncio.wrap_future(future)
