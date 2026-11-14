import asyncio
import threading
import time

import pytest
from fastapi import HTTPException
from app.password_jobs import run_password_job


def test_password_work_is_bounded_and_cancellation_does_not_release_running_slot():
    started = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active = 0
    peak = 0

    def expensive():
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            if active == 2:
                started.set()
        release.wait(timeout=5)
        with lock:
            active -= 1
        return True

    async def exercise():
        tasks = [asyncio.create_task(run_password_job(expensive)) for _ in range(10)]
        try:
            # Yield until the two worker threads are running and all 10 slots reserved.
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert started.is_set()
            assert peak == 2
            with pytest.raises(HTTPException) as exc:
                await run_password_job(expensive)
            assert exc.value.status_code == 503
            tasks[0].cancel()
            await asyncio.gather(tasks[0], return_exceptions=True)
            # The cancelled request's still-running hash retains its slot.
            with pytest.raises(HTTPException) as exc:
                await run_password_job(expensive)
            assert exc.value.status_code == 503
        finally:
            release.set()
            await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.run(exercise())
    assert peak == 2
