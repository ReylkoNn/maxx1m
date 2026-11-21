"""Thread-safe identity and cancellation for one active call generation."""
import asyncio
import threading


MAX_PENDING_CALL_TASKS = 128


class CallLifecycle:
    def __init__(self):
        self._lock = threading.Lock()
        self._active = None
        self._tasks = set()

    def activate(self, peer_id, call_id):
        if not isinstance(peer_id, str) or not peer_id or not isinstance(call_id, str) or not call_id:
            raise ValueError('Missing call identity')
        with self._lock:
            if self._active is not None:
                raise RuntimeError('Call already active')
            self._active = (peer_id, call_id)

    def matches(self, peer_id, call_id):
        with self._lock:
            return self._active == (peer_id, call_id)

    def idle(self):
        with self._lock:
            return self._active is None

    def submit(self, loop, peer_id, call_id, coroutine):
        with self._lock:
            if self._active != (peer_id, call_id) or len(self._tasks) >= MAX_PENDING_CALL_TASKS:
                coroutine.close()
                return None
            try:
                future = asyncio.run_coroutine_threadsafe(coroutine, loop)
            except BaseException:
                coroutine.close()
                raise
            self._tasks.add(future)
        def done(completed):
            with self._lock:
                self._tasks.discard(completed)
        future.add_done_callback(done)
        return future

    def invalidate(self):
        with self._lock:
            previous, self._active = self._active, None
            tasks, self._tasks = self._tasks, set()
        # Never cancel while holding the lock: callbacks can run synchronously.
        for task in tasks:
            task.cancel()
        return previous
