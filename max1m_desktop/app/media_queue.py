"""GUI-thread scheduler for bounded attachment downloads."""
from collections import deque


class MediaQueue:
    def __init__(self, start, failed, max_active=2, max_pending=100):
        if max_active < 1 or max_pending < 0:
            raise ValueError('Invalid download limits')
        self.start, self.failed = start, failed
        self.max_active, self.max_pending = max_active, max_pending
        self.active = set()
        self.pending = deque()
        self.generation = 0

    def enqueue(self, worker):
        if len(self.active) >= self.max_active and len(self.pending) >= self.max_pending:
            return False
        worker.media_generation = self.generation
        self.pending.append(worker)
        self._pump()
        return True

    def _pump(self):
        while self.pending and len(self.active) < self.max_active:
            worker = self.pending.popleft()
            self.active.add(worker)
            try:
                self.start(worker)
            except Exception:
                self.active.remove(worker)
                self.failed(worker)

    def complete(self, worker):
        if worker not in self.active:
            return False
        self.active.remove(worker)
        current = worker.media_generation == self.generation
        self._pump()
        return current

    def reset(self):
        self.generation += 1
        self.pending.clear()
