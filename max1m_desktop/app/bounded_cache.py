"""Small least-recently-used cache for already-decrypted media."""
from collections import OrderedDict


class BoundedBytesCache:
    def __init__(self, max_bytes: int):
        if max_bytes < 0:
            raise ValueError("max_bytes must not be negative")
        self.max_bytes = max_bytes
        self.size_bytes = 0
        self._items = OrderedDict()

    def __contains__(self, key):
        return key in self._items

    def __getitem__(self, key):
        value = self._items[key]
        self._items.move_to_end(key)
        return value

    def __setitem__(self, key, value):
        if not isinstance(value, bytes):
            raise TypeError("cache values must be bytes")
        if key in self._items:
            self.size_bytes -= len(self._items.pop(key))
        if len(value) > self.max_bytes:
            return
        while self.size_bytes + len(value) > self.max_bytes:
            _, old = self._items.popitem(last=False)
            self.size_bytes -= len(old)
        self._items[key] = value
        self.size_bytes += len(value)

    def pop(self, key, default=None):
        if key not in self._items:
            return default
        val = self._items.pop(key)
        self.size_bytes -= len(val)
        return val

    def delete_prefix(self, prefix: tuple) -> int:
        if not isinstance(prefix, tuple):
            return 0
        plen = len(prefix)
        matching = [
            k for k in list(self._items.keys())
            if isinstance(k, tuple) and len(k) >= plen and k[:plen] == prefix
        ]
        for k in matching:
            val = self._items.pop(k)
            self.size_bytes -= len(val)
        return len(matching)

    def clear(self):
        self._items.clear()
        self.size_bytes = 0
