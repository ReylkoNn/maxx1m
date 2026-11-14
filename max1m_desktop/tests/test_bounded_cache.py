import pytest
from app.bounded_cache import BoundedBytesCache


def test_eviction_and_recent_access():
    cache = BoundedBytesCache(5)
    cache["one"] = b"11"
    cache["two"] = b"22"
    assert cache["one"] == b"11"
    cache["three"] = b"333"
    assert "two" not in cache
    assert cache["one"] == b"11" and cache["three"] == b"333"
    assert cache.size_bytes == 5


def test_replace_oversized_and_clear():
    cache = BoundedBytesCache(4)
    cache["one"] = b"aa"
    cache["one"] = b"b"
    assert cache.size_bytes == 1
    cache["one"] = b"12345"
    assert "one" not in cache and cache.size_bytes == 0
    cache["two"] = b"12"
    cache.clear()
    assert cache.size_bytes == 0 and "two" not in cache
    with pytest.raises(TypeError):
        cache["invalid"] = "text"
