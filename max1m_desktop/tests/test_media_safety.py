import base64
import io
import os
import wave
import pytest
from app import audio_waveform, voice_cache
from app.media_queue import MediaQueue

@pytest.fixture
def cache(tmp_path, monkeypatch):
    keys = {}
    monkeypatch.setattr(voice_cache.keyring, 'get_password', lambda s, n: keys.get((s, n)))
    monkeypatch.setattr(voice_cache.keyring, 'set_password', lambda s, n, v: keys.__setitem__((s, n), v))
    return voice_cache.VoiceCache(tmp_path), keys

def test_voice_scope_separates_profiles_chats_and_assets(cache):
    c, _ = cache
    a = voice_cache.message_scope('alice', 'https://one', 'bob', 'same')
    other_chat = voice_cache.message_scope('alice', 'https://one', 'charlie', 'same')
    assert len({a, other_chat, voice_cache.message_scope('alice', 'https://two', 'bob', 'same'), voice_cache.message_scope('other', 'https://one', 'bob', 'same')}) == 4
    x, y = voice_cache.asset_scope('file', 'key'), voice_cache.asset_scope('file', 'different-key')
    assert c.save(a, x, b'original') and c.load(a, x) == b'original'
    assert c.load(a, y) is None and c.load(other_chat, x) is None
    assert c.save(other_chat, x, b'other')
    c.delete_group(a)
    assert c.load(a, x) is None and c.load(other_chat, x) == b'other'

def test_missing_or_changed_key_never_deletes_or_overwrites(cache):
    c, keys = cache
    group, asset = voice_cache.message_scope('a', 'server', 'b', 'id'), voice_cache.asset_scope('f', 'k')
    assert c.save(group, asset, b'offline original')
    path = c._get_path(group, asset); original = path.read_bytes()
    c._box = None; keys.clear()
    assert c.load(group, asset) is None and not c.save(group, asset, b'new')
    assert path.read_bytes() == original and not keys
    keys[(voice_cache.SERVICE_NAME, voice_cache.CACHE_KEY_NAME)] = base64.b64encode(os.urandom(32)).decode()
    assert c.load(group, asset) is None and not c.save(group, asset, b'new')
    assert path.read_bytes() == original

def test_legacy_cache_preserved_and_blocks_rekey(cache):
    c, keys = cache
    legacy = c.cache_dir / 'old.bin'; legacy.write_bytes(b'legacy encrypted data')
    assert not c.save(voice_cache.message_scope('a', 's', 'b', 'id'), voice_cache.asset_scope('f', 'k'), b'hello')
    assert legacy.read_bytes() == b'legacy encrypted data' and not keys

def test_atomic_replace_failure_preserves_previous(cache, monkeypatch):
    c, _ = cache
    group, asset = voice_cache.message_scope('a', 's', 'b', 'id'), voice_cache.asset_scope('f', 'k')
    assert c.save(group, asset, b'old')
    monkeypatch.setattr(voice_cache.os, 'replace', lambda *args: (_ for _ in ()).throw(OSError('failure')))
    assert not c.save(group, asset, b'new') and c.load(group, asset) == b'old'
    assert not list(c.cache_dir.glob('.voice-*'))

def test_queue_bounds_reset_stale_completions_and_retry():
    started, failed = [], []
    q = MediaQueue(started.append, failed.append, max_active=2, max_pending=1)
    class Job: pass
    a, b, c, d = (Job() for _ in range(4))
    assert q.enqueue(a) and q.enqueue(b) and q.enqueue(c)
    assert not q.enqueue(d) and started == [a, b]
    q.reset()
    assert q.enqueue(d) and started == [a, b]
    assert not q.complete(a) and started == [a, b, d]
    assert not q.complete(b) and q.complete(d)
    assert not q.complete(d) and not q.pending

def test_queue_start_failure_releases_slot():
    failed, started = [], []
    class Job: pass
    bad, good = Job(), Job()
    def start(job):
        if job is bad: raise RuntimeError()
        started.append(job)
    q = MediaQueue(start, failed.append, max_active=1)
    assert q.enqueue(bad) and q.enqueue(good)
    assert failed == [bad] and started == [good] and q.complete(good)

def test_waveform_samples_bounded_chunks(monkeypatch):
    buf = io.BytesIO()
    with wave.open(buf, 'wb') as wav:
        wav.setnchannels(2); wav.setsampwidth(2); wav.setframerate(16000)
        wav.writeframes((b'\x01\x10\x00\x00') * 160000)
    real_open = wave.open; sizes = []
    class Wrapped:
        def __init__(self, inner): self.inner = inner
        def __enter__(self): return self
        def __exit__(self, *args): self.inner.close()
        def __getattr__(self, name): return getattr(self.inner, name)
        def readframes(self, n): sizes.append(n); return self.inner.readframes(n)
    monkeypatch.setattr(audio_waveform.wave, 'open', lambda *args, **kw: Wrapped(real_open(*args, **kw)))
    bars = audio_waveform.waveform_bars(buf.getvalue())
    assert len(bars) == 30 and all(v == 1 for v in bars)
    assert len(sizes) == 30 and max(sizes) <= 512

def test_download_worker_completes_after_result_and_exception(monkeypatch):
    from PySide6.QtCore import QCoreApplication, QEventLoop, QTimer
    from app import workers
    app = QCoreApplication.instance() or QCoreApplication([])
    for operation, expected in [(lambda *a: (True, b'data'), (True, b'data')),
                                (lambda *a: (_ for _ in ()).throw(OSError()), (False, b''))]:
        monkeypatch.setattr(workers.api, 'download_file', operation)
        worker = workers.DownloadFileWorker('server', 'token', 'file')
        loop = QEventLoop()
        completed = []
        worker.finished.connect(lambda w=worker: (completed.append((w.result, w.isRunning())), loop.quit()))
        QTimer.singleShot(3000, loop.quit)
        worker.start(); loop.exec()
        assert worker.wait(3000)
        assert completed == [(expected, False)]


def test_untrusted_attachment_identifiers_and_keys():
    import base64
    from app.media_identity import valid_file_id, valid_file_key
    assert valid_file_id('123e4567-e89b-42d3-a456-426614174000')
    assert not valid_file_id('../files/upload')
    assert not valid_file_id('123E4567-E89B-42D3-A456-426614174000')
    assert valid_file_key(base64.b64encode(bytes(range(32))).decode())
    assert not valid_file_key('a|b')
    assert not valid_file_key(base64.b64encode(b'short').decode())


def test_cached_box_does_not_write_after_keyring_loss(cache):
    c, keys = cache
    group = voice_cache.message_scope('a', 's', 'b', 'id')
    first, second = voice_cache.asset_scope('f', 'k'), voice_cache.asset_scope('g', 'k')
    assert c.save(group, first, b'first')
    keys.clear()
    assert not c.save(group, second, b'new')
    assert not c._get_path(group, second).exists()
    # The in-memory key can still read the existing data during this session.
    assert c.load(group, first) == b'first'
