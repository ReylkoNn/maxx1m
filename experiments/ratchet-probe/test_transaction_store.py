import concurrent.futures
import os
import sqlite3
import pytest
from transaction_store import Store, Conflict


@pytest.fixture
def store(tmp_path):
    path, key, scope = tmp_path / 'test.db', os.urandom(32), ('alice', 'server', 'mine', 'peer')
    s = Store(path, key, scope)
    s.init({'private_state': 'secret state'})
    return s, path, key, scope


def fault(): raise OSError('simulated failure')


def test_send_is_atomic_and_retry_uses_stored_ciphertext(store):
    s, path, key, scope = store
    with pytest.raises(OSError): s.commit_outgoing(0, {'step': 1}, 'msg1', 'wire1', {'text': 'private text'}, fault)
    assert s.snapshot() == (0, {'private_state': 'secret state'})
    assert s.get_outgoing('msg1') is None
    s.commit_outgoing(0, {'step': 1}, 'msg1', 'wire1', {'text': 'private text'})
    s = Store(path, key, scope)
    assert s.snapshot() == (1, {'step': 1})
    assert s.get_outgoing('msg1')['wire'] == 'wire1'
    with pytest.raises(Conflict): s.commit_outgoing(1, {'step': 2}, 'msg1', 'other', {})
    assert s.snapshot() == (1, {'step': 1})
    assert b'private text' not in path.read_bytes() and b'secret state' not in path.read_bytes()
    s.acknowledge_outgoing('msg1')
    assert s.get_outgoing('msg1') is None
    assert s.get_sent_history('msg1') == {'text': 'private text'}
    with pytest.raises(Conflict): s.commit_outgoing(1, {'step': 2}, 'msg1', 'other', {})


def test_incoming_commit_duplicate_and_failure(store):
    s, _, _, _ = store
    assert not s.seen_incoming('serverid', b'signed encrypted wire')
    with pytest.raises(OSError): s.commit_incoming(0, {'step': 1}, 'serverid', b'signed encrypted wire', {'text': 'hello'}, fault)
    assert s.snapshot()[0] == 0 and not s.seen_incoming('serverid', b'signed encrypted wire')
    assert s.commit_incoming(0, {'step': 1}, 'serverid', b'signed encrypted wire', {'text': 'hello'})
    assert s.seen_incoming('serverid', b'signed encrypted wire')
    assert s.commit_incoming(0, {'bad': 1}, 'serverid', b'signed encrypted wire', {}) is False
    assert s.snapshot() == (1, {'step': 1}) and s.get_incoming('serverid') == {'text': 'hello'}
    with pytest.raises(Conflict): s.seen_incoming('serverid', b'tampered')


def test_stale_parallel_transitions_cannot_overwrite_or_reuse_counter(store):
    s, path, key, scope = store
    def commit(i):
        try:
            Store(path, key, scope).commit_outgoing(0, {'step': i}, f'msg{i}', f'wire{i}', {})
            return True
        except Conflict: return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(commit, [1, 2]))
    assert sorted(outcomes) == [False, True]
    assert s.snapshot()[0] == 1
    assert sum(s.get_outgoing(f'msg{i}') is not None for i in [1, 2]) == 1


def test_wrong_scope_wrong_key_and_tampering_fail_closed(store):
    s, path, key, scope = store
    with pytest.raises(Conflict): Store(path, key, ('alice', 'server', 'mine', 'other'))
    with pytest.raises(Exception): Store(path, os.urandom(32), scope).snapshot()
    s.commit_incoming(0, {'step': 1}, 'id', b'wire', {'text': 'secret'})
    with sqlite3.connect(path) as db:
        db.execute("UPDATE incoming SET id='other' WHERE id='id'")
    with pytest.raises(Conflict): s.seen_incoming('other', b'wire')
