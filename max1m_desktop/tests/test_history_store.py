import concurrent.futures
import json
import sqlite3
import pytest
import nacl.secret
import nacl.utils
from app.history_paging import history_page
from app.history_store import EncryptedHistory, migrate_legacy_copy, MAX_RECORD_BYTES


@pytest.fixture
def sample(tmp_path):
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    store = EncryptedHistory.create(tmp_path / 'history.sqlite3', key, 'alice', 'bob')
    return store, key


def message(i, **kwargs):
    return {'msg_id': f'message-{i}', 'text': f'secret body {i}', 'is_mine': i % 3 == 0,
            'is_read': i % 5 == 0, 'timestamp':'2025-01-01', 'deleted':False, **kwargs}


def test_encrypted_paging_matches_legacy_and_counts_unread(sample):
    store, _ = sample
    original = [message(i) for i in range(73)]
    for msg in original: assert store.append(msg)
    unread = sum(m['is_mine'] is False and not m['is_read'] for m in original)
    for offset in (0, 1, 25, 50, 72, 73, 500):
        expected = history_page(original, offset)
        page = store.page(offset)
        assert (page.messages, page.offset, page.total, page.has_older, page.has_newer) == (
            expected.messages, expected.offset, expected.total, expected.has_older, expected.has_newer)
        assert page.unread == unread
    assert store.offset_for_id('message-30') == 42
    assert store.offset_for_id('missing') is None
    database = store.path.read_bytes()
    assert b'secret body' not in database and b'message-30' not in database


def test_search_does_not_search_attachment_keys(sample):
    store, _ = sample
    for msg in (message(1, text='[IMAGE_META]|identifier|secretkey|A sunset'),
                message(2, text='[VOICE_META]|id|secretkey|2'), message(3, text='a sunset')):
        store.append(msg)
    assert [m['msg_id'] for m in store.page(query='sunset').messages] == ['message-1', 'message-3']
    assert not store.page(query='secretkey').messages
    assert store.page(query='sunset').unread == 2


def test_idempotency_conflicts_and_mutation_after_deletion(sample):
    store, _ = sample
    msg = message(1)
    assert store.append(msg)
    assert not store.append({**msg, 'timestamp':'2026-01-01', 'is_read':True})
    with pytest.raises(ValueError, match='Conflicting'):
        store.append({**msg, 'text':'different'})
    assert store.update(['message-1'], mark_read=True, only_incoming=True) == ['message-1']
    assert not store.append(msg)
    assert store.update(['message-1'], delete=True, only_mine=True) == []
    assert store.update(['message-1'], delete=True, only_incoming=True) == ['message-1']
    assert store.page().messages == []
    assert not store.append(msg)  # Do not resurrect deleted messages on retry.
    with pytest.raises(ValueError, match='Conflicting'):
        store.append({**msg, 'text':'different'})


def test_failed_batch_update_rolls_back_every_row(sample, monkeypatch):
    store, _ = sample
    store.append(message(1)); store.append(message(2))
    original_encrypt = store._encrypt
    def fail(seq, tag, msg, identity=None):
        if msg['msg_id'] == 'message-2': raise OSError('disk write failed')
        return original_encrypt(seq, tag, msg, identity)
    monkeypatch.setattr(store, '_encrypt', fail)
    with pytest.raises(OSError): store.update(['message-1', 'message-2'], mark_read=True)
    assert [m['is_read'] for m in store.page().messages] == [False, False]


def test_failed_oversized_insert_does_not_create_placeholder(sample):
    store, _ = sample
    with pytest.raises(ValueError, match='size limit'):
        store.append(message(1, text='x' * MAX_RECORD_BYTES))
    assert store.page().total == 0
    assert store.append(message(1))


def test_wrong_key_scope_corruption_and_missing_file_fail_closed(sample, tmp_path):
    store, key = sample
    store.append(message(1))
    with pytest.raises(Exception): EncryptedHistory(store.path, key, 'alice', 'mallory').page()
    with pytest.raises(Exception): EncryptedHistory(store.path, b'Z'*32, 'alice', 'bob').page()
    missing = tmp_path / 'missing.sqlite3'
    with pytest.raises(sqlite3.OperationalError): EncryptedHistory(missing, key, 'alice', 'bob').append(message(1))
    assert not missing.exists()
    with sqlite3.connect(store.path) as conn:
        conn.execute('UPDATE messages SET ciphertext=?', (b'corrupt',))
    with pytest.raises(Exception): store.page()
    with pytest.raises(Exception): store.append(message(1))


def test_swapped_encrypted_rows_are_detected(sample):
    store, _ = sample
    store.append(message(1)); store.append(message(2))
    with sqlite3.connect(store.path) as conn:
        first, second = conn.execute('SELECT ciphertext FROM messages ORDER BY seq').fetchall()
        conn.execute('UPDATE messages SET ciphertext=? WHERE seq=1', (second[0],))
        conn.execute('UPDATE messages SET ciphertext=? WHERE seq=2', (first[0],))
    with pytest.raises(ValueError, match='Invalid history record'): store.page()


def legacy(path, key, messages):
    path.write_bytes(nacl.secret.SecretBox(key).encrypt(json.dumps(messages, ensure_ascii=False).encode()))


def test_migration_is_verified_copy_and_keeps_legacy(sample, tmp_path):
    _, key = sample
    source, dest = tmp_path/'old.enc', tmp_path/'new.sqlite3'
    messages = [message(1), {'text':'old without id', 'is_mine':False}, message(3, deleted=True, text='')]
    legacy(source, key, messages)
    before = source.read_bytes()
    store = migrate_legacy_copy(source, dest, key, 'alice', 'bob')
    assert source.read_bytes() == before
    assert store.page().messages == messages[:2]
    with store._connection() as conn:
        assert list(store._rows(conn, descending=False)) == messages
    with pytest.raises(FileExistsError): migrate_legacy_copy(source, dest, key, 'alice', 'bob')


def test_migration_failure_never_publishes_or_modifies_source(sample, tmp_path):
    _, key = sample
    source, dest = tmp_path/'old.enc', tmp_path/'new.sqlite3'
    legacy(source, key, [message(1), message(1)])
    before = source.read_bytes()
    with pytest.raises(ValueError, match='Duplicate'): migrate_legacy_copy(source, dest, key, 'alice', 'bob')
    assert source.read_bytes() == before and not dest.exists()
    assert not list(tmp_path.glob('.history-migration-*'))
    source.write_bytes(b'broken')
    with pytest.raises(Exception): migrate_legacy_copy(source, dest, key, 'alice', 'bob')
    assert source.read_bytes() == b'broken' and not dest.exists()


def test_migration_refuses_changed_source_before_publish(sample, tmp_path, monkeypatch):
    _, key = sample
    source, dest = tmp_path/'old.enc', tmp_path/'new.sqlite3'
    legacy(source, key, [message(1)])
    old_insert = EncryptedHistory._insert
    def mutate(self, conn, msg):
        result = old_insert(self, conn, msg)
        source.write_bytes(b'changed by another process')
        return result
    monkeypatch.setattr(EncryptedHistory, '_insert', mutate)
    with pytest.raises(ValueError, match='changed'): migrate_legacy_copy(source, dest, key, 'alice', 'bob')
    assert source.read_bytes() == b'changed by another process' and not dest.exists()


def test_concurrent_writers_serialize_and_duplicate_cannot_overwrite(sample):
    store, _ = sample
    def insert(i): return store.append(message(i))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(insert, list(range(30)) + list(range(30))))
    assert sum(results) == 30 and store.page().total == 30


def test_pages_cover_randomized_history_and_deletion(sample):
    import random
    store, _ = sample
    rng = random.Random(1234)
    records = [message(i, deleted=rng.random() < .2) for i in range(133)]
    for msg in records: store.append(msg)
    visible = [m for m in records if not m['deleted']]
    for offset in range(0, len(visible)+30, 7):
        expected = history_page(visible, offset)
        actual = store.page(offset)
        assert (actual.messages, actual.offset, actual.total) == (expected.messages, expected.offset, expected.total)
        assert actual.has_older == expected.has_older and actual.has_newer == expected.has_newer
    with pytest.raises(ValueError): store.page(page_size=26)


def test_crash_during_sqlite_transaction_keeps_old_row(sample):
    import base64
    import subprocess
    import sys
    store, key = sample
    store.append(message(1))
    program = '''
import base64, os, sys
from app.history_store import EncryptedHistory
store = EncryptedHistory(sys.argv[1], base64.b64decode(sys.argv[2]), 'alice', 'bob')
with store._connection(write=True) as conn:
    conn.execute("UPDATE messages SET ciphertext=?", (b'bad uncommitted ciphertext',))
    os._exit(17)
'''
    result = subprocess.run([sys.executable, '-c', program, str(store.path), base64.b64encode(key).decode()], timeout=15)
    assert result.returncode == 17
    assert store.page().messages == [message(1)]


def test_migration_publish_failure_preserves_source(sample, tmp_path, monkeypatch):
    from app import history_store
    _, key = sample
    source, dest = tmp_path/'old.enc', tmp_path/'new.sqlite3'
    legacy(source, key, [message(1)])
    before = source.read_bytes()
    def fail(*args): raise OSError('publication failed')
    monkeypatch.setattr(history_store.os, 'link', fail)
    with pytest.raises(OSError, match='publication failed'):
        migrate_legacy_copy(source, dest, key, 'alice', 'bob')
    assert source.read_bytes() == before and not dest.exists()
    assert not list(tmp_path.glob('.history-migration-*'))


def test_competing_migrations_never_replace_published_destination(sample, tmp_path):
    _, key = sample
    source, dest = tmp_path/'old.enc', tmp_path/'new.sqlite3'
    legacy(source, key, [message(1), message(2)])
    before = source.read_bytes()
    def migrate(_):
        try:
            migrate_legacy_copy(source, dest, key, 'alice', 'bob')
            return 'ok'
        except FileExistsError:
            return 'exists'
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(migrate, range(2)))
    assert sorted(result) == ['exists', 'ok']
    assert source.read_bytes() == before
    assert EncryptedHistory(dest, key, 'alice', 'bob').page().messages == [message(1), message(2)]
    assert not list(tmp_path.glob('.history-migration-*'))


def test_abrupt_migration_exit_never_changes_source_or_publishes(sample, tmp_path):
    import base64
    import subprocess
    import sys
    _, key = sample
    source, dest = tmp_path/'old.enc', tmp_path/'new.sqlite3'
    legacy(source, key, [message(1), message(2)])
    before = source.read_bytes()
    program = '''
import base64, os, sys
from app.history_store import EncryptedHistory, migrate_legacy_copy
original = EncryptedHistory._insert
def interrupted(self, conn, msg):
    original(self, conn, msg)
    os._exit(18)
EncryptedHistory._insert = interrupted
migrate_legacy_copy(sys.argv[1], sys.argv[2], base64.b64decode(sys.argv[3]), 'alice', 'bob')
'''
    result = subprocess.run([sys.executable, '-c', program, str(source), str(dest),
                             base64.b64encode(key).decode()], timeout=15)
    assert result.returncode == 18
    assert source.read_bytes() == before and not dest.exists()
    # A crash can leave private temporary SQLite/journal files, but no plaintext.
    leftovers = list(tmp_path.glob('.history-migration-*'))
    assert leftovers
    assert all(b'secret body' not in item.read_bytes() for item in leftovers)


def test_missing_local_key_does_not_replace_key_when_history_database_exists(tmp_path, monkeypatch):
    from app import secure_storage
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda *args: None)
    writes = []
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda *args: writes.append(args))
    history = tmp_path / 'profiles' / 'alice' / 'messages'
    history.mkdir(parents=True)
    database = history / 'bob.history.sqlite3'
    database.write_bytes(b'important encrypted db')
    with pytest.raises(ValueError, match='key is missing'):
        secure_storage.SecureStorage._get_or_create_local_key('alice')
    assert database.read_bytes() == b'important encrypted db' and not writes


def test_experimental_adapter_scope_crud_and_idempotent_incoming_delete(sample):
    from app.experimental_history_adapter import ExperimentalHistoryAdapter
    store, _ = sample
    adapter = ExperimentalHistoryAdapter(store)
    assert adapter.save_message('alice', 'bob', 'incoming', False, msg_id='in')
    assert adapter.save_message('alice', 'bob', 'mine', True, msg_id='mine')
    assert not adapter.save_message('alice', 'bob', 'incoming', False, msg_id='in')
    with pytest.raises(ValueError, match='Conflicting'):
        adapter.save_message('alice', 'bob', 'different', False, msg_id='in')
    assert adapter.mark_messages_as_read('alice', 'bob', ['in', 'mine'], only_mine=True)
    page = adapter.load_history_page('alice', 'bob')
    assert [m['is_read'] for m in page.messages] == [False, True] and page.unread == 1
    assert adapter.history_offset_for_id('alice', 'bob', 'in') == 1
    assert not adapter.delete_incoming_message('alice', 'bob', 'mine')
    assert not adapter.delete_incoming_message('alice', 'bob', 'unknown')
    assert adapter.delete_incoming_message('alice', 'bob', 'in')
    assert adapter.delete_incoming_message('alice', 'bob', 'in')  # replay after ACK loss
    assert adapter.delete_message('alice', 'bob', 'mine')
    assert not adapter.delete_message('alice', 'bob', 'mine')
    assert adapter.load_history_page('alice', 'bob').total == 0
    with pytest.raises(ValueError, match='scope'):
        adapter.clear_chat('other', 'bob')
    assert adapter.clear_chat('alice', 'bob')
    assert adapter.save_message('alice', 'bob', 'new after clear', False, msg_id='in')
    assert adapter.load_history_page('alice', 'bob').messages[0]['text'] == 'new after clear'


def test_read_batch_limit_and_corruption_fail_without_partial_update(sample):
    from app.experimental_history_adapter import ExperimentalHistoryAdapter
    store, _ = sample
    adapter = ExperimentalHistoryAdapter(store)
    adapter.save_message('alice', 'bob', 'one', False, msg_id='one')
    adapter.save_message('alice', 'bob', 'two', False, msg_id='two')
    with pytest.raises(ValueError):
        adapter.mark_messages_as_read('alice', 'bob', ['one'] * 1025)
    with sqlite3.connect(store.path) as conn:
        conn.execute('UPDATE messages SET ciphertext=? WHERE seq=2', (b'corrupted',))
    with pytest.raises(Exception):
        adapter.mark_messages_as_read('alice', 'bob', ['one', 'two'])
    with store._connection() as conn:
        row = conn.execute('SELECT seq, tag, ciphertext FROM messages WHERE seq=1').fetchone()
        assert not store._decrypt(*row)['is_read']


def test_deleted_legacy_record_without_original_text_does_not_ack_conflicting_retry(sample, tmp_path):
    from app.experimental_history_adapter import ExperimentalHistoryAdapter
    _, key = sample
    source, dest = tmp_path/'legacy.enc', tmp_path/'imported.sqlite3'
    legacy(source, key, [message(1, deleted=True, text='')])
    adapter = ExperimentalHistoryAdapter(migrate_legacy_copy(source, dest, key, 'alice', 'bob'))
    # A legacy tombstone has no original text to validate; reject a retry
    # rather than silently claiming that its payload is the same message.
    with pytest.raises(ValueError, match='Conflicting'):
        adapter.save_message('alice', 'bob', 'original before deletion', False, msg_id='message-1')
    assert source.exists() and adapter.load_history_page('alice', 'bob').total == 0


def test_large_read_ack_updates_atomically_and_rejects_over_limit(sample):
    from app.delivery import MAX_READ_ACK_IDS
    store, _ = sample
    with store._connection(write=True) as conn:
        for i in range(MAX_READ_ACK_IDS):
            store._insert(conn, message(i, is_mine=True, is_read=False))
    ids = [f'message-{i}' for i in range(MAX_READ_ACK_IDS)]
    assert store.update(ids, mark_read=True, only_mine=True) == ids
    with store._connection() as conn:
        assert all(item['is_read'] for item in store._rows(conn))
    with pytest.raises(ValueError, match='IDs'):
        store.update(ids + ['extra'], mark_read=True)


def test_large_read_ack_rolls_back_on_mid_batch_error(sample, monkeypatch):
    store, _ = sample
    with store._connection(write=True) as conn:
        for i in range(150): store._insert(conn, message(i, is_mine=True, is_read=False))
    original=store._encrypt
    def fail(seq, tag, msg, identity=None):
        if msg['msg_id']=='message-120': raise OSError('disk error')
        return original(seq, tag, msg, identity)
    monkeypatch.setattr(store, '_encrypt', fail)
    with pytest.raises(OSError):
        store.update([f'message-{i}' for i in range(150)], mark_read=True, only_mine=True)
    with store._connection() as conn:
        assert all(not item['is_read'] for item in store._rows(conn))
