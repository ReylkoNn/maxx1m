"""Explicit, fail-closed activation of row histories, one chat at a time.

Callers must ensure the standard desktop instance lock is held. Older clients
and other processes do not honour that lock; they must not use the profile.
"""
import hashlib
import hmac
import json
import os
import re
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

import nacl.secret

from app.history_store import EncryptedHistory, migrate_legacy_copy
from app.experimental_history_adapter import ExperimentalHistoryAdapter
from app.history_paging import check_cancel

MAX_CATALOG_BYTES = 1024 * 1024
MAX_CATALOG_CHATS = 1000


def paths(owner, chat):
    from app.secure_storage import SecureStorage
    source = SecureStorage._get_messages_file(owner, chat)
    database = source.with_suffix('.history.sqlite3')
    catalog = SecureStorage._get_user_dir(owner) / 'history_catalog.enc'
    return source, database, catalog


def file_hash(path, cancel=None):
    check_cancel(cancel)
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while chunk := stream.read(1024 * 1024):
            check_cancel(cancel)
            digest.update(chunk)
    check_cancel(cancel)
    return digest.hexdigest()


def _fsync_directory(directory: Path) -> None:
    if os.name != 'posix' or not directory.is_dir():
        return
    fd = None
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        os.fsync(fd)
    except OSError:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def read_catalog(path, key, owner):
    path = Path(path)
    if not os.path.lexists(path):
        return {}
    if path.is_symlink() or not path.is_file():
        raise ValueError('Invalid history catalog')
    with path.open('rb') as f:
        encrypted = f.read(MAX_CATALOG_BYTES + 1)
    if len(encrypted) > MAX_CATALOG_BYTES:
        raise ValueError('History catalog exceeds size limit')
    record = json.loads(nacl.secret.SecretBox(key).decrypt(encrypted))
    if (not isinstance(record, dict) or set(record) != {'version', 'owner', 'chats'}
            or record['version'] != 1 or record['owner'] != owner
            or not isinstance(record['chats'], dict) or len(record['chats']) > MAX_CATALOG_CHATS):
        raise ValueError('Invalid history catalog')
    for chat, entry in record['chats'].items():
        if (not isinstance(chat, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', chat)
                or not isinstance(entry, dict) or set(entry) != {'db_id', 'source_hash'}
                or not isinstance(entry['source_hash'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', entry['source_hash'])):
            raise ValueError('Invalid history catalog entry')
        try:
            parsed = uuid.UUID(entry['db_id'])
            if parsed.version != 4 or str(parsed) != entry['db_id']:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError('Invalid history catalog identity') from exc
    return record['chats']


def write_catalog(path, key, owner, chats):
    path = Path(path)
    if os.path.islink(path):
        raise ValueError('Invalid history catalog path')
    if len(chats) > MAX_CATALOG_CHATS:
        raise ValueError('History catalog is full')
    payload = json.dumps({'version': 1, 'owner': owner, 'chats': chats},
                         sort_keys=True, separators=(',', ':')).encode('utf-8')
    encrypted = bytes(nacl.secret.SecretBox(key).encrypt(payload))
    if len(encrypted) > MAX_CATALOG_BYTES:
        raise ValueError('History catalog exceeds size limit')
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
            temp = f.name
            if os.name == 'posix':
                try:
                    os.fchmod(f.fileno(), 0o600)
                except OSError:
                    pass
            f.write(encrypted)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        temp = None
        _fsync_directory(path.parent)
    finally:
        if temp and os.path.exists(temp):
            os.unlink(temp)


def _same_source(source, expected, cancel=None):
    try:
        actual = file_hash(source, cancel=cancel)
    except OSError as exc:
        raise ValueError('Legacy history backup is unavailable') from exc
    if not hmac.compare_digest(actual, expected):
        raise ValueError('Legacy history backup has changed; manual recovery required')


@contextmanager
def active_adapter(owner, chat, cancel=None):
    """Select active row store, or None for legacy; never fall back on conflict."""
    from app.secure_storage import SecureStorage
    check_cancel(cancel)
    source, database, catalog = paths(owner, chat)
    catalog_exists = os.path.lexists(catalog)
    db_exists = os.path.lexists(database)
    if not catalog_exists and not db_exists:
        yield None
        return
    key = SecureStorage._get_or_create_local_key(owner)
    entries = read_catalog(catalog, key, owner)
    entry = entries.get(chat)
    if entry is None:
        if db_exists:
            raise ValueError('Unfinished history migration; resume or recover before opening chat')
        yield None
        return
    if not db_exists:
        raise ValueError('Active history database is missing')
    _same_source(source, entry['source_hash'], cancel=cancel)
    store = EncryptedHistory(database, key, owner, chat, expected_db_id=entry['db_id'],
                             expected_source_hash=entry['source_hash'])
    store.metadata()  # Authenticate identity before exposing the backend.
    yield ExperimentalHistoryAdapter(store)
    # If a legacy writer raced our operation, don't report success to caller.
    _same_source(source, entry['source_hash'], cancel=cancel)


def _verify_candidate(source, store, key):
    """Recheck a copied DB before publishing or resuming an interrupted cutover."""
    header = store.metadata()
    expected = header['source_hash']
    if expected is None:
        raise ValueError('History database is not a verified migration copy')
    raw = source.read_bytes()  # Legacy SecretBox is a single monolithic record.
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected):
        raise ValueError('Legacy history changed before cutover')
    messages = json.loads(nacl.secret.SecretBox(key).decrypt(raw))
    del raw
    if not isinstance(messages, list) or any(not isinstance(m, dict) for m in messages):
        raise ValueError('Invalid legacy history')
    with store._connection() as conn:
        rows = store._rows(conn, descending=False)
        for message in messages:
            if next(rows, None) != message:
                raise ValueError('Migration copy does not match legacy history')
        if next(rows, None) is not None:
            raise ValueError('Migration copy does not match legacy history')
    _same_source(source, expected)
    return {'db_id': header['db_id'], 'source_hash': expected}


def migrate_chat(owner, chat):
    """Explicitly migrate one existing chat while holding the desktop lock.

    Never deletes or overwrites the legacy file. A failed/interrupted cutover
    leaves both files intact; invoking this function again verifies before resume.
    """
    from app import secure_storage
    from app.instance_guard import acquire_instance_lock
    lock = acquire_instance_lock(secure_storage.BASE_DIR)
    try:
        source, database, catalog = paths(owner, chat)
        if not source.is_file():
            raise ValueError('Existing legacy history is required')
        key = secure_storage.SecureStorage._get_or_create_local_key(owner)
        entries = read_catalog(catalog, key, owner)
        if chat in entries:
            with active_adapter(owner, chat):
                return False  # Already active; never re-import old messages.
        if len(entries) >= MAX_CATALOG_CHATS:
            raise ValueError('History catalog is full')
        if not os.path.lexists(database):
            store = migrate_legacy_copy(source, database, key, owner, chat)
        else:
            store = EncryptedHistory(database, key, owner, chat)
        entry = _verify_candidate(source, store, key)
        updated = dict(entries)
        updated[chat] = entry
        # No other updated instance can be active while the desktop lock is held.
        # Old clients do not honor the lock, so operators must stop them too.
        _same_source(source, entry['source_hash'])
        write_catalog(catalog, key, owner, updated)
        return True
    finally:
        lock.unlock()
