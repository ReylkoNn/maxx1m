"""Encrypted, row-oriented history store used after explicit opt-in migration.

Only ciphertext, keyed message-id tags, sequence numbers and SQLite metadata
are stored on disk. Counts, ordering, sizes and access patterns are visible.
This format does not provide rollback, truncation or secure-deletion protection.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import time
import uuid
import re
from contextlib import contextmanager
from pathlib import Path

import nacl.exceptions
import nacl.secret

from app.history_paging import PAGE_SIZE, searchable_text, HistoryView, check_cancel
from app.delivery import MAX_READ_ACK_IDS

FORMAT_VERSION = 2
APPLICATION_ID = 0x4D315348  # M1SH
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_PAGE_SIZE = PAGE_SIZE
MAX_UPDATE_IDS = MAX_READ_ACK_IDS


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _derive(key, label, owner, chat):
    return hmac.new(key, b'max1m-history-v1\0' + label + b'\0' + _json([owner, chat]), hashlib.sha256).digest()


def _content_identity(index_key, message):
    fields = [message.get(name) for name in
              ('text', 'is_mine', 'reply_to_msg_id', 'reply_to_text', 'reply_to_sender')]
    return hmac.new(index_key, b'content\0' + _json(fields), hashlib.sha256).hexdigest()


def content_identity(key, owner, chat, message):
    """Stable keyed identity shared with legacy tombstones, scoped to a chat."""
    return _content_identity(_derive(key, b'index', owner, chat), message)


def _is_message_expired(message: dict, now_ts: float | None = None) -> bool:
    exp = message.get("expires_at")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return False
    ref = time.time() if now_ts is None else float(now_ts)
    return float(exp) <= ref


StoredPage = HistoryView

class EncryptedHistory:
    def __init__(self, path, key, owner, chat, *, expected_db_id=None, expected_source_hash=None):
        if not isinstance(key, bytes) or len(key) != nacl.secret.SecretBox.KEY_SIZE:
            raise ValueError('Invalid history key')
        if not all(isinstance(x, str) and x for x in (owner, chat)):
            raise ValueError('Invalid history scope')
        self.path = Path(path)
        self.owner, self.chat = owner, chat
        self.expected_db_id, self.expected_source_hash = expected_db_id, expected_source_hash
        self._box = nacl.secret.SecretBox(_derive(key, b'encryption', owner, chat))
        self._index_key = _derive(key, b'index', owner, chat)

    @classmethod
    def create(cls, path, key, owner, chat):
        store = cls(path, key, owner, chat)
        # Exclusive creation: never replace another database or follow a symlink.
        fd = os.open(store.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            store._initialize_empty()
        except BaseException:
            store.path.unlink(missing_ok=True)
            raise
        return store

    def _initialize_empty(self, source_hash=None):
        # Only call on a newly-created private file; never on an existing store.
        conn = sqlite3.connect(self.path, isolation_level=None, timeout=5)
        try:
            conn.execute('PRAGMA synchronous=FULL')
            conn.execute('PRAGMA secure_delete=ON')
            conn.execute('PRAGMA temp_store=MEMORY')
            conn.execute('BEGIN IMMEDIATE')
            conn.execute(f'PRAGMA application_id={APPLICATION_ID}')
            conn.execute(f'PRAGMA user_version={FORMAT_VERSION}')
            conn.execute('CREATE TABLE header (id INTEGER PRIMARY KEY CHECK(id=1), ciphertext BLOB NOT NULL)')
            conn.execute('CREATE TABLE messages (seq INTEGER PRIMARY KEY AUTOINCREMENT, tag BLOB NOT NULL UNIQUE, ciphertext BLOB NOT NULL)')
            header = self._box.encrypt(_json({'version': FORMAT_VERSION, 'owner': self.owner, 'chat': self.chat,
                                               'db_id': str(uuid.uuid4()), 'source_hash': source_hash}))
            conn.execute('INSERT INTO header VALUES (1, ?)', (bytes(header),))
            conn.execute('COMMIT')
        except BaseException:
            if conn.in_transaction:
                conn.execute('ROLLBACK')
            raise
        finally:
            conn.close()

    @contextmanager
    def _connection(self, write=False):
        # mode=rw avoids creating an empty replacement when the file is missing.
        # SQLite may need write access even on a read to recover a hot rollback
        # journal after a crash; rw still refuses to create a missing database.
        uri = self.path.resolve().as_uri() + '?mode=rw'
        conn = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=5)
        try:
            conn.execute('PRAGMA trusted_schema=OFF')
            conn.execute('PRAGMA temp_store=MEMORY')
            conn.execute('PRAGMA secure_delete=ON')
            if write:
                conn.execute('PRAGMA synchronous=FULL')
            conn.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            if (conn.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID or
                    conn.execute('PRAGMA user_version').fetchone()[0] != FORMAT_VERSION):
                raise ValueError('Unsupported history database')
            self._read_header(conn)
            yield conn
            conn.execute('COMMIT')
        except BaseException:
            if conn.in_transaction:
                conn.execute('ROLLBACK')
            raise
        finally:
            conn.close()

    def _read_header(self, conn):
        row = conn.execute('SELECT CASE WHEN length(ciphertext) <= 4096 THEN ciphertext END FROM header WHERE id=1').fetchone()
        if not row or row[0] is None:
            raise ValueError('Invalid history header')
        header = json.loads(self._box.decrypt(row[0]))
        if (not isinstance(header, dict) or set(header) != {'version', 'owner', 'chat', 'db_id', 'source_hash'}
                or header['version'] != FORMAT_VERSION or header['owner'] != self.owner or header['chat'] != self.chat):
            raise ValueError('History scope mismatch')
        try:
            db_id = uuid.UUID(header['db_id'])
            valid_id = db_id.version == 4 and str(db_id) == header['db_id']
        except (ValueError, TypeError, AttributeError):
            valid_id = False
        source_hash = header['source_hash']
        if (not valid_id or (source_hash is not None and
                (not isinstance(source_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', source_hash)))
                or (self.expected_db_id is not None and header['db_id'] != self.expected_db_id)
                or (self.expected_source_hash is not None and source_hash != self.expected_source_hash)):
            raise ValueError('History identity mismatch')
        return header

    def metadata(self):
        with self._connection() as conn:
            return self._read_header(conn)

    def _tag(self, message):
        msg_id = message.get('msg_id')
        if msg_id is None or msg_id == '':
            # Old messages without IDs retain independent random identifiers.
            return hmac.new(self._index_key, b'no-id\0' + os.urandom(32), hashlib.sha256).digest()
        if not isinstance(msg_id, str) or len(msg_id) > 256:
            raise ValueError('Invalid message id')
        return hmac.new(self._index_key, b'id\0' + msg_id.encode('utf-8'), hashlib.sha256).digest()

    def _identity(self, message):
        # Read state and deletion are mutable. Timestamp may be assigned anew
        # when a delivery is retried, so it is intentionally excluded.
        return _content_identity(self._index_key, message)

    def _encrypt(self, seq, tag, message, identity=None):
        identity = identity or self._identity(message)
        plaintext = _json({'version': FORMAT_VERSION, 'seq': seq, 'tag': tag.hex(),
                           'identity': identity, 'message': message})
        if len(plaintext) > MAX_RECORD_BYTES:
            raise ValueError('History record exceeds size limit')
        return bytes(self._box.encrypt(plaintext))

    def _decrypt_record(self, seq, tag, ciphertext):
        if ciphertext is None or not isinstance(tag, bytes) or len(tag) != 32:
            raise ValueError('Invalid history record')
        record = json.loads(self._box.decrypt(ciphertext))
        if (not isinstance(record, dict) or record.get('version') != FORMAT_VERSION or
                record.get('seq') != seq or record.get('tag') != tag.hex() or
                not isinstance(record.get('identity'), str) or len(record['identity']) != 64 or
                not isinstance(record.get('message'), dict)):
            raise ValueError('Invalid history record')
        message = record['message']
        if message.get('msg_id') and not hmac.compare_digest(self._tag(message), tag):
            raise ValueError('History index mismatch')
        if not message.get('deleted', False) and not hmac.compare_digest(self._identity(message), record['identity']):
            raise ValueError('History content mismatch')
        return message, record['identity']

    def _decrypt(self, seq, tag, ciphertext):
        return self._decrypt_record(seq, tag, ciphertext)[0]

    def _insert(self, conn, message, *, migrated_identity=None):
        if not isinstance(message, dict):
            raise ValueError('Invalid history message')
        tag = self._tag(message)
        row = conn.execute('SELECT seq, tag, CASE WHEN length(ciphertext) <= ? THEN ciphertext END FROM messages WHERE tag=?',
                           (MAX_RECORD_BYTES + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES, tag)).fetchone()
        if row:
            existing_msg, identity = self._decrypt_record(*row)
            cand_id = self._identity(message)
            orig_id = existing_msg.get('original_identity')
            if not hmac.compare_digest(identity, cand_id) and not (
                isinstance(orig_id, str) and len(orig_id) == 64 and hmac.compare_digest(orig_id, cand_id)
            ):
                raise ValueError('Conflicting message id')
            return False
        cur = conn.execute('INSERT INTO messages(tag, ciphertext) VALUES (?, ?)', (tag, b''))
        seq = cur.lastrowid
        ciphertext = self._encrypt(seq, tag, message, migrated_identity)
        conn.execute('UPDATE messages SET ciphertext=? WHERE seq=?', (ciphertext, seq))
        return True

    def append(self, message):
        with self._connection(write=True) as conn:
            return self._insert(conn, message)

    def _rows(self, conn, descending=True, cancel=None):
        direction = 'DESC' if descending else 'ASC'
        limit = MAX_RECORD_BYTES + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES
        cursor = conn.execute(f'SELECT seq, CASE WHEN length(tag)=32 THEN tag END, CASE WHEN length(ciphertext) <= ? THEN ciphertext END FROM messages ORDER BY seq {direction}', (limit,))
        for row in cursor:
            check_cancel(cancel)
            yield self._decrypt(*row)

    def _rows_concurrent(self, cancel=None):
        """Read bounded chunks in short transactions so writers aren't held
        behind a full decrypted scan. Caller must reject stale revisions.
        """
        last_seq = None
        limit = MAX_RECORD_BYTES + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES
        while True:
            check_cancel(cancel)
            batch, size, exhausted = [], 0, False
            with self._connection() as conn:
                where = '' if last_seq is None else 'WHERE seq < ?'
                args = (limit,) if last_seq is None else (limit, last_seq)
                cursor = conn.execute(
                    f'SELECT seq, CASE WHEN length(tag)=32 THEN tag END, '
                    f'CASE WHEN length(ciphertext) <= ? THEN ciphertext END '
                    f'FROM messages {where} ORDER BY seq DESC LIMIT 32', args)
                while len(batch) < 32 and size < 4 * 1024 * 1024:
                    check_cancel(cancel)
                    row = cursor.fetchone()
                    if row is None:
                        exhausted = True
                        break
                    batch.append(row)
                    size += len(row[2]) if row[2] is not None else 0
            if not batch:
                return
            last_seq = batch[-1][0]
            for row in batch:
                check_cancel(cancel)
                yield self._decrypt(*row)
            if exhausted:
                return

    def _page_from_rows(self, rows, offset, page_size, query, cancel):
        query_lower = query.lower() if query is not None else None
        total = unread = 0
        selected = []
        oldest = None
        for message in rows:
            if message.get('deleted', False) or _is_message_expired(message):
                continue
            if message.get('is_mine') is False and not message.get('is_read') and message.get('msg_id'):
                unread += 1
            if query_lower is not None and query_lower not in searchable_text(message).lower():
                continue
            if offset <= total < offset + page_size:
                selected.append(message)
            oldest = message
            total += 1
        check_cancel(cancel)
        if total and offset >= total:
            offset = total - 1
            selected = [oldest]
        elif not total:
            offset = 0
        selected.reverse()
        return StoredPage(selected, offset, total, unread, total - offset > page_size, offset > 0)

    def _check_page(self, offset, page_size, query):
        if (type(offset) is not int or offset < 0 or type(page_size) is not int or
                not 1 <= page_size <= MAX_PAGE_SIZE or (query is not None and not isinstance(query, str))):
            raise ValueError('Invalid history page')

    def page(self, offset=0, page_size=PAGE_SIZE, query=None, cancel=None):
        self._check_page(offset, page_size, query)
        with self._connection() as conn:
            return self._page_from_rows(self._rows(conn, cancel=cancel), offset, page_size, query, cancel)

    def page_concurrent(self, offset=0, page_size=PAGE_SIZE, query=None, cancel=None):
        self._check_page(offset, page_size, query)
        return self._page_from_rows(self._rows_concurrent(cancel), offset, page_size, query, cancel)

    def offset_for_id_concurrent(self, msg_id, cancel=None):
        if not isinstance(msg_id, str) or not msg_id:
            raise ValueError('Invalid message id')
        offset = 0
        for message in self._rows_concurrent(cancel):
            if message.get('deleted', False) or _is_message_expired(message):
                continue
            if message.get('msg_id') == msg_id:
                return offset
            offset += 1
        check_cancel(cancel)
        return None

    def offset_for_id(self, msg_id, cancel=None):
        if not isinstance(msg_id, str) or not msg_id:
            raise ValueError('Invalid message id')
        offset = 0
        with self._connection() as conn:
            for message in self._rows(conn, cancel=cancel):
                if message.get('deleted', False) or _is_message_expired(message):
                    continue
                if message.get('msg_id') == msg_id:
                    return offset
                offset += 1
        check_cancel(cancel)
        return None

    def purge_expired(self, now_ts: float | None = None) -> list[str]:
        """Physically delete expired TTL rows (zeroed in-place via PRAGMA secure_delete=ON)."""
        limit = MAX_RECORD_BYTES + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES
        purged_ids: list[str] = []
        with self._connection(write=True) as conn:
            rows = conn.execute(
                'SELECT seq, CASE WHEN length(tag)=32 THEN tag END, '
                'CASE WHEN length(ciphertext) <= ? THEN ciphertext END FROM messages ORDER BY seq ASC',
                (limit,),
            ).fetchall()
            expired_seqs = []
            for seq, tag, ciphertext in rows:
                msg = self._decrypt(seq, tag, ciphertext)
                if _is_message_expired(msg, now_ts=now_ts):
                    expired_seqs.append(seq)
                    mid = msg.get('msg_id')
                    if isinstance(mid, str) and mid:
                        purged_ids.append(mid)
            for seq in expired_seqs:
                conn.execute('DELETE FROM messages WHERE seq=?', (seq,))
        return purged_ids

    def list_message_ids(self) -> list[str]:
        ids: list[str] = []
        with self._connection() as conn:
            for message in self._rows(conn):
                mid = message.get('msg_id')
                if isinstance(mid, str) and mid:
                    ids.append(mid)
        return ids

    def update(self, msg_ids, *, mark_read=False, delete=False, only_mine=False, only_incoming=False):
        if mark_read == delete or (only_mine and only_incoming):
            raise ValueError('Invalid history update')
        if not isinstance(msg_ids, (list, tuple)) or len(msg_ids) > MAX_UPDATE_IDS:
            raise ValueError('Invalid history update IDs')
        if any(not isinstance(i, str) or not i for i in msg_ids):
            raise ValueError('Invalid message id')
        ids = list(dict.fromkeys(msg_ids))
        changed = []
        with self._connection(write=True) as conn:
            for msg_id in ids:
                tag = self._tag({'msg_id': msg_id})
                row = conn.execute('SELECT seq, tag, CASE WHEN length(ciphertext) <= ? THEN ciphertext END FROM messages WHERE tag=?',
                                   (MAX_RECORD_BYTES + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES, tag)).fetchone()
                if not row:
                    continue
                seq, saved_tag, ciphertext = row
                message, identity = self._decrypt_record(seq, saved_tag, ciphertext)
                if (only_mine and message.get('is_mine') is not True) or (only_incoming and message.get('is_mine') is not False):
                    continue
                if delete and not message.get('deleted', False):
                    message['deleted'], message['text'] = True, ''
                elif mark_read and not message.get('is_read', False):
                    message['is_read'] = True
                else:
                    continue
                conn.execute('UPDATE messages SET ciphertext=? WHERE seq=?', (self._encrypt(seq, saved_tag, message, identity), seq))
                changed.append(msg_id)
        return changed

    def delete_one(self, msg_id, *, only_incoming=False, accept_already_deleted=False):
        """Atomically delete a known message; incoming retries may be idempotent."""
        deleted, _was_mine = self.delete_one_with_meta(
            msg_id, only_incoming=only_incoming, accept_already_deleted=accept_already_deleted
        )
        return deleted

    def delete_one_with_meta(self, msg_id, *, only_incoming=False, accept_already_deleted=False):
        """Atomically delete a known message and return (deleted, was_mine)."""
        if not isinstance(msg_id, str) or not msg_id:
            raise ValueError('Invalid message id')
        tag = self._tag({'msg_id': msg_id})
        with self._connection(write=True) as conn:
            row = conn.execute('SELECT seq, tag, CASE WHEN length(ciphertext) <= ? THEN ciphertext END FROM messages WHERE tag=?',
                               (MAX_RECORD_BYTES + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES, tag)).fetchone()
            if not row:
                return False, False
            seq, saved_tag, ciphertext = row
            message, identity = self._decrypt_record(seq, saved_tag, ciphertext)
            was_mine = bool(message.get('is_mine') is True)
            if only_incoming and message.get('is_mine') is not False:
                return False, was_mine
            if message.get('deleted', False):
                return bool(accept_already_deleted), was_mine
            message['deleted'], message['text'] = True, ''
            conn.execute('UPDATE messages SET ciphertext=? WHERE seq=?',
                         (self._encrypt(seq, saved_tag, message, identity), seq))
            return True, was_mine

    def edit_one(
        self,
        msg_id: str,
        new_text: str,
        *,
        only_mine: bool = False,
        only_incoming: bool = False,
        expected_sender_name: str | None = None,
    ) -> bool:
        """Atomically edit a text message if ownership and type invariants pass."""
        if (
            not isinstance(msg_id, str)
            or not 1 <= len(msg_id) <= 256
            or not isinstance(new_text, str)
            or not 1 <= len(new_text) <= 256 * 1024
            or new_text.startswith(('[IMAGE_META]|', '[VOICE_META]|', '[FILE_META]|'))
        ):
            raise ValueError('Invalid edit parameters')
        tag = self._tag({'msg_id': msg_id})
        with self._connection(write=True) as conn:
            row = conn.execute(
                'SELECT seq, tag, CASE WHEN length(ciphertext) <= ? THEN ciphertext END FROM messages WHERE tag=?',
                (MAX_RECORD_BYTES + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES, tag),
            ).fetchone()
            if not row:
                return False
            seq, saved_tag, ciphertext = row
            message, old_identity = self._decrypt_record(seq, saved_tag, ciphertext)
            if message.get('deleted', False):
                return False
            cur_text = message.get('text', '')
            if isinstance(cur_text, str) and cur_text.startswith(('[IMAGE_META]|', '[VOICE_META]|', '[FILE_META]|')):
                return False
            if only_mine and message.get('is_mine') is not True:
                return False
            if only_incoming and message.get('is_mine') is not False:
                return False
            if expected_sender_name is not None and message.get('sender_name') != expected_sender_name:
                return False
            if 'original_identity' not in message:
                message['original_identity'] = old_identity
            message['text'] = new_text
            message['edited'] = True
            conn.execute(
                'UPDATE messages SET ciphertext=? WHERE seq=?',
                (self._encrypt(seq, saved_tag, message), seq),
            )
            return True

    def clear(self):
        """Remove all rows in one transaction; this is not secure erasure."""
        with self._connection(write=True) as conn:
            conn.execute('DELETE FROM messages')
        return True


def migrate_legacy_copy(source, destination, key, owner, chat):
    """Create a verified independent DB copy; never modify/delete the source.

    Caller must exclusively lock the profile and prevent legacy clients from
    writing it for the entire migration and subsequent use. This one-time path
    necessarily reads the complete legacy encrypted JSON history into memory.
    No automatic cutover or crash/power-loss directory durability is claimed.
    """
    source, destination = Path(source), Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    if not isinstance(key, bytes) or len(key) != nacl.secret.SecretBox.KEY_SIZE:
        raise ValueError('Invalid history key')
    raw = source.read_bytes()
    source_hash = hashlib.sha256(raw).digest()
    decoded = nacl.secret.SecretBox(key).decrypt(raw)
    del raw
    messages = json.loads(decoded)
    del decoded
    if not isinstance(messages, list) or any(not isinstance(m, dict) for m in messages):
        raise ValueError('Invalid legacy history')
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.history-migration-', suffix='.sqlite3', dir=destination.parent)
    os.close(fd)
    temp = Path(name)
    try:
        store = EncryptedHistory(temp, key, owner, chat)
        store._initialize_empty(source_hash.hex())
        with store._connection(write=True) as conn:
            for message in messages:
                identity = message.get('_legacy_content_identity') if isinstance(message, dict) else None
                if identity is not None:
                    if (not message.get('deleted', False) or not isinstance(identity, str)
                            or not re.fullmatch(r'[0-9a-f]{64}', identity)):
                        raise ValueError('Invalid legacy tombstone identity')
                    inserted = store._insert(conn, message, migrated_identity=identity)
                else:
                    inserted = store._insert(conn, message)
                if not inserted:
                    raise ValueError('Duplicate legacy message id')
        with store._connection() as conn:
            rows = store._rows(conn, descending=False)
            for message in messages:
                if next(rows, None) != message:
                    raise ValueError('Migration verification failed')
            if next(rows, None) is not None:
                raise ValueError('Migration verification failed')
        digest = hashlib.sha256()
        with source.open('rb') as f:
            while chunk := f.read(1024 * 1024):
                digest.update(chunk)
        if not hmac.compare_digest(digest.digest(), source_hash):
            raise ValueError('Legacy history changed during migration')
        # Hard-link publication is atomic and fails if the destination exists.
        os.link(temp, destination)
    finally:
        temp.unlink(missing_ok=True)
    return EncryptedHistory(destination, key, owner, chat)
