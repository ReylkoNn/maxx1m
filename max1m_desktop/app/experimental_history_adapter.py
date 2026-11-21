"""Scope-bound row-store adapter used after explicit experimental migration.

This handles one already-open row store only. Selection and cutover are managed
by history_activation, which checks the catalog and legacy backup.
"""
from datetime import datetime
import uuid
from app.history_paging import PAGE_SIZE


class ExperimentalHistoryAdapter:
    def __init__(self, store):
        self.store = store

    def _check_scope(self, owner, chat):
        if (owner, chat) != (self.store.owner, self.store.chat):
            raise ValueError('History scope mismatch')

    def load_history_page(self, owner, chat, offset=0, page_size=PAGE_SIZE, query=None, cancel=None):
        self._check_scope(owner, chat)
        return self.store.page(offset, page_size, query, cancel=cancel)

    def history_offset_for_id(self, owner, chat, msg_id, cancel=None):
        self._check_scope(owner, chat)
        return self.store.offset_for_id(msg_id, cancel=cancel)

    def save_message(self, my_username, ally_username, text, is_mine, timestamp=None,
                     msg_id=None, is_read=False, reply_to_msg_id=None,
                     reply_to_text=None, reply_to_sender=None, expires_at=None, sender_name=None):
        self._check_scope(my_username, ally_username)
        if not msg_id:
            msg_id = f'local_{uuid.uuid4().hex[:12]}'
        message = {'msg_id': msg_id, 'text': text, 'is_mine': is_mine,
                   'is_read': is_read, 'timestamp': timestamp or datetime.now().isoformat(),
                   'deleted': False}
        if isinstance(sender_name, str) and sender_name:
            message['sender_name'] = sender_name
        if reply_to_msg_id:
            message.update(reply_to_msg_id=reply_to_msg_id, reply_to_text=reply_to_text,
                           reply_to_sender=reply_to_sender)
        if isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool) and expires_at > 0:
            message['expires_at'] = int(expires_at)
        return self.store.append(message)

    def purge_expired(self, my_username, ally_username, now_ts=None):
        self._check_scope(my_username, ally_username)
        return self.store.purge_expired(now_ts=now_ts)

    def mark_messages_as_read(self, my_username, ally_username, msg_ids, only_mine=False):
        self._check_scope(my_username, ally_username)
        return bool(self.store.update(msg_ids, mark_read=True, only_mine=only_mine))

    def delete_message(self, my_username, ally_username, msg_id):
        self._check_scope(my_username, ally_username)
        return self.store.delete_one(msg_id)

    def delete_message_with_meta(self, my_username, ally_username, msg_id):
        self._check_scope(my_username, ally_username)
        return self.store.delete_one_with_meta(msg_id)

    def delete_incoming_message(self, my_username, ally_username, msg_id):
        self._check_scope(my_username, ally_username)
        if not msg_id:
            return False
        return self.store.delete_one(msg_id, only_incoming=True, accept_already_deleted=True)

    def edit_message(
        self,
        my_username,
        ally_username,
        msg_id,
        new_text,
        *,
        only_mine=False,
        only_incoming=False,
        expected_sender_name=None,
    ):
        self._check_scope(my_username, ally_username)
        return self.store.edit_one(
            msg_id,
            new_text,
            only_mine=only_mine,
            only_incoming=only_incoming,
            expected_sender_name=expected_sender_name,
        )

    def list_message_ids(self, my_username, ally_username):
        self._check_scope(my_username, ally_username)
        return self.store.list_message_ids()

    def clear_chat(self, my_username, ally_username):
        self._check_scope(my_username, ally_username)
        return self.store.clear()
