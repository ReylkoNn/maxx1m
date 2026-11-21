import json

import pytest
from app.crypto_box import CryptoManager, crypto
from app import secure_storage
from app.secure_storage import storage
from app.state import state


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    monkeypatch.setattr(secure_storage, "CONFIG_FILE", tmp_path / "state.json")
    keyring = {}
    monkeypatch.setattr(secure_storage.keyring, "get_password", lambda service, name: keyring.get(name))
    monkeypatch.setattr(secure_storage.keyring, "set_password", lambda service, name, value: keyring.__setitem__(name, value))
    state.username = "receiver"
    state.device_id = "receiver-device"
    state.server_url = "https://node"
    state.current_chat_username = None
    state.allies = {}
    yield
    state.username = ""
    state.allies = {}


@pytest.fixture(scope="session")
def qapp():
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:
        pytest.skip(f"Qt system libraries unavailable: {exc}")
    return QApplication.instance() or QApplication([])


def test_replay_does_not_restore_deleted_message(environment):
    assert storage.save_message("receiver", "sender", "hello", False, msg_id="id1")
    assert storage.delete_message("receiver", "sender", "id1")
    assert not storage.save_message("receiver", "sender", "hello", False, msg_id="id1")
    assert storage.save_message("receiver", "sender", "next", False, msg_id="id2")
    assert [m["msg_id"] for m in storage.load_messages("receiver", "sender")] == ["id2"]


def test_corrupt_history_is_not_overwritten(environment):
    assert storage.save_message("receiver", "sender", "hello", False, msg_id="id1")
    path = storage._get_messages_file("receiver", "sender")
    path.write_bytes(b"unreadable history")
    with pytest.raises(Exception):
        storage.save_message("receiver", "sender", "next", False, msg_id="id2")
    assert path.read_bytes() == b"unreadable history"


def test_failed_atomic_replace_preserves_original(environment, monkeypatch):
    assert storage.save_message("receiver", "sender", "hello", False, msg_id="id1")
    path = storage._get_messages_file("receiver", "sender")
    before = path.read_bytes()
    def fail(*args):
        raise OSError("simulated failure")
    monkeypatch.setattr(secure_storage.os, "replace", fail)
    with pytest.raises(OSError):
        storage.save_message("receiver", "sender", "next", False, msg_id="id2")
    assert path.read_bytes() == before
    assert list(path.parent.iterdir()) == [path]


def test_verified_message_persisted_before_success_and_replay(qapp, environment):
    from app.windows.main_screen import MainScreen
    sender = CryptoManager()
    sender.generate_new_keypair()
    crypto.generate_new_keypair()
    from app.contact_keys import fingerprint_public_key
    key = sender.get_public_key_b64()
    state.allies = {"sender": {"devices": [{"device_id": "sender-device", "public_key": key,
                                             "verified_fingerprint": fingerprint_public_key(key),
                                             "verified_scope": {"username": "receiver", "device_id": "receiver-device", "server_url": "https://node"}}]}}
    screen = MainScreen()
    payload = json.dumps({"type": "text", "text": "private", "msg_id": "msg-1"})
    encrypted = sender.encrypt_message(payload, crypto.get_public_key_b64())
    envelope = {"id": "server-id", "sender_device_id": "sender-device", **encrypted}
    assert screen.process_incoming_message(envelope, is_sync=True)
    assert screen.process_incoming_message(envelope, is_sync=True)
    assert [m["text"] for m in storage.load_messages("receiver", "sender")] == ["private"]
    assert not screen.process_incoming_message({**envelope, "sender_device_id": "unknown"}, is_sync=True)
    assert not screen.process_incoming_message({**envelope, "signature": "invalid"}, is_sync=True)
    screen.deleteLater()


def test_legacy_duplicate_compares_content_direction_and_reply(environment):
    kw=dict(msg_id='same',reply_to_msg_id='reply',reply_to_text='old',reply_to_sender='friend')
    assert storage.save_message('receiver','sender','original',False,**kw)
    path=storage._get_messages_file('receiver','sender'); before=path.read_bytes()
    assert not storage.save_message('receiver','sender','original',False,timestamp='other',is_read=True,**kw)
    for text,is_mine,options in [('different',False,kw),('original',True,kw),
                                 ('original',False,{**kw,'reply_to_text':'changed'})]:
        with pytest.raises(ValueError,match='Conflicting'):
            storage.save_message('receiver','sender',text,is_mine,**options)
        assert path.read_bytes()==before


def test_legacy_tombstone_preserves_identity_and_old_tombstones_fail_closed(environment):
    assert storage.save_message('receiver','sender','private',False,msg_id='new')
    assert storage.delete_message('receiver','sender','new')
    path=storage._get_messages_file('receiver','sender'); after_delete=path.read_bytes()
    assert not storage.save_message('receiver','sender','private',False,msg_id='new')
    with pytest.raises(ValueError,match='Conflicting'):
        storage.save_message('receiver','sender','different',False,msg_id='new')
    assert path.read_bytes()==after_delete
    # Existing tombstones predate the keyed content identity and cannot be safely matched.
    storage._save_messages_to_file('receiver','sender',[
        {'msg_id':'old','text':'','is_mine':False,'deleted':True}])
    before=path.read_bytes()
    with pytest.raises(ValueError,match='Cannot verify'):
        storage.save_message('receiver','sender','original',False,msg_id='old')
    assert path.read_bytes()==before


def test_legacy_deleted_identity_survives_manual_copy_migration(environment, tmp_path):
    from app.history_store import migrate_legacy_copy
    from app.secure_storage import SecureStorage
    assert storage.save_message('receiver','sender','private',False,msg_id='msg')
    assert storage.delete_incoming_message('receiver','sender','msg')
    source=storage._get_messages_file('receiver','sender'); before=source.read_bytes()
    key=SecureStorage._get_or_create_local_key('receiver')
    store=migrate_legacy_copy(source,tmp_path/'copied.sqlite3',key,'receiver','sender')
    message={'msg_id':'msg','text':'private','is_mine':False,'is_read':False,'deleted':False,'timestamp':'new'}
    assert not store.append(message)
    with pytest.raises(ValueError,match='Conflicting'):
        store.append({**message,'text':'different'})
    assert not store.page().messages and source.read_bytes()==before
