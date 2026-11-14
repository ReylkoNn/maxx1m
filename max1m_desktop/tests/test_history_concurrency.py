import concurrent.futures
import threading
import time
from pathlib import Path
import pytest
from app import secure_storage
from app.history_paging import HistoryCancelled


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    keys, writes = {}, []
    def get(service, name):
        time.sleep(0.001)
        return keys.get(name)
    def set_key(service, name, value):
        time.sleep(0.001)
        writes.append(name); keys[name] = value
    monkeypatch.setattr(secure_storage.keyring, 'get_password', get)
    monkeypatch.setattr(secure_storage.keyring, 'set_password', set_key)
    return secure_storage.SecureStorage, writes


def test_concurrent_key_initialization_is_serialized_per_profile(setup):
    storage,writes=setup
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        keys=list(pool.map(lambda _: storage._get_or_create_local_key('alice'), range(30)))
    assert len(set(keys)) == 1 and writes == ['alice_local_storage_key']


def test_concurrent_legacy_chat_writes_do_not_overwrite_each_other(setup, monkeypatch):
    storage,writes=setup
    load=storage._load_all_messages
    def slow_load(*args):
        value=load(*args)
        time.sleep(0.002)  # Widens the former read-modify-write race.
        return value
    monkeypatch.setattr(storage, '_load_all_messages', slow_load)
    def write(i):
        return storage.save_message('alice','bob',f'text-{i}',False,msg_id=f'id-{i}')
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        assert all(pool.map(write,range(60)))
    records=storage.load_messages_strict('alice','bob')
    assert len(records)==60 and {m['msg_id'] for m in records} == {f'id-{i}' for i in range(60)}
    assert len(writes)==1


def test_cancellable_reader_can_abort_while_waiting_for_profile_lock(setup):
    storage,_=setup
    entered=threading.Event(); release=threading.Event(); cancelled=threading.Event()
    lock=secure_storage._PROFILE_LOCKS[hash('alice') % len(secure_storage._PROFILE_LOCKS)]
    def hold():
        with lock:
            entered.set()
            assert release.wait(3)
    thread=threading.Thread(target=hold); thread.start()
    try:
        assert entered.wait(2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(storage.load_history_page,'alice','bob',cancel=cancelled.is_set)
            cancelled.set()
            with pytest.raises(HistoryCancelled): future.result(timeout=2)
    finally:
        release.set(); thread.join(3)
    assert not thread.is_alive()


def test_failed_operation_releases_profile_lock(setup, monkeypatch):
    storage,_=setup
    original=storage._save_messages_to_file
    monkeypatch.setattr(storage, '_save_messages_to_file', lambda *a: (_ for _ in ()).throw(OSError('disk')))
    with pytest.raises(OSError): storage.save_message('alice','bob','first',False,msg_id='first')
    monkeypatch.setattr(storage, '_save_messages_to_file', original)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(storage.save_message,'alice','bob','second',False,msg_id='second').result(timeout=3)
    assert storage.load_history_page('alice','bob').total == 1


def test_contact_store_fallback_username_uses_same_profile_lock(setup, monkeypatch):
    storage,_=setup
    monkeypatch.setattr(storage,'load_local_state',lambda: {'username':'alice'})
    lock=secure_storage._PROFILE_LOCKS[hash('alice') % len(secure_storage._PROFILE_LOCKS)]
    entered=threading.Event(); release=threading.Event()
    def hold():
        with lock:
            entered.set(); assert release.wait(3)
    thread=threading.Thread(target=hold); thread.start()
    try:
        assert entered.wait(2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(storage.save_allies,'',{'bob':{}})
            time.sleep(0.1)
            assert not future.done()
            release.set()
            assert future.result(timeout=2) is None
    finally:
        release.set(); thread.join(3)
    assert storage.load_allies('alice') == {'bob':{}}


def test_contact_fallback_account_is_frozen_before_lock(setup, monkeypatch):
    storage,_=setup
    calls=[]
    def changing_state():
        calls.append(True)
        return {'username': 'alice' if len(calls)==1 else 'bob'}
    monkeypatch.setattr(storage,'load_local_state',changing_state)
    storage.save_allies('', {'contact':{}})
    assert len(calls)==1 and storage.load_allies('alice') == {'contact':{}}
    assert storage.load_allies('bob') == {}


def test_legacy_background_page_matches_and_rejects_stale(tmp_path, monkeypatch):
    import threading
    from app import secure_storage
    from app.history_paging import HistoryStale
    from concurrent.futures import ThreadPoolExecutor
    keys={}
    monkeypatch.setattr(secure_storage,'BASE_DIR',tmp_path)
    monkeypatch.setattr(secure_storage.keyring,'get_password',lambda service,name:keys.get(name))
    monkeypatch.setattr(secure_storage.keyring,'set_password',lambda service,name,value:keys.__setitem__(name,value))
    storage=secure_storage.SecureStorage
    assert storage.save_message('alice','bob','first',False,msg_id='one')
    page,revision=storage.load_history_page_background('alice','bob')
    assert page==storage.load_history_page('alice','bob')
    entered,release=threading.Event(),threading.Event()
    original=secure_storage.nacl.secret.SecretBox.decrypt
    def slow(self,*args,**kwargs):
        if threading.current_thread() is not threading.main_thread() and not entered.is_set():
            entered.set(); assert release.wait(5)
        return original(self,*args,**kwargs)
    monkeypatch.setattr(secure_storage.nacl.secret.SecretBox,'decrypt',slow)
    with ThreadPoolExecutor(max_workers=2) as pool:
        scan=pool.submit(storage.load_history_page_background,'alice','bob')
        try:
            assert entered.wait(3)
            # Write on the main thread because the test only pauses the scan thread.
            assert storage.save_message('alice','bob','second',False,msg_id='two')
        finally: release.set()
        with pytest.raises(HistoryStale): scan.result(timeout=3)
    assert storage.mark_messages_as_read_if_revision('alice','bob',['one'],revision) is None
