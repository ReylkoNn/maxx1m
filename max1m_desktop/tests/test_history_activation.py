import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from app import secure_storage, history_activation
from app.instance_guard import acquire_instance_lock, InstanceAlreadyRunning


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda service, name: keys.get(name))
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda service, name, value: keys.__setitem__(name, value))
    storage = secure_storage.SecureStorage
    for i in range(30):
        storage.save_message('alice', 'bob', f'message {i}', i % 2 == 0, msg_id=f'id-{i}')
    source, database, catalog = history_activation.paths('alice', 'bob')
    return storage, source, database, catalog, keys


def test_explicit_migration_routes_all_chat_operations_and_preserves_backup(setup):
    storage, source, database, catalog, keys = setup
    original = source.read_bytes()
    before = storage.load_history_page('alice', 'bob')
    assert history_activation.migrate_chat('alice', 'bob') is True
    assert source.read_bytes() == original and database.exists() and catalog.exists()
    assert storage.load_history_page('alice', 'bob') == before
    assert not history_activation.migrate_chat('alice', 'bob')  # No re-import after cutover.
    assert storage.save_message('alice', 'bob', 'new content', False, msg_id='new')
    assert not storage.save_message('alice', 'bob', 'new content', False, msg_id='new')
    with pytest.raises(ValueError, match='Conflicting'):
        storage.save_message('alice', 'bob', 'different', False, msg_id='new')
    assert storage.history_offset_for_id('alice', 'bob', 'new') == 0
    assert storage.mark_messages_as_read('alice', 'bob', ['new'])
    assert storage.delete_incoming_message('alice', 'bob', 'new')
    assert storage.delete_incoming_message('alice', 'bob', 'new')
    assert not storage.delete_incoming_message('alice', 'bob', 'id-0')  # outgoing
    assert storage.delete_message('alice', 'bob', 'id-0')
    assert not storage.delete_message('alice', 'bob', 'id-0')
    assert source.read_bytes() == original
    with pytest.raises(ValueError, match='Refusing to overwrite'):
        storage._save_messages_to_file('alice', 'bob', [])
    assert storage.clear_chat('alice', 'bob')
    assert storage.load_history_page('alice', 'bob').total == 0
    assert source.read_bytes() == original  # Clear is not secure erasure.
    assert storage.save_message('alice', 'bob', 'after clear', True, msg_id='next')
    assert storage.load_messages_strict('alice', 'bob')[0]['text'] == 'after clear'


def test_unmigrated_chat_stays_on_legacy_when_other_chat_migrated(setup):
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice', 'bob')
    assert storage.save_message('alice', 'carol', 'legacy', True, msg_id='x')
    csrc, cdb, _ = history_activation.paths('alice', 'carol')
    assert csrc.exists() and not cdb.exists()
    assert storage.load_history_page('alice', 'carol').messages[0]['text'] == 'legacy'


def test_missing_or_changed_components_never_fall_back_to_stale_legacy(setup):
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice', 'bob')
    storage.save_message('alice', 'bob', 'new row', False, msg_id='later')
    backup = source.read_bytes()
    source.write_bytes(b'legacy changed by an old client')
    for operation in (lambda: storage.load_history_page('alice', 'bob'),
                      lambda: storage.load_history_page_background('alice', 'bob', target_id='id-1'),
                      lambda: storage.save_message('alice', 'bob', 'x', False, msg_id='x'),
                      lambda: storage.clear_chat('alice', 'bob'),
                      lambda: storage.load_messages('alice', 'bob')):
        with pytest.raises(ValueError, match='changed'): operation()
    source.write_bytes(backup)
    assert storage.load_history_page('alice', 'bob').messages[-1]['text'] == 'new row'
    catalog_data = catalog.read_bytes()
    catalog.unlink()
    with pytest.raises(ValueError, match='Unfinished'):
        storage.load_history_page('alice', 'bob')
    catalog.write_bytes(catalog_data)
    os.rename(database, database.with_suffix('.offline'))
    with pytest.raises(ValueError, match='missing'):
        storage.load_history_page('alice', 'bob')
    assert source.read_bytes() == backup


def test_corrupt_catalog_and_wrong_database_are_rejected(setup, tmp_path):
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice', 'bob')
    original = catalog.read_bytes()
    catalog.write_bytes(b'corrupt')
    with pytest.raises(Exception): storage.save_message('alice', 'bob', 'new', False, msg_id='new')
    catalog.write_bytes(original)
    from app.history_store import EncryptedHistory
    key = storage._get_or_create_local_key('alice')
    alternative = tmp_path/'alternative.sqlite3'
    EncryptedHistory.create(alternative, key, 'alice', 'bob')
    os.replace(alternative, database)
    with pytest.raises(ValueError, match='identity'):
        storage.load_history_page('alice', 'bob')
    assert source.exists()


def test_interrupted_catalog_publication_fails_closed_and_resumes(setup, monkeypatch):
    storage, source, database, catalog, keys = setup
    original = source.read_bytes()
    write = history_activation.write_catalog
    monkeypatch.setattr(history_activation, 'write_catalog', lambda *a: (_ for _ in ()).throw(OSError('disk full')))
    with pytest.raises(OSError): history_activation.migrate_chat('alice', 'bob')
    assert database.exists() and not catalog.exists() and source.read_bytes() == original
    with pytest.raises(ValueError, match='Unfinished'):
        storage.load_history_page('alice', 'bob')
    monkeypatch.setattr(history_activation, 'write_catalog', write)
    assert history_activation.migrate_chat('alice', 'bob')
    assert storage.load_history_page('alice', 'bob').total == 30


def test_resume_rejects_candidate_edited_after_interruption(setup, monkeypatch):
    storage, source, database, catalog, keys = setup
    write = history_activation.write_catalog
    monkeypatch.setattr(history_activation, 'write_catalog', lambda *a: (_ for _ in ()).throw(OSError()))
    with pytest.raises(OSError): history_activation.migrate_chat('alice', 'bob')
    from app.history_store import EncryptedHistory
    store = EncryptedHistory(database, storage._get_or_create_local_key('alice'), 'alice', 'bob')
    store.append({'msg_id':'injected', 'text':'different'})
    monkeypatch.setattr(history_activation, 'write_catalog', write)
    with pytest.raises(ValueError, match='does not match'):
        history_activation.migrate_chat('alice', 'bob')
    assert not catalog.exists() and source.exists() and database.exists()


def test_migration_is_blocked_by_running_updated_desktop(setup):
    storage, source, database, catalog, keys = setup
    lock = acquire_instance_lock(secure_storage.BASE_DIR)
    try:
        with pytest.raises(InstanceAlreadyRunning): history_activation.migrate_chat('alice', 'bob')
        assert not database.exists() and not catalog.exists() and source.exists()
    finally:
        lock.unlock()
    assert history_activation.migrate_chat('alice', 'bob')


def test_migrated_backend_failure_never_acknowledges_unsaved_input(setup, monkeypatch):
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice', 'bob')
    from app.history_store import EncryptedHistory
    from app.delivery import process_delivery_page
    real = EncryptedHistory._encrypt
    monkeypatch.setattr(EncryptedHistory, '_encrypt', lambda *a, **kw: (_ for _ in ()).throw(OSError('disk failure')))
    def process(item):
        try:
            storage.save_message('alice', 'bob', 'received', False, msg_id='incoming')
            return True
        except Exception:
            return False
    assert process_delivery_page([{'id':'server-id'}], process)[0] == []
    assert storage.load_history_page('alice', 'bob').total == 30
    monkeypatch.setattr(EncryptedHistory, '_encrypt', real)
    assert process_delivery_page([{'id':'server-id'}], process)[0] == ['server-id']
    assert storage.load_history_page('alice', 'bob').total == 31


def test_legacy_changes_during_write_does_not_report_success(setup, monkeypatch):
    from app.experimental_history_adapter import ExperimentalHistoryAdapter
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice', 'bob')
    original = source.read_bytes()
    real = ExperimentalHistoryAdapter.save_message
    def race(self, *args, **kwargs):
        value = real(self, *args, **kwargs)
        source.write_bytes(b'old client racing')
        return value
    monkeypatch.setattr(ExperimentalHistoryAdapter, 'save_message', race)
    with pytest.raises(ValueError, match='changed'):
        storage.save_message('alice', 'bob', 'durably saved', False, msg_id='retry')
    source.write_bytes(original)
    monkeypatch.setattr(ExperimentalHistoryAdapter, 'save_message', real)
    # The database commit happened, but the caller must retry before ACK.
    assert not storage.save_message('alice', 'bob', 'durably saved', False, msg_id='retry')
    assert storage.load_history_page('alice', 'bob').messages[-1]['text'] == 'durably saved'


def test_cli_requires_explicit_confirmation(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root/'migrate_history.py'), 'alice', 'bob'],
                            cwd=root, capture_output=True, text=True, timeout=10)
    assert result.returncode != 0 and '--confirm-backup-and-stop-old-clients' in result.stderr


def test_multiple_migrations_use_same_encrypted_catalog(setup):
    storage, source, database, catalog, keys = setup
    storage.save_message('alice', 'carol', 'private carol', False, msg_id='c1')
    original_carol = history_activation.paths('alice', 'carol')[0].read_bytes()
    assert history_activation.migrate_chat('alice', 'bob')
    assert history_activation.migrate_chat('alice', 'carol')
    assert storage.save_message('alice', 'bob', 'new bob', False, msg_id='b2')
    assert storage.save_message('alice', 'carol', 'new carol', False, msg_id='c2')
    assert storage.load_history_page('alice', 'carol').total == 2
    assert history_activation.paths('alice', 'carol')[0].read_bytes() == original_carol
    assert b'carol' not in catalog.read_bytes() and b'bob' not in catalog.read_bytes()


def test_failed_migration_leaves_legacy_operational(setup):
    storage, source, database, catalog, keys = setup
    # Existing duplicate IDs are not silently discarded by migration.
    all_messages = storage._load_all_messages('alice', 'bob')
    all_messages.append(dict(all_messages[0]))
    storage._save_messages_to_file('alice', 'bob', all_messages)
    original = source.read_bytes()
    with pytest.raises(ValueError, match='Duplicate'):
        history_activation.migrate_chat('alice', 'bob')
    assert source.read_bytes() == original and not database.exists() and not catalog.exists()
    assert storage.save_message('alice', 'bob', 'more', False, msg_id='after')


def test_catalog_key_missing_never_generates_replacement(setup, monkeypatch):
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice', 'bob')
    source.unlink(); database.unlink()
    writes = []
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda *args: None)
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda *args: writes.append(args))
    with pytest.raises(ValueError, match='key is missing'):
        storage._get_or_create_local_key('alice')
    assert not writes and catalog.exists()


def test_full_catalog_rejects_migration_before_creating_database(setup, monkeypatch):
    storage, source, database, catalog, keys = setup
    monkeypatch.setattr(history_activation, 'MAX_CATALOG_CHATS', 0)
    with pytest.raises(ValueError, match='catalog is full'):
        history_activation.migrate_chat('alice', 'bob')
    assert source.exists() and not database.exists() and not catalog.exists()


def test_real_cli_resumes_after_process_exit_between_copy_and_cutover(tmp_path):
    import base64
    home = tmp_path/'home'; home.mkdir()
    overrides = tmp_path/'overrides'; overrides.mkdir()
    encoded = base64.b64encode(b'Z'*32).decode()
    (overrides/'keyring.py').write_text(
        f'def get_password(service, name):\n    return {encoded!r} if name == "alice_local_storage_key" else None\n'
        'def set_password(*args):\n    raise AssertionError("key must not be replaced")\n')
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, 'HOME':str(home), 'PYTHONPATH':os.pathsep.join((str(overrides), str(root)))}
    def run_code(code):
        return subprocess.run([sys.executable, '-c', code], cwd=root, env=env,
                              capture_output=True, text=True, timeout=15)
    prepare = run_code("from app.secure_storage import SecureStorage as s; s.save_message('alice','bob','secret old',False,msg_id='old')")
    assert prepare.returncode == 0, prepare.stderr
    source = home/'.max1m/profiles/alice/messages/bob.enc'
    original = source.read_bytes()
    interrupted = run_code("import os; import app.history_activation as h; h.write_catalog=lambda *a: os._exit(19); h.migrate_chat('alice','bob')")
    assert interrupted.returncode == 19
    database = source.with_suffix('.history.sqlite3')
    catalog = home/'.max1m/profiles/alice/history_catalog.enc'
    assert database.exists() and not catalog.exists() and source.read_bytes() == original
    fail_closed = run_code("from app.secure_storage import SecureStorage as s; s.load_history_page('alice','bob')")
    assert fail_closed.returncode != 0 and 'Unfinished' in fail_closed.stderr
    result = subprocess.run([sys.executable, str(root/'migrate_history.py'), 'alice', 'bob',
                             '--confirm-backup-and-stop-old-clients'], cwd=root, env=env,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert catalog.exists() and source.read_bytes() == original
    verified = run_code("from app.secure_storage import SecureStorage as s; "
                        "assert s.load_history_page('alice','bob').messages[0]['text']=='secret old'; "
                        "assert s.save_message('alice','bob','new',False,msg_id='new'); "
                        "assert s.load_history_page('alice','bob').total==2")
    assert verified.returncode == 0, verified.stderr
    assert source.read_bytes() == original


def test_active_pages_and_writes_do_not_load_legacy_json_in_memory(setup, monkeypatch):
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice', 'bob')
    def forbid(*args, **kwargs): raise AssertionError('must not load monolithic history')
    monkeypatch.setattr(storage, '_load_all_messages', forbid)
    assert len(storage.load_history_page('alice', 'bob').messages) == 25
    assert storage.history_offset_for_id('alice', 'bob', 'id-3') == 26
    assert storage.save_message('alice', 'bob', 'new', False, msg_id='new')
    assert storage.mark_messages_as_read('alice', 'bob', ['new'])
    assert storage.delete_incoming_message('alice', 'bob', 'new')


def test_refuse_stale_legacy_before_ack_using_real_crypto_and_callback(setup):
    import ast
    import json
    from types import SimpleNamespace
    from app.crypto_box import CryptoManager
    from app.contact_keys import fingerprint_public_key
    from app.incoming_identity import verify_incoming, IncomingIdentityError
    from app.delivery import process_delivery_page
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice', 'bob')
    sender, receiver = CryptoManager(), CryptoManager()
    sender.generate_new_keypair(); receiver.generate_new_keypair()
    key = sender.get_public_key_b64()
    device = {'device_id':'dev-bob', 'public_key':key, 'verified_fingerprint':fingerprint_public_key(key),
              'verified_scope':{'username':'alice','device_id':'dev-alice','server_url':'https://node'}}
    state = SimpleNamespace(username='alice', device_id='dev-alice', server_url='https://node',
                            current_chat_username=None, allies={'bob':{'devices':[device]}})
    envelope = {'id':'server-id', 'sender_device_id':'dev-bob',
                **sender.encrypt_message(json.dumps({'type':'text','text':'secure new','msg_id':'secure-id'}), receiver.get_public_key_b64())}
    path = Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    tree = ast.parse(path.read_text())
    wanted = {'_handle_decrypted_payload', 'process_incoming_message'}
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'MainScreen'
             for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    env = {'json':json, 'state':state, 'storage':storage, 'crypto':receiver,
           'verify_incoming':verify_incoming, 'IncomingIdentityError':IncomingIdentityError}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), env)
    class Screen:
        _incoming_identity_notice_shown = False
        incoming_message_processed = SimpleNamespace(emit=lambda value: None)
        def window(self): return SimpleNamespace(isActiveWindow=lambda: True)
        def _get_ally_card(self, username): return None
        def _get_ally_item(self, username): return None
    Screen._handle_decrypted_payload = env['_handle_decrypted_payload']
    Screen.process_incoming_message = env['process_incoming_message']
    screen = Screen()
    process = lambda item: screen.process_incoming_message(item, is_sync=True)
    backup = source.read_bytes()
    source.write_bytes(b'old client changed backup')
    assert process_delivery_page([envelope], process)[0] == []
    source.write_bytes(backup)
    assert process_delivery_page([envelope], process)[0] == ['server-id']
    assert process_delivery_page([envelope], process)[0] == ['server-id']
    assert storage.load_history_page('alice', 'bob').messages[-1]['text'] == 'secure new'


def test_background_page_matches_sync_and_rejects_stale_revision(setup):
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice', 'bob')
    # More than two 32-row chunks, including filtered page boundaries.
    for i in range(55):
        assert storage.save_message('alice', 'bob', f'extra {i}', False, msg_id=f'extra-{i}')
    for offset in (0, 25, 40, 100):
        for query in (None, 'message 2', 'extra', 'not found'):
            page, revision = storage.load_history_page_background('alice', 'bob', offset, query=query)
            assert page == storage.load_history_page('alice', 'bob', offset, query=query)
            assert revision == storage.history_revision('alice')
    page, revision = storage.load_history_page_background('alice', 'bob')
    storage.save_message('alice', 'bob', 'new', False, msg_id='new')
    assert storage.mark_messages_as_read_if_revision('alice', 'bob', ['id-1'], revision) is None
    assert not next(x for x in storage.load_messages_strict('alice','bob') if x['msg_id']=='id-1')['is_read']


def test_background_scan_does_not_hold_profile_or_sqlite_read_lock_during_decryption(setup, monkeypatch):
    import concurrent.futures
    import threading
    from app.history_store import EncryptedHistory
    from app.history_paging import HistoryStale
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice', 'bob')
    entered, release = threading.Event(), threading.Event()
    real = EncryptedHistory._decrypt
    def slow(self, *args):
        if threading.current_thread() is not threading.main_thread() and not entered.is_set():
            entered.set()
            assert release.wait(5)
        return real(self, *args)
    monkeypatch.setattr(EncryptedHistory, '_decrypt', slow)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        scan=pool.submit(storage.load_history_page_background,'alice','bob')
        try:
            assert entered.wait(3)
            write=pool.submit(storage.save_message,'alice','bob','new',False,msg_id='during-scan')
            assert write.result(timeout=3) is True
        finally:
            release.set()
        with pytest.raises(HistoryStale): scan.result(timeout=3)
    assert storage.load_history_page('alice','bob').messages[-1]['text']=='new'


def test_mark_read_is_atomic_against_newer_history_revision(setup):
    storage, source, database, catalog, keys = setup
    history_activation.migrate_chat('alice','bob')
    page, version=storage.load_history_page_background('alice','bob')
    assert storage.mark_messages_as_read_if_revision('alice','bob',['id-1'],version) is True
    assert storage.mark_messages_as_read_if_revision('alice','bob',['id-3'],version) is None
