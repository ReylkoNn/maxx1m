import ast
import json
from pathlib import Path
from types import SimpleNamespace
from app.crypto_box import CryptoManager
from app.group_crypto import group_crypto, store_member_sender_key
from app.workers import FetchGroupsWorker, LeaveGroupWorker, DeleteGroupWorker

class Response:
    def __init__(self, content=b'[]', status=200): self.content, self.status_code, self.closed = content, status, False
    def iter_content(self, _): yield self.content
    def close(self): self.closed = True

def collect(worker):
    result = []
    worker.finished.connect(lambda *args: result.append(args))
    worker.run()
    return result

def test_group_list_bounded_validated_and_no_redirect(monkeypatch):
    calls = []
    response = Response(json.dumps([{'id':'good-id', 'name':'Group', 'members':[]}]).encode())
    monkeypatch.setattr('app.workers.requests.get', lambda *a, **kw: calls.append(kw) or response)
    result = collect(FetchGroupsWorker('https://server', 'token'))
    assert result[0][0] and response.closed and calls[0]['stream'] and not calls[0]['allow_redirects']
    for body in (b'x'*(4*1024*1024+1), b'{}', json.dumps([{'id':'../bad', 'name':'G','members':[]}]).encode(),
                 json.dumps([{'id':'same','name':'G','members':[]}] * 2).encode()):
        response = Response(body)
        assert not collect(FetchGroupsWorker('https://server', 'token'))[0][0] and response.closed
    response = Response(status=503)
    assert collect(FetchGroupsWorker('https://server', 'token'))[0] == (False, 'HTTP 503') and response.closed

def test_group_actions_bounded_and_reject_redirect(monkeypatch):
    for name, cls in [('post', LeaveGroupWorker), ('delete', DeleteGroupWorker)]:
        response = Response(b'{"status":"ok"}')
        calls = []
        monkeypatch.setattr('app.workers.requests.'+name, lambda *a, **kw: calls.append(kw) or response)
        assert collect(cls('https://server','token','group'))[0][0] and response.closed
        assert calls[0]['stream'] and not calls[0]['allow_redirects']
        response = Response(status=307)
        assert not collect(cls('https://server','token','group'))[0][0] and response.closed
        response = Response(b'x' * (16*1024+1))
        assert not collect(cls('https://server','token','group'))[0][0] and response.closed

def extract(names, env):
    path = Path(__file__).resolve().parents[1] / 'app/windows/main_screen.py'
    tree = ast.parse(path.read_text())
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'MainScreen'
             for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(nodes) == len(names)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), env)
    return [env[n] for n in names]

class Signal:
    def connect(self, fn, *_): self.fn = fn
    def emit(self, *args): self.fn(*args)
class Worker:
    made = []
    def __init__(self, server, token, group_id):
        self.group_id = group_id; self.finished = Signal(); self.waited = False
        Worker.made.append(self)
    def start(self): pass
    def wait(self): self.waited = True

def test_group_completion_binds_origin_and_preserves_local_history():
    state = SimpleNamespace(username='alice', server_url='https://node', device_id='dev', token='t',
                            current_chat_type='group', current_group_id='group1',
                            groups={'group1': {'name':'One'}, 'group2': {'name':'Two'}})
    QMessageBox = SimpleNamespace(Yes=1, No=2, question=lambda *a: 1, warning=lambda *a: None)
    env = {'state':state, 'DeleteGroupWorker':Worker, 'LeaveGroupWorker':Worker,
           'QMessageBox':QMessageBox, 'Qt':SimpleNamespace(QueuedConnection=0)}
    names = ['force_remove_group', '_group_action_context', '_delete_group_on_server', '_leave_group_on_server',
             '_finish_group_action', '_on_group_deleted_response', '_on_group_left_response']
    methods = dict(zip(names, extract(names, env)))
    Screen = type('Screen', (), methods)
    screen = Screen(); screen._net_workers = []
    screen._get_group_card = lambda gid: None
    screen.chat_title = SimpleNamespace(setText=lambda *_: None)
    screen._delete_group_on_server(); worker = Worker.made[-1]
    state.current_group_id = 'group2'
    worker.finished.emit(True, {}, 'group1')
    assert worker.waited and state.groups['group1']['archived'] and not state.groups['group2'].get('archived')
    # `storage` is not in the environment: any attempted history deletion fails the test.
    screen._leave_group_on_server(); stale = Worker.made[-1]
    state.username = 'another_account'
    stale.finished.emit(True, {}, 'group2')
    assert not state.groups['group2'].get('archived')

def test_confirmation_cannot_clear_switched_chat():
    state = SimpleNamespace(username='a', server_url='s', device_id='d', token='t',
                            current_chat_type='ally', current_chat_username='bob', current_group_id=None, groups={})
    def question(*_):
        state.current_chat_username = 'eve'
        return 1
    warnings = []
    env = {'state':state, 'QMessageBox':SimpleNamespace(Yes=1, No=2, question=question, warning=lambda *a: warnings.append(a))}
    method = extract(['_confirm_clear_chat'], env)[0]
    class Screen:
        _confirm_clear_chat = method
        def _clear_chat(self): raise AssertionError('wrong chat must not be cleared')
    Screen()._confirm_clear_chat()
    assert warnings


def test_group_list_callback_rejects_stale_account_and_starts_no_crypto_workers():
    path = Path(__file__).resolve().parents[1] / 'app/windows/app_window.py'
    tree = ast.parse(path.read_text())
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'AppWindow'
             for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_on_groups_fetched']
    state = SimpleNamespace(username='alice', server_url='https://node', device_id='dev', token='t', groups={})
    env = {'state': state}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), env)
    class Screen:
        _on_groups_fetched = env['_on_groups_fetched']
    screen = Screen()
    worker = SimpleNamespace(account_context=('different', 'https://node', 'dev', 't'), wait=lambda: None)
    screen.groups_fetch_worker = worker
    data = [{'id':'g1', 'name':'Group', 'created_by_device_id':'dev', 'members':[]}]
    screen._on_groups_fetched(True, data, worker)
    assert not state.groups
    worker.account_context = ('alice', 'https://node', 'dev', 't')
    screen._on_groups_fetched(True, data, worker)
    assert state.groups['g1']['my_sender_key'] is None
    assert state.groups['g1']['sender_keys'] == {}


def test_group_member_roster_completion_recovers_sender_key_fetched_too_early():
    alice = CryptoManager(); alice.generate_new_keypair()
    bob = CryptoManager(); bob.generate_new_keypair()
    alice_id, bob_id, group_id = 'alice-device', 'bob-device', 'g1'
    alice_key = group_crypto.generate_sender_key(group_id='', epoch=1)
    encrypted_key, signature = group_crypto.encrypt_sender_key_for_member(
        alice_key, bob.get_public_key_b64(), group_id='',
        sender_device_id=alice_id, recipient_device_id=bob_id,
        crypto_mgr=alice,
    )

    state = SimpleNamespace(
        username='bob', server_url='https://node', device_id=bob_id, token='t',
        groups={group_id: {'members': [], 'sender_keys': {}, 'epoch': 1}},
    )
    events = ['initial_sender_key_fetch']  # Started concurrently by group_created.
    env = {
        'state': state,
        'group_crypto': SimpleNamespace(
            decrypt_sender_key=lambda *args, **kwargs: group_crypto.decrypt_sender_key(
                *args, crypto_mgr=bob, **kwargs
            )
        ),
        'store_member_sender_key': store_member_sender_key,
    }
    names = ['ingest_sender_key_entry', '_on_group_members_loaded']
    ingest, on_members_loaded = extract(names, env)
    members = [{'device_id': alice_id, 'public_key': alice.get_public_key_b64(),
                'device_name': 'Alice'}]
    worker = SimpleNamespace(
        account_context=('bob', 'https://node', bob_id, 't'),
        _force_rotate=False, _target_epoch=1,
    )

    class Screen:
        ingest_sender_key_entry = ingest
        _on_group_members_loaded = on_members_loaded
        def __init__(self): self._net_workers = [worker]
        def _resolve_group_member_pub_and_name(self, gid, sender_id):
            for member in state.groups[gid]['members']:
                if member.get('device_id') == sender_id:
                    return member.get('public_key'), member.get('device_name', '')
            return None, ''
        def _save_group_keys_safe(self): pass
        def ensure_my_group_sender_key(self, gid, **_kwargs):
            assert state.groups[gid]['members'] is members
            assert alice_id in state.groups[gid]['sender_keys']
            events.append('ensure_own_key')
        def _request_group_sender_keys(self, gid):
            assert state.groups[gid]['members'] is members
            events.append('retry_sender_key_fetch_with_roster')
        def _drain_deferred_group_messages(self, _gid): events.append('drain_deferred')

    screen = Screen()
    # This is the reproducible bad order: SenderKey response arrives before
    # FetchGroupMembers, so its authenticated sender key cannot be resolved.
    assert not screen.ingest_sender_key_entry(
        group_id, alice_id, encrypted_key, signature, epoch=1
    )
    assert not state.groups[group_id]['sender_keys']

    # group_created also carries the same encrypted key inline. It is held until
    # the authoritative member response makes signature verification possible.
    screen._pending_group_sender_keys = {
        (state.username, state.server_url, state.device_id, group_id): [{
            'sender_device_id': alice_id,
            'encrypted_sender_key': encrypted_key,
            'sender_key_signature': signature,
            'epoch': 1,
        }]
    }
    screen._on_group_members_loaded(True, members, group_id, worker)
    assert events == [
        'initial_sender_key_fetch', 'drain_deferred', 'ensure_own_key',
        'retry_sender_key_fetch_with_roster', 'drain_deferred',
    ]
    assert alice_id in state.groups[group_id]['sender_keys']


def test_group_created_event_queues_inline_sender_key_until_roster_is_loaded():
    state = SimpleNamespace(
        username='bob', server_url='https://node', device_id='bob-device', groups={}
    )
    method = extract(
        ['process_group_created_event'],
        {'state': state, 'SERVER_GROUP_NAME_PLACEHOLDER': '[E2EE]'},
    )[0]
    calls = []
    screen = SimpleNamespace(
        _get_group_item=lambda _gid: None,
        _add_group_card=lambda *args: calls.append(('card', args)),
        _persist_groups_index=lambda: None,
        _fetch_group_members_and_rotate=lambda gid, **kwargs: calls.append(('members', gid, kwargs)),
        _request_group_sender_keys=lambda gid: calls.append(('keys', gid)),
    )
    entry = {
        'encrypted_sender_key': 'opaque-encrypted-key',
        'sender_key_signature': 'signature',
        'epoch': 1,
    }
    method(screen, {
        'group_id': 'g1', 'group_name': '[E2EE]', 'epoch': 1,
        'created_by': 'alice-device', 'sender_key_from': 'alice-device',
        'sender_key': entry,
    })
    assert screen._pending_group_sender_keys[('bob', 'https://node', 'bob-device', 'g1')] == [{
        'sender_device_id': 'alice-device',
        'encrypted_sender_key': 'opaque-encrypted-key',
        'sender_key_signature': 'signature',
        'epoch': 1,
    }]
    assert ('members', 'g1', {'target_epoch': 1}) in calls
    assert ('keys', 'g1') in calls


def test_delete_group_confirmation_does_not_target_switched_group():
    state = SimpleNamespace(username='alice', server_url='https://node', device_id='dev', token='t',
                            current_chat_type='group', current_group_id='one',
                            groups={'one': {'name':'one'}, 'two': {'name':'two'}})
    def switch(*_):
        state.current_group_id = 'two'
        return 1
    env = {'state':state, 'DeleteGroupWorker':Worker, 'QMessageBox':SimpleNamespace(Yes=1, No=2, question=switch)}
    names = ['_group_action_context', '_delete_group_on_server']
    screen = type('Screen', (), dict(zip(names, extract(names, env))))()
    count = len(Worker.made)
    screen._delete_group_on_server()
    assert len(Worker.made) == count


def test_encrypted_groups_index_and_archived_group_restoration_across_restart(tmp_path, monkeypatch):
    import pytest
    from app import secure_storage
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    monkeypatch.setattr(secure_storage, 'CONFIG_FILE', tmp_path / 'local_state.json')
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda svc, key: keys.get(key))
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda svc, key, val: keys.__setitem__(key, val))
    store = secure_storage.SecureStorage

    # Save group history + metadata for g_left, plus an older local-only history g_orphan.
    assert store.save_message('alice', 'group_g_left', 'Saved group message', True, msg_id='m1')
    assert store.save_message('alice', 'group_g_orphan', 'Pre-existing group message', False, msg_id='m2')
    store.save_groups_index('alice', {
        'g_left': {'name': 'Left Group', 'created_by_device_id': 'dev_creator', 'archived': True},
        'g_active': {'name': 'Old Name', 'created_by_device_id': 'dev_creator', 'archived': False},
    })
    assert store.load_groups_index('alice')['g_left']['archived'] is True
    assert store.list_local_group_ids('alice') == ['g_left', 'g_orphan']

    # Corrupt index refuses overwrite; missing local key with existing groups.enc fails closed.
    groups_file = store._get_groups_file('alice')
    good_bytes = groups_file.read_bytes()
    groups_file.write_bytes(b'corrupted')
    with pytest.raises( Exception ):
        store.save_groups_index('alice', {})
    assert groups_file.read_bytes() == b'corrupted'
    groups_file.write_bytes(good_bytes)

    saved_local_key = keys.pop('alice_local_storage_key')
    with pytest.raises(ValueError):
        store._get_or_create_local_key('alice')
    keys['alice_local_storage_key'] = saved_local_key

    # Simulate client restart: _load_groups_from_storage restores cards, then _on_groups_fetched
    # activates g_active, archives g_left/g_orphan, clears groups_fetch_worker, and persists index.
    cards = {}
    state = SimpleNamespace(username='alice', server_url='https://node', device_id='dev', token='t',
                            current_chat_type=None, current_group_id=None, groups={'stale_other_user': {'name': 'Leak'}})
    env_main = {'state': state, 'storage': store, 'QMessageBox': SimpleNamespace(warning=lambda *a: None)}
    main_names = ['_persist_groups_index', '_load_groups_from_storage', 'force_remove_group']
    Main = type('Main', (), dict(zip(main_names, extract(main_names, env_main))))
    main = Main()
    main.groups_list = SimpleNamespace(clear=lambda: cards.clear())
    class Card:
        def __init__(self, name): self.name, self.tooltip = name, ''
        def setToolTip(self, t): self.tooltip = t
    main._add_group_card = lambda gid, name: cards.__setitem__(gid, Card(name))
    main._get_group_item = lambda gid: cards.get(gid)
    main._get_group_card = lambda gid: cards.get(gid)
    main.chat_title = SimpleNamespace(setText=lambda *_: None)

    main._load_groups_from_storage()
    assert 'stale_other_user' not in state.groups
    assert set(state.groups) == {'g_left', 'g_active', 'g_orphan'}
    assert state.groups['g_left']['archived'] is True
    assert state.groups['g_orphan']['name'] == 'Группа g_orphan'

    app_path = Path(__file__).resolve().parents[1] / 'app/windows/app_window.py'
    tree = ast.parse(app_path.read_text())
    node = next(n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'AppWindow'
                for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_on_groups_fetched')
    env_app = {'state': state}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(app_path), 'exec'), env_app)
    App = type('App', (), {'_on_groups_fetched': env_app['_on_groups_fetched']})
    window = App()
    window.main_screen = main
    worker = SimpleNamespace(account_context=('alice', 'https://node', 'dev', 't'), wait=lambda: None)
    window.groups_fetch_worker = worker
    window._on_groups_fetched(True, [{'id': 'g_active', 'name': 'Updated Name', 'created_by_device_id': 'dev_creator', 'members': ['dev']}], worker)

    assert window.groups_fetch_worker is None
    assert state.groups['g_active']['archived'] is False and state.groups['g_active']['name'] == 'Updated Name'
    assert state.groups['g_left']['archived'] is True and 'сохранена' in cards['g_left'].tooltip
    assert state.groups['g_orphan']['archived'] is True
    # Local history of archived groups remains completely intact and readable.
    assert [m['text'] for m in store.load_messages('alice', 'group_g_left')] == ['Saved group message']
    assert [m['text'] for m in store.load_messages('alice', 'group_g_orphan')] == ['Pre-existing group message']
    persisted = store.load_groups_index('alice')
    assert persisted['g_active']['archived'] is False and persisted['g_left']['archived'] is True


def test_open_group_tolerates_missing_display_name_and_sender_key_failure():
    path = Path(__file__).resolve().parents[1] / 'app/windows/main_screen.py'
    tree = ast.parse(path.read_text())
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'MainScreen'
             for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_on_group_selected']
    env = {
        'state': SimpleNamespace(current_chat_type=None, current_group_id=None,
                                 current_chat_username=None, current_chat_device_id=None,
                                 groups={'group-1': {'archived': False}}),
        'Qt': SimpleNamespace(UserRole=1),
        'GroupCardWidget': type('GroupCardWidget', (), {}),
        'GROUP_CHAT_SEND_ENABLED': True,
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), env)

    class Item:
        def data(self, _role): return 'group-1'
    card = env['GroupCardWidget']()
    card.reset_unread = lambda: None

    class Screen:
        _on_group_selected = env['_on_group_selected']
        def __init__(self):
            self.groups_list = SimpleNamespace(itemWidget=lambda _item: card)
            self.chat_title = SimpleNamespace(setText=lambda value: setattr(self, 'title', value))
            self.identity_status = SimpleNamespace(setVisible=lambda _value: None)
            self.call_btn = SimpleNamespace(setVisible=lambda _value: None)
            self.group_voice_btn = SimpleNamespace(setVisible=lambda _value: None)
            self.search_btn = SimpleNamespace(setVisible=lambda _value: None)
            self.chat_menu_btn = SimpleNamespace(setVisible=lambda _value: None)
            self.chat_area = object()
            self.right_stack = SimpleNamespace(setCurrentWidget=lambda _value: None)
            self.msg_input = SimpleNamespace(setEnabled=lambda _value: None,
                setPlaceholderText=lambda value: setattr(self, 'placeholder', value), setFocus=lambda: None)
            self.attach_btn = SimpleNamespace(setEnabled=lambda _value: None)
            self.mic_input_btn = SimpleNamespace(setEnabled=lambda _value: None)
            self.send_btn = SimpleNamespace(setEnabled=lambda _value: None)
            self._set_chat_header_icon = lambda _value: None
            self._fetch_group_voice_state = lambda _gid: None
            self._refresh_group_voice_bar = lambda: None
            self.ensure_my_group_sender_key = lambda _gid: (_ for _ in ()).throw(RuntimeError('key state'))
            self._render_history_page = lambda: setattr(self, 'rendered', True)
    screen = Screen()
    screen._on_group_selected(Item())
    assert env['state'].current_group_id == 'group-1'
    assert screen.title == 'Группа group-1'
    assert 'Группа group-1' in screen.placeholder
    assert screen.rendered


def test_group_sender_key_setup_rejects_corrupt_epoch_without_raising():
    path = Path(__file__).resolve().parents[1] / 'app/windows/main_screen.py'
    tree = ast.parse(path.read_text())
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'MainScreen'
             for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'ensure_my_group_sender_key']
    state = SimpleNamespace(token='token', device_id='self',
        groups={'g1': {'epoch': 'not-an-epoch', 'archived': False}})
    env = {'state': state}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), env)
    Screen = type('Screen', (), {'ensure_my_group_sender_key': env['ensure_my_group_sender_key']})
    assert Screen().ensure_my_group_sender_key('g1') is False
    state.groups['g1']['epoch'] = True
    assert Screen().ensure_my_group_sender_key('g1') is False


def test_restoring_group_keys_skips_corrupt_epochs_and_keeps_valid_group_key():
    path = Path(__file__).resolve().parents[1] / 'app/windows/main_screen.py'
    tree = ast.parse(path.read_text())
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'MainScreen'
             for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'restore_persisted_group_keys']
    state = SimpleNamespace(username='alice', groups={
        'good': {'epoch': 1, 'archived': False, 'sender_keys': {}},
        'bad': {'epoch': 1, 'archived': False, 'sender_keys': {}},
    })
    persisted = {
        'good': {
            'epoch': 2, 'distributed_epoch': 2, 'my_sender_key': {'epoch': 2},
            'sender_keys': {'peer': {'key_id': 'valid-key'}},
        },
        'bad': {'epoch': 'not-an-epoch', 'sender_keys': {}},
    }
    stored = []
    env = {
        'state': state,
        'storage': SimpleNamespace(load_group_keys=lambda _user: persisted),
        'store_member_sender_key': lambda target, device, key: stored.append((target, device, key)),
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), env)
    Screen = type('Screen', (), {'restore_persisted_group_keys': env['restore_persisted_group_keys']})
    Screen().restore_persisted_group_keys()
    assert state.groups['good']['epoch'] == 2
    assert state.groups['good']['my_sender_key'] == {'epoch': 2}
    assert state.groups['good']['distributed_epoch'] == 2
    assert stored and stored[0][1] == 'peer'
    assert state.groups['bad']['epoch'] == 1


def test_group_voice_roster_is_sanitized_before_ui_render():
    path = Path(__file__).resolve().parents[1] / 'app/windows/main_screen.py'
    tree = ast.parse(path.read_text())
    node = next(n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'MainScreen'
                for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_normalize_group_voice_roster')
    node.decorator_list = []
    env = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(path), 'exec'), env)
    normalize = env['_normalize_group_voice_roster']
    roster = normalize([
        None,
        {'device_id': '../bad', 'username': 'evil'},
        {'device_id': 'device_1', 'username': [], 'is_muted': 'false', 'public_key': 'key'},
        {'device_id': 'device_1', 'username': 'duplicate'},
        *[{'device_id': f'device-{n}', 'username': f'user{n}', 'public_key': 'key'} for n in range(1, 12)],
    ])
    assert len(roster) == 8
    assert roster[0]['device_id'] == 'device_1'
    assert roster[0]['username'] == 'device_1'
    assert roster[0]['is_muted'] is False
    assert len({entry['device_id'] for entry in roster}) == len(roster)
