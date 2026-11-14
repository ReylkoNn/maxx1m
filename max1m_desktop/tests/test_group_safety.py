import ast
import json
from pathlib import Path
from types import SimpleNamespace
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
