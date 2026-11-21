import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from app import identity_setup, secure_storage
from app.crypto_box import CryptoManager


@pytest.fixture
def profile(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    monkeypatch.setattr(secure_storage, 'CONFIG_FILE', tmp_path / 'local_state.json')
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda svc, key: keys.get(key))
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda svc, key, value: keys.__setitem__(key, value))
    return tmp_path, keys


def test_existing_key_never_replaced_by_registration_or_new_device(profile):
    path, keys = profile
    old = CryptoManager(); old.generate_new_keypair()
    secure_storage.SecureStorage.save_private_key('alice', old.get_private_key_b64())
    replacement = CryptoManager(); replacement.generate_new_keypair()
    with pytest.raises(ValueError): secure_storage.SecureStorage.save_private_key('alice', replacement.get_private_key_b64())
    for purpose in ('register', 'device'):
        with pytest.raises(ValueError): identity_setup.prepare_new_identity('alice', 'https://server', purpose, replacement)
    assert keys['alice_privkey'] == old.get_private_key_b64()
    assert not list(path.rglob(identity_setup.PENDING_NAME))


def test_retry_uses_same_key_only_with_same_scope_and_purpose(profile):
    path, keys = profile
    first = CryptoManager()
    identity_setup.prepare_new_identity('alice', 'https://server/', 'device', first)
    saved_key, public = first.get_private_key_b64(), first.get_public_key_b64()
    marker = next(path.rglob(identity_setup.PENDING_NAME))
    assert saved_key not in marker.read_text()
    second = CryptoManager()
    identity_setup.prepare_new_identity('alice', 'https://server', 'device', second)
    assert second.get_private_key_b64() == saved_key and second.get_public_key_b64() == public
    with pytest.raises(ValueError): identity_setup.prepare_new_identity('alice', 'https://other', 'device', second)
    with pytest.raises(ValueError): identity_setup.prepare_new_identity('alice', 'https://server', 'register', second)
    assert keys['alice_privkey'] == saved_key and marker.exists()
    identity_setup.finish_identity('alice', 'https://server', 'device', second)
    assert not marker.exists()
    with pytest.raises(ValueError): identity_setup.prepare_new_identity('alice', 'https://server', 'device', second)


def test_missing_key_with_existing_profile_or_incomplete_marker_fails_closed(profile, monkeypatch):
    path, keys = profile
    history = secure_storage.SecureStorage._get_messages_file('alice', 'bob')
    history.write_bytes(b'preserve')
    crypto = CryptoManager()
    with pytest.raises(ValueError): identity_setup.prepare_new_identity('alice', 'https://server', 'register', crypto)
    assert history.read_bytes() == b'preserve' and not keys
    def fail(*args): raise OSError('keyring unavailable')
    monkeypatch.setattr(secure_storage.keyring, 'set_password', fail)
    with pytest.raises(OSError): identity_setup.prepare_new_identity('bob', 'https://server', 'register', crypto)
    marker = path / 'profiles' / 'bob' / identity_setup.PENDING_NAME
    assert marker.exists()
    with pytest.raises(ValueError): identity_setup.prepare_new_identity('bob', 'https://server', 'register', crypto)
    assert marker.exists() and not keys


def test_pending_identity_key_mismatch_never_overwrites(profile):
    path, keys = profile
    crypto = CryptoManager()
    identity_setup.prepare_new_identity('alice', 'https://server', 'register', crypto)
    other = CryptoManager(); other.generate_new_keypair()
    keys['alice_privkey'] = other.get_private_key_b64()  # simulated wrong keyring restore
    with pytest.raises(ValueError): identity_setup.prepare_new_identity('alice', 'https://server', 'register', crypto)
    assert keys['alice_privkey'] == other.get_private_key_b64()
    assert next(path.rglob(identity_setup.PENDING_NAME)).exists()


def test_profile_path_rejects_traversal(profile):
    for name in ('../other', '/tmp/outside', 'a/b', '..', 'a\\b', ''):
        with pytest.raises(ValueError): secure_storage.SecureStorage._get_user_dir(name)


def test_local_state_failure_preserves_previous_file(profile, monkeypatch):
    path, keys = profile
    store = secure_storage.SecureStorage
    store.save_local_state({'username': 'alice', 'device_id': 'old'})
    def fail(*args): raise OSError('disk failure')
    monkeypatch.setattr(secure_storage.os, 'replace', fail)
    with pytest.raises(OSError): store.save_local_state({'username': 'alice', 'device_id': 'new'})
    assert store.load_local_state() == {'username': 'alice', 'device_id': 'old'}
    assert sorted(p.name for p in path.iterdir()) == ['local_state.json']


def extract_methods(*names, env):
    source = Path(__file__).resolve().parents[1] / 'app/windows/app_window.py'
    tree = ast.parse(source.read_text())
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) for n in cls.body
             if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(nodes) == len(names)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source), 'exec'), env)
    return {name: env[name] for name in names}


def test_ui_stops_before_network_when_key_preparation_fails():
    calls = []
    def fail(*args): raise ValueError('old key')
    env = {'crypto': CryptoManager(), 'identity_setup': SimpleNamespace(prepare_new_identity=fail),
           'state': SimpleNamespace(device_id=None, username=None),
           'RegisterWorker': lambda **kw: calls.append('register'), 'LoginWorker': lambda **kw: calls.append('login')}
    methods = extract_methods('_start_registration', '_start_login', env=env)
    screen = SimpleNamespace(submit_button=SimpleNamespace(setEnabled=lambda value: calls.append(value)),
                             _set_status=lambda *args: calls.append(args))
    methods['_start_registration'](screen, 'server', 'alice', 'password', 'desktop', 'invite')
    methods['_start_login'](screen, 'server', 'alice', 'password', 'desktop')
    assert 'register' not in calls and 'login' not in calls and calls.count(True) == 2


def test_register_callback_uses_frozen_context_not_mutable_form():
    saved, finishes, logins, modes = [], [], [], []
    state = SimpleNamespace()
    env = {'state': state, 'storage': SimpleNamespace(save_local_state=lambda value: saved.append(value)),
           'crypto': object(), 'identity_setup': SimpleNamespace(finish_identity=lambda *args: finishes.append(args), current_identity_matches=lambda *args: True),
           'QTimer': SimpleNamespace(singleShot=lambda *args: None)}
    method = extract_methods('_on_register_finished', env=env)['_on_register_finished']
    worker = SimpleNamespace(auth_context=('https://one', 'alice', 'desktop', 'register', 'pub'),
                             _register_password='frozen-password')
    screen = SimpleNamespace(worker=worker,
                             username_block={'input': SimpleNamespace(text=lambda: 'mallory')},
                             submit_button=SimpleNamespace(setEnabled=lambda v: None),
                             loading_screen=SimpleNamespace(set_status=lambda *args: None),
                             stack=SimpleNamespace(setCurrentWidget=lambda w: (_ for _ in ()).throw(AssertionError('must login, not open unauthenticated screen'))),
                             main_screen=object(), _update_auth_animation_state=lambda: None,
                             _set_mode=lambda m: modes.append(m),
                             _start_login=lambda *args: logins.append(args))
    method(screen, True, {'device_id': 'id'})
    assert saved[0]['username'] == state.username == 'alice' and saved[0]['server_url'] == 'https://one'
    assert finishes[0][:3] == ('alice', 'https://one', 'register')
    assert modes == ['login']
    assert logins == [('https://one', 'alice', 'frozen-password', 'desktop')]
    assert worker._register_password is None


def test_register_without_login_handler_returns_to_auth_never_unauthenticated_main_screen():
    saved, widgets, statuses = [], [], []
    state = SimpleNamespace()
    env = {'state': state, 'storage': SimpleNamespace(save_local_state=lambda value: saved.append(value)),
           'crypto': object(), 'identity_setup': SimpleNamespace(finish_identity=lambda *args: None, current_identity_matches=lambda *args: True),
           'QTimer': SimpleNamespace(singleShot=lambda *args: None)}
    method = extract_methods('_on_register_finished', env=env)['_on_register_finished']
    auth_screen, main_screen = object(), object()
    screen = SimpleNamespace(worker=SimpleNamespace(auth_context=('https://one', 'alice', 'desktop', 'register', 'pub')),
                             submit_button=SimpleNamespace(setEnabled=lambda v: None),
                             loading_screen=SimpleNamespace(set_status=lambda *args: None),
                             auth_screen=auth_screen, main_screen=main_screen,
                             stack=SimpleNamespace(setCurrentWidget=lambda w: widgets.append(w)),
                             _update_auth_animation_state=lambda: None,
                             _set_status=lambda *args: statuses.append(args))
    method(screen, True, {'device_id': 'id'})
    assert widgets == [auth_screen] and main_screen not in widgets
    assert statuses and statuses[0][1] is False


def test_login_loads_groups_stops_previous_ws_and_flushes_outboxes():
    crypto = CryptoManager(); crypto.generate_new_keypair()
    events = []
    state = SimpleNamespace(device_name='desktop')
    class DummyWS:
        def __init__(self, server, token, device_id):
            self.new_message_received = self.group_message_received = object()
            self.group_created_received = self.group_invited_received = object()
            self.group_member_joined = self.group_member_left = self.group_deleted_received = object()
            self.webrtc_signal_received = self.call_offer_received = self.call_accept_received = self.call_ended_received = object()
            self.connection_status = SimpleNamespace(connect=lambda *a: None)
        def start(self): events.append('ws_started')
    class DummyGroupsWorker:
        def __init__(self, server, token):
            self.finished = SimpleNamespace(connect=lambda *a: None)
        def start(self): events.append('groups_fetch_started')
    import sys, types
    fake_workers = types.ModuleType('app.workers')
    fake_workers.FetchGroupsWorker = DummyGroupsWorker
    old_workers = sys.modules.get('app.workers')
    sys.modules['app.workers'] = fake_workers
    try:
        timers = []
        env = {'state': state, 'storage': SimpleNamespace(save_local_state=lambda value: events.append(('saved', value['device_id']))),
               'crypto': crypto,
               'identity_setup': SimpleNamespace(current_identity_matches=lambda *a: True, finish_identity=lambda *a: None),
               'WebSocketWorker': DummyWS,
               'Qt': SimpleNamespace(QueuedConnection=0),
               'QTimer': SimpleNamespace(singleShot=lambda delay, fn: timers.append((delay, fn)))}
        method = extract_methods('_on_login_finished', env=env)['_on_login_finished']
        old_ws = SimpleNamespace(stop=lambda: events.append('old_ws_stop'), wait=lambda ms: events.append(('old_ws_wait', ms)))
        main_screen = SimpleNamespace(
            _load_allies_from_storage=lambda: events.append('load_allies'),
            _load_groups_from_storage=lambda: events.append('load_groups'),
            _try_outbox=lambda: events.append('try_outbox'),
            _try_attachment_outbox=lambda: events.append('try_attachment_outbox'),
        )
        screen = SimpleNamespace(
            worker=SimpleNamespace(auth_context=('https://server', 'alice', 'desktop', None, 'dev1', crypto.get_public_key_b64())),
            ws_worker=old_ws, main_screen=main_screen,
            submit_button=SimpleNamespace(setEnabled=lambda v: None),
            loading_screen=SimpleNamespace(set_status=lambda *a: None),
            stack=SimpleNamespace(setCurrentWidget=lambda *a: None), auth_screen=object(),
            _connect_ws_event=lambda *a: None,
            _sync_timer=SimpleNamespace(start=lambda: events.append('sync_timer')),
            _start_message_sync=lambda: events.append('start_sync'),
            _update_auth_animation_state=lambda: None,
            _on_incoming_message=lambda *a: None,
            _on_incoming_group_message=lambda *a: None,
            _on_group_created_event=lambda *a: None,
            _on_group_invited_event=lambda *a: None,
            _on_group_member_joined=lambda *a: None,
            _on_group_member_left=lambda *a: None,
            _on_group_deleted_event=lambda *a: None,
            _on_webrtc_signal=lambda *a: None,
            _on_call_offer=lambda *a: None,
            _on_call_accepted=lambda *a: None,
            _on_call_ended=lambda *a: None,
            _on_ws_connection_status=lambda *a: None,
            _on_groups_fetched=lambda *a: None,
        )
        method(screen, True, {'access_token': 'jwt', 'device_id': 'dev1', 'device_public_key': crypto.get_public_key_b64()})
        for delay, fn in timers:
            if delay == 0:
                fn()
        assert 'load_allies' in events and 'load_groups' in events
        assert 'old_ws_stop' in events and 'ws_started' in events
        assert 'try_outbox' in events and 'try_attachment_outbox' in events
    finally:
        if old_workers is not None:
            sys.modules['app.workers'] = old_workers
        else:
            sys.modules.pop('app.workers', None)


def test_login_rejects_server_key_or_device_mismatch_before_saving():
    saved, statuses = [], []
    crypto = CryptoManager(); crypto.generate_new_keypair()
    state = SimpleNamespace(device_name='desktop')
    env = {'state': state, 'storage': SimpleNamespace(save_local_state=lambda value: saved.append(value)),
           'crypto': crypto, 'identity_setup': identity_setup}
    method = extract_methods('_on_login_finished', env=env)['_on_login_finished']
    screen = SimpleNamespace(worker=SimpleNamespace(auth_context=('https://server', 'alice', 'desktop', None, 'device', crypto.get_public_key_b64())),
                             submit_button=SimpleNamespace(setEnabled=lambda v: None),
                             stack=SimpleNamespace(setCurrentWidget=lambda *a: None), auth_screen=object(),
                             _update_auth_animation_state=lambda: None, _set_status=lambda *args: statuses.append(args))
    for answer in ({'access_token': 'token', 'device_id': 'device'},
                   {'access_token': 'token', 'device_id': 'device', 'device_public_key': 'wrong'},
                   {'access_token': 'token', 'device_id': 'other', 'device_public_key': crypto.get_public_key_b64()}):
        method(screen, True, answer)
    assert len(statuses) == 3 and not saved and not hasattr(state, 'token')


def test_identity_match_rechecks_keyring_before_accepting_server_result(profile):
    _, keys = profile
    first = CryptoManager()
    identity_setup.prepare_new_identity('alice', 'https://server', 'device', first)
    expected = first.get_public_key_b64()
    assert identity_setup.current_identity_matches('alice', first, expected)
    other = CryptoManager(); other.generate_new_keypair()
    keys['alice_privkey'] = other.get_private_key_b64()
    assert not identity_setup.current_identity_matches('alice', first, expected)
