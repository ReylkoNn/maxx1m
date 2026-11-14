import json
from types import SimpleNamespace
import pytest
from app import secure_storage
from app.contact_keys import fingerprint_public_key, newly_advertised_devices
from app.crypto_box import CryptoManager
from app.incoming_identity import IncomingIdentityError, verify_incoming
from app.delivery import process_delivery_page
from app.secure_storage import SecureStorage


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, "get_password", lambda service, name: keys.get(name))
    monkeypatch.setattr(secure_storage.keyring, "set_password", lambda service, name, value: keys.__setitem__(name, value))
    sender, receiver, other = CryptoManager(), CryptoManager(), CryptoManager()
    for peer in (sender, receiver, other): peer.generate_new_keypair()
    pub = sender.get_public_key_b64()
    device = {"device_id": "sender-device", "device_name": "Phone", "public_key": pub}
    state = SimpleNamespace(username="receiver", device_id="receiver-device", server_url="https://node",
                            allies={"sender": {"user_id": "sender-user", "devices": [device]}})
    payload = json.dumps({"type": "text", "text": "private", "msg_id": "msg-1"})
    envelope = {"id": "server-id", "sender_device_id": "sender-device",
                **sender.encrypt_message(payload, receiver.get_public_key_b64())}
    return state, sender, receiver, other, device, envelope


def trust(device):
    device["verified_fingerprint"] = fingerprint_public_key(device["public_key"])
    device["verified_scope"] = {"username": "receiver", "device_id": "receiver-device", "server_url": "https://node"}


def test_unverified_unknown_ambiguous_and_changed_key_are_not_accepted(setup):
    state, sender, receiver, other, device, envelope = setup
    with pytest.raises(IncomingIdentityError): verify_incoming(state, receiver, envelope)
    trust(device)
    context, plaintext = verify_incoming(state, receiver, envelope)
    assert context.username == "sender" and json.loads(plaintext)["text"] == "private"
    with pytest.raises(IncomingIdentityError):
        verify_incoming(state, receiver, {**envelope, "sender_device_id": "unknown"})
    state.allies["other"] = {"devices": [device.copy()]}
    with pytest.raises(IncomingIdentityError): verify_incoming(state, receiver, envelope)
    state.allies.pop("other")
    device["public_key"] = other.get_public_key_b64()
    with pytest.raises(IncomingIdentityError): verify_incoming(state, receiver, envelope)
    trust(device)  # Even a confirmed replacement does not validate an old sender's signature.
    with pytest.raises(IncomingIdentityError): verify_incoming(state, receiver, envelope)


def test_forgery_and_wrong_recipient_are_rejected(setup):
    state, sender, receiver, other, device, envelope = setup
    trust(device)
    with pytest.raises(IncomingIdentityError): verify_incoming(state, receiver, {**envelope, "signature": "bad"})
    with pytest.raises(IncomingIdentityError): verify_incoming(state, other, envelope)
    with pytest.raises(IncomingIdentityError): verify_incoming(state, receiver, [])


def test_durable_write_precedes_ack_and_failure_is_retried(setup, monkeypatch):
    state, sender, receiver, _, device, envelope = setup
    def process(item):
        try:
            context, plaintext = verify_incoming(state, receiver, item)
            payload = json.loads(plaintext)
            SecureStorage.save_message(state.username, context.username, payload["text"], False, msg_id=payload["msg_id"])
            return True
        except Exception:
            return False
    assert process_delivery_page([envelope], process)[0] == []  # Not verified.
    trust(device)
    original = SecureStorage._save_messages_to_file
    def fail(*args): raise OSError("storage unavailable")
    monkeypatch.setattr(SecureStorage, "_save_messages_to_file", fail)
    assert process_delivery_page([envelope], process)[0] == []
    assert SecureStorage.load_messages("receiver", "sender") == []
    monkeypatch.setattr(SecureStorage, "_save_messages_to_file", original)
    assert process_delivery_page([envelope], process)[0] == ["server-id"]
    assert process_delivery_page([envelope], process)[0] == ["server-id"]
    assert len(SecureStorage.load_messages("receiver", "sender")) == 1


def test_new_devices_are_candidates_never_implicitly_verified(setup):
    state, sender, _, other, device, _ = setup
    trust(device)
    existing = state.allies["sender"]
    new_device = {"device_id": "new", "public_key": other.get_public_key_b64(), "verified_fingerprint": "forged", "verified_scope": {"forged": True}}
    incoming = {"user_id": "sender-user", "devices": [dict(device), new_device]}
    candidates = newly_advertised_devices(existing, incoming, state.allies, "sender")
    assert len(candidates) == 1 and "verified_fingerprint" not in candidates[0] and "verified_scope" not in candidates[0]
    assert len(existing["devices"]) == 1
    with pytest.raises(ValueError):
        newly_advertised_devices(existing, {**incoming, "user_id": "changed"}, state.allies, "sender")
    with pytest.raises(ValueError):
        newly_advertised_devices(existing, {**incoming, "devices": [new_device]}, state.allies, "sender")
    with pytest.raises(ValueError):
        newly_advertised_devices(existing, {**incoming, "devices": [{**device, "public_key": other.get_public_key_b64()}]}, state.allies, "sender")
    state.allies["another"] = {"devices": [{**new_device}]}
    with pytest.raises(ValueError): newly_advertised_devices(existing, incoming, state.allies, "sender")


def extract_method(name, namespace):
    import ast
    from pathlib import Path
    tree = ast.parse((Path(__file__).resolve().parents[1] / "app/windows/main_screen.py").read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "MainScreen")
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), "main_screen.py", "exec"), namespace)
    return namespace[name]


def test_real_incoming_callback_only_acks_after_verification_and_storage(setup, monkeypatch):
    state, _, receiver, _, device, envelope = setup
    notifications, signals = [], []
    class Screen:
        _incoming_identity_notice_shown = False
        incoming_message_processed = SimpleNamespace(emit=lambda value: signals.append(value))
        def window(self): return SimpleNamespace(show_notification=lambda *args: notifications.append(args))
        def _handle_decrypted_payload(self, sender, plaintext, signature, is_sync, **kwargs):
            data = json.loads(plaintext)
            SecureStorage.save_message(state.username, sender, data["text"], False, msg_id=data["msg_id"])
            return True
    screen = Screen()
    screen.process_incoming_message = extract_method("process_incoming_message", {
        "state": state, "crypto": receiver, "verify_incoming": verify_incoming,
        "IncomingIdentityError": IncomingIdentityError,
    }).__get__(screen)
    process = lambda message: screen.process_incoming_message(message, is_sync=True)
    assert process_delivery_page([envelope], process)[0] == []
    assert process_delivery_page([envelope], process)[0] == []
    assert len(notifications) == 1 and not signals
    trust(device)
    original = SecureStorage._save_messages_to_file
    monkeypatch.setattr(SecureStorage, "_save_messages_to_file", lambda *args: (_ for _ in ()).throw(OSError()))
    assert process_delivery_page([envelope], process)[0] == []
    assert not signals
    monkeypatch.setattr(SecureStorage, "_save_messages_to_file", original)
    assert process_delivery_page([envelope], process)[0] == ["server-id"]
    assert len(signals) == 1


def test_server_and_local_device_scope_cannot_reuse_verification(setup):
    state, _, receiver, _, device, envelope = setup
    trust(device)
    verify_incoming(state, receiver, envelope)
    state.server_url = "https://other-server"
    with pytest.raises(IncomingIdentityError): verify_incoming(state, receiver, envelope)
    state.server_url = "https://node"
    state.device_id = "another-receiver-device"
    with pytest.raises(IncomingIdentityError): verify_incoming(state, receiver, envelope)


def test_peer_can_only_delete_their_own_messages(setup):
    SecureStorage.save_message("receiver", "sender", "theirs", False, msg_id="theirs")
    SecureStorage.save_message("receiver", "sender", "mine", True, msg_id="mine")
    assert not SecureStorage.delete_incoming_message("receiver", "sender", "mine")
    assert not SecureStorage.delete_incoming_message("receiver", "sender", "not-yet-delivered")
    assert SecureStorage.delete_incoming_message("receiver", "sender", "theirs")
    assert SecureStorage.delete_incoming_message("receiver", "sender", "theirs")
    messages = SecureStorage._load_all_messages("receiver", "sender")
    assert messages[0]["deleted"] and not messages[1]["deleted"]
    assert SecureStorage.mark_messages_as_read("receiver", "sender", ["theirs", "mine"], only_mine=True)
    messages = SecureStorage._load_all_messages("receiver", "sender")
    assert not messages[0]["is_read"] and messages[1]["is_read"]


def test_search_callback_rechecks_after_user_confirmation_and_saves_before_publish(setup):
    from app.contact_keys import device_key_map
    state, _, _, other, device, _ = setup
    state.token = "token"
    worker = SimpleNamespace(account_context=(state.username, state.server_url, state.device_id, state.token), requested_username="sender")
    fresh = {"device_id": "phone2", "public_key": other.get_public_key_b64(), "verified_fingerprint": "fake", "verified_scope": {"fake": 1}}
    data = {"username": "sender", "user_id": "sender-user", "devices": [dict(device), fresh]}
    class Widget:
        def setEnabled(self, *args): pass
        def setVisible(self, *args): pass
        def setText(self, *args): pass
    class Box:
        Yes, No = 1, 0
        on_question = staticmethod(lambda: None)
        @staticmethod
        def question(*args):
            Box.on_question()
            return Box.Yes
        @staticmethod
        def warning(*args): pass
    saved = []
    def save(name, allies):
        assert len(state.allies["sender"]["devices"]) == 1
        saved.append(allies)
    store = SimpleNamespace(save_allies=save)
    screen = SimpleNamespace(find_worker=worker, add_ally_btn=Widget(), ally_input=Widget(), search_status=Widget(), _update_contact_identity_status=lambda: None)
    callback = extract_method("_on_search_finished", {"state": state, "storage": store, "device_key_map": device_key_map,
                                                     "newly_advertised_devices": newly_advertised_devices, "QMessageBox": Box})
    Box.on_question = staticmethod(lambda: setattr(state, "token", "different"))
    callback(screen, True, data, worker)
    assert not saved and len(state.allies["sender"]["devices"]) == 1
    state.token = "token"
    Box.on_question = staticmethod(lambda: None)
    store.save_allies = lambda *args: (_ for _ in ()).throw(OSError())
    callback(screen, True, data, worker)
    assert len(state.allies["sender"]["devices"]) == 1
    store.save_allies = save
    callback(screen, True, data, worker)
    assert len(saved) == 1
    added = state.allies["sender"]["devices"][1]
    assert "verified_fingerprint" not in added and "verified_scope" not in added


def test_oversized_envelope_is_rejected_before_crypto(setup):
    state, sender, receiver, other, device, envelope = setup
    trust(device)
    class NeverCrypto:
        def verify_signature(self, *args): raise AssertionError('Must not verify oversized envelope')
    for data in ({**envelope, 'sender_device_id': 'x'*65},
                 {**envelope, 'encrypted_blob': 'x'*(1024*1024+1)},
                 {**envelope, 'signature': 'x'*513}):
        with pytest.raises(IncomingIdentityError):
            verify_incoming(state, NeverCrypto(), data)


def test_row_adapter_with_real_incoming_delivery_preserves_ack_order(setup, tmp_path, monkeypatch):
    import ast
    from pathlib import Path
    from app.history_store import EncryptedHistory
    from app.experimental_history_adapter import ExperimentalHistoryAdapter
    state, sender, receiver, _, device, envelope = setup
    trust(device)
    state.current_chat_username = None
    row_store = EncryptedHistory.create(tmp_path/'incoming.sqlite3', b'k'*32, 'receiver', 'sender')
    adapter = ExperimentalHistoryAdapter(row_store)
    path = Path(__file__).resolve().parents[1] / 'app/windows/main_screen.py'
    tree = ast.parse(path.read_text())
    wanted = {'_handle_decrypted_payload', 'process_incoming_message'}
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'MainScreen'
             for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    env = {'json':json, 'state':state, 'storage':adapter, 'crypto':receiver,
           'verify_incoming':verify_incoming, 'IncomingIdentityError':IncomingIdentityError}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), env)
    class Screen:
        _incoming_identity_notice_shown = False
        incoming_message_processed = SimpleNamespace(emit=lambda data: None)
        def window(self): return SimpleNamespace(isActiveWindow=lambda: True)
        def _get_ally_card(self, username): return None
        def _get_ally_item(self, username): return None
    Screen._handle_decrypted_payload = env['_handle_decrypted_payload']
    Screen.process_incoming_message = env['process_incoming_message']
    screen = Screen()
    process = lambda item: screen.process_incoming_message(item, is_sync=True)
    assert process_delivery_page([envelope], process)[0] == ['server-id']
    assert process_delivery_page([envelope], process)[0] == ['server-id']
    assert adapter.load_history_page('receiver', 'sender').messages[0]['text'] == 'private'
    conflict = {**envelope, **sender.encrypt_message(json.dumps({'type':'text', 'text':'different', 'msg_id':'msg-1'}), receiver.get_public_key_b64())}
    assert process_delivery_page([conflict], process)[0] == []
    assert adapter.load_history_page('receiver', 'sender').messages[0]['text'] == 'private'
    failing = {**envelope, 'id':'server-id-2', **sender.encrypt_message(json.dumps({'type':'text', 'text':'new', 'msg_id':'msg-2'}), receiver.get_public_key_b64())}
    original = row_store._encrypt
    monkeypatch.setattr(row_store, '_encrypt', lambda *args, **kwargs: (_ for _ in ()).throw(OSError('disk error')))
    assert process_delivery_page([failing], process)[0] == []
    assert adapter.load_history_page('receiver', 'sender').total == 1
    monkeypatch.setattr(row_store, '_encrypt', original)
    assert process_delivery_page([failing], process)[0] == ['server-id-2']
    assert adapter.load_history_page('receiver', 'sender').total == 2


def test_account_change_during_decryption_never_processes_or_acknowledges(setup, monkeypatch):
    state,sender,receiver,other,device,envelope=setup
    trust(device); state.token='session'; calls=[]; signals=[]
    decrypt=receiver.decrypt_message
    def changing_decrypt(*args):
        plaintext=decrypt(*args)
        state.username='new-account'; state.token='new-session'
        return plaintext
    monkeypatch.setattr(receiver,'decrypt_message',changing_decrypt)
    class Screen:
        _incoming_identity_notice_shown=False
        incoming_message_processed=SimpleNamespace(emit=lambda data:signals.append(data))
        def _handle_decrypted_payload(self,*args,**kwargs): calls.append(args); return True
        def window(self): return SimpleNamespace()
    screen=Screen()
    screen.process_incoming_message=extract_method('process_incoming_message',
        {'state':state,'crypto':receiver,'verify_incoming':verify_incoming,
         'IncomingIdentityError':IncomingIdentityError}).__get__(screen)
    assert not screen.process_incoming_message(envelope,True)
    assert not calls and not signals


def test_changed_recipient_key_during_decrypt_blocks_processing(setup, monkeypatch):
    state,sender,receiver,other,device,envelope=setup
    trust(device); state.token='session'; calls=[]
    decrypt=receiver.decrypt_message
    def change_key(*args):
        plaintext=decrypt(*args)
        device['public_key']=other.get_public_key_b64()
        return plaintext
    monkeypatch.setattr(receiver,'decrypt_message',change_key)
    class Screen:
        _incoming_identity_notice_shown=False
        incoming_message_processed=SimpleNamespace(emit=lambda data:pytest.fail('must not ack'))
        def _handle_decrypted_payload(self,*args,**kwargs): calls.append(args); return True
        def window(self): return SimpleNamespace()
    screen=Screen()
    screen.process_incoming_message=extract_method('process_incoming_message',
        {'state':state,'crypto':receiver,'verify_incoming':verify_incoming,
         'IncomingIdentityError':IncomingIdentityError}).__get__(screen)
    assert not screen.process_incoming_message(envelope,True) and not calls


def test_changed_session_during_processing_does_not_emit_delivery_success(setup):
    state,sender,receiver,other,device,envelope=setup
    trust(device); state.token='session'; signals=[]; calls=[]
    class Screen:
        _incoming_identity_notice_shown=False
        incoming_message_processed=SimpleNamespace(emit=lambda data:signals.append(data))
        def _handle_decrypted_payload(self,*args,**kwargs):
            calls.append('processed'); state.token='new-session'; return True
        def window(self): return SimpleNamespace()
    screen=Screen()
    screen.process_incoming_message=extract_method('process_incoming_message',
        {'state':state,'crypto':receiver,'verify_incoming':verify_incoming,
         'IncomingIdentityError':IncomingIdentityError}).__get__(screen)
    assert not screen.process_incoming_message(envelope,True)
    assert calls==['processed'] and not signals


def test_session_change_during_storage_prevents_read_receipt_and_ui_update():
    from types import SimpleNamespace
    state=SimpleNamespace(username='receiver',server_url='https://node',device_id='mine',token='old',current_chat_username='sender')
    sends=[]; saved=[]
    def save(*args,**kwargs):
        saved.append((args,kwargs)); state.token='new'; return True
    env={'state':state,'storage':SimpleNamespace(save_message=save),'json':json}
    method=extract_method('_handle_decrypted_payload',env)
    class Screen:
        _handle_decrypted_payload=method
        _history_available=True; _history_offset=0; _history_query=None
        def __init__(self):
            self.chat_area=object(); self.right_stack=SimpleNamespace(currentWidget=lambda:self.chat_area)
        def window(self): return SimpleNamespace(isActiveWindow=lambda:True)
        def isVisible(self): return True
        def _send_system_payload(self,*a,**kw): sends.append((a,kw))
        def _get_ally_card(self,*a): pytest.fail('stale context touched UI')
    screen=Screen()
    assert not screen._handle_decrypted_payload('sender',json.dumps({'type':'text','text':'hi','msg_id':'m'}),
                    'sig',session_guard=lambda:state.token=='old')
    assert saved[0][0][0]=='receiver' and not sends


def test_live_receipt_targets_actual_verified_sender_device(monkeypatch):
    from app.recipient_context import RecipientContext
    from app.outbox_policy import OutboxRecipientError
    owner,sender,other=CryptoManager(),CryptoManager(),CryptoManager()
    for peer in (owner,sender,other): peer.generate_new_keypair()
    pub=sender.get_public_key_b64()
    state=SimpleNamespace(username='alice',device_id='mine',server_url='https://node',token='token',
        allies={'bob':{'devices':[{'device_id':'sender-device','public_key':pub,
                 'verified_fingerprint':fingerprint_public_key(pub),
                 'verified_scope':{'username':'alice','device_id':'mine','server_url':'https://node'}},
                 {'device_id':'other-device','public_key':other.get_public_key_b64()}]}})
    context=RecipientContext('bob','sender-device',pub,'alice','mine','https://node')
    from app.recipient_context import recipient_is_verified
    workers=[]
    class Signal:
        def connect(self,*args): pass
    class Worker:
        def __init__(self,server,token,payload): self.server=server; self.token=token; self.payload=payload; self.finished=Signal(); workers.append(self)
        def start(self): pass
    env={'state':state,'crypto':owner,'json':json,'recipient_is_verified':recipient_is_verified,'SendMessageWorker':Worker,
         'QMessageBox':SimpleNamespace(warning=lambda *a:None),'Qt':SimpleNamespace(QueuedConnection=0)}
    method=extract_method('_send_system_payload',env)
    class Screen:
        _send_system_payload=method
        def __init__(self): self._net_workers=[]
        def _on_send_finished(self,*a): pass
    screen=Screen(); account=('alice','https://node','mine','token')
    assert screen._send_system_payload('bob',{'type':'read_ack','msg_ids':['m']},context=context,account_context=account)
    assert len(workers)==1 and workers[0].payload['receiver_device_id']=='sender-device'
    plaintext=sender.decrypt_message(workers[0].payload['encrypted_blob'],owner.get_public_key_b64())
    assert json.loads(plaintext)=={'type':'read_ack','msg_ids':['m']}
    with pytest.raises(Exception): other.decrypt_message(workers[0].payload['encrypted_blob'],owner.get_public_key_b64())
    encrypt=owner.encrypt_message
    def change_session(*args):
        encrypted=encrypt(*args); state.token='new-token'; return encrypted
    monkeypatch.setattr(owner,'encrypt_message',change_session)
    assert not screen._send_system_payload('bob',{'type':'read_ack','msg_ids':['m']},context=context,account_context=account)
    assert len(workers)==1
    state.token='token'
    def change_owner_key(*args):
        encrypted=encrypt(*args); owner.generate_new_keypair(); return encrypted
    monkeypatch.setattr(owner,'encrypt_message',change_owner_key)
    assert not screen._send_system_payload('bob',{'type':'read_ack','msg_ids':['m']},context=context,account_context=account)
    assert len(workers)==1


def test_real_verified_delivery_legacy_conflicting_id_is_not_acked(setup):
    import ast
    from pathlib import Path
    state,sender,receiver,_,device,envelope=setup; trust(device); state.current_chat_username=None
    path=Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    tree=ast.parse(path.read_text()); names={'_handle_decrypted_payload','process_incoming_message'}
    nodes=[n for cls in tree.body if isinstance(cls,ast.ClassDef) and cls.name=='MainScreen'
           for n in cls.body if isinstance(n,ast.FunctionDef) and n.name in names]
    env={'json':json,'state':state,'storage':SecureStorage,'crypto':receiver,
         'verify_incoming':verify_incoming,'IncomingIdentityError':IncomingIdentityError}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(path),'exec'),env)
    class Screen:
        _incoming_identity_notice_shown=False
        incoming_message_processed=SimpleNamespace(emit=lambda data:None)
        def window(self): return SimpleNamespace(isActiveWindow=lambda:True)
        def _get_ally_card(self,*args): return None
        def _get_ally_item(self,*args): return None
    Screen._handle_decrypted_payload=env['_handle_decrypted_payload']; Screen.process_incoming_message=env['process_incoming_message']
    screen=Screen(); process=lambda msg:screen.process_incoming_message(msg,is_sync=True)
    assert process_delivery_page([envelope],process)[0]==['server-id']
    assert process_delivery_page([envelope],process)[0]==['server-id']
    conflicting={**envelope,'id':'server-id-2',**sender.encrypt_message(
        json.dumps({'type':'text','text':'different','msg_id':'msg-1'}),receiver.get_public_key_b64())}
    assert process_delivery_page([conflicting],process)[0]==[]
    assert SecureStorage.load_messages_strict('receiver','sender')[0]['text']=='private'
    assert SecureStorage.delete_message('receiver','sender','msg-1')
    assert process_delivery_page([envelope],process)[0]==['server-id']
    assert process_delivery_page([conflicting],process)[0]==[]


@pytest.mark.parametrize('payload', [
    [], {'type':'text','text':[],'msg_id':'m'}, {'type':'text','text':{},'msg_id':'m'},
    {'type':'image','caption':[],'msg_id':'m'}, {'type':'voice','reply_to':['bad'],'msg_id':'m'},
    {'type':'text','text':'ok','reply_to':{'text':[]},'msg_id':'m'},
    {'type':'text','text':'ok','reply_to':{'msg_id':'x'*257},'msg_id':'m'},
    {'type':'text','text':'ok','msg_id':'x'*257}, {'type':'delete_msg','msg_id':'x'*257},
])
def test_malformed_decrypted_payload_is_not_persisted(payload):
    env={'json':json,'state':SimpleNamespace(username='receiver',current_chat_username=None),
         'storage':SimpleNamespace(save_message=lambda *a,**kw:pytest.fail('invalid message persisted'),
                                   delete_incoming_message=lambda *a,**kw:pytest.fail('invalid deletion applied'))}
    method=extract_method('_handle_decrypted_payload',env)
    screen=SimpleNamespace(window=lambda:SimpleNamespace(isActiveWindow=lambda:True))
    assert method(screen,'sender',json.dumps(payload),'sig') is False


def test_transient_messages_use_selected_verified_device_and_recheck_session(monkeypatch):
    from app.recipient_context import capture_recipient, recipient_is_verified
    owner,selected,other=CryptoManager(),CryptoManager(),CryptoManager()
    for peer in (owner,selected,other): peer.generate_new_keypair()
    key=selected.get_public_key_b64()
    device={'device_id':'chosen','public_key':key,'verified_fingerprint':fingerprint_public_key(key),
            'verified_scope':{'username':'alice','device_id':'mine','server_url':'https://node'}}
    state=SimpleNamespace(username='alice',server_url='https://node',device_id='mine',token='token',
         current_chat_type='ally',current_chat_username='bob',current_chat_device_id='chosen',
         allies={'bob':{'devices':[device,{'device_id':'other','public_key':other.get_public_key_b64()}]}})
    workers=[]
    class Signal:
        def connect(self,*args): pass
    class Worker:
        def __init__(self,server,token,payload): self.args=(server,token,payload); self.finished=Signal(); workers.append(self)
        def start(self): pass
    env={'state':state,'crypto':owner,'json':json,'capture_recipient':capture_recipient,
         'recipient_is_verified':recipient_is_verified,'SendMessageWorker':Worker,
         'QMessageBox':SimpleNamespace(warning=lambda *a:None),'Qt':SimpleNamespace(QueuedConnection=0)}
    method=extract_method('_send_system_payload',env)
    class Screen:
        _send_system_payload=method
        def __init__(self): self._net_workers=[]
        def _on_send_finished(self,*args): pass
    screen=Screen()
    assert screen._send_system_payload('bob',{'type':'typing'})
    assert workers[0].args[2]['receiver_device_id']=='chosen'
    assert json.loads(selected.decrypt_message(workers[0].args[2]['encrypted_blob'],owner.get_public_key_b64()))=={'type':'typing'}
    state.current_chat_device_id='other'
    assert not screen._send_system_payload('bob',{'type':'read_ack','msg_ids':['m']}) and len(workers)==1
    state.current_chat_device_id='chosen'
    encrypt=owner.encrypt_message
    def replace_token(*args):
        result=encrypt(*args); state.token='changed'; return result
    monkeypatch.setattr(owner,'encrypt_message',replace_token)
    assert not screen._send_system_payload('bob',{'type':'typing'}) and len(workers)==1
    state.token='token'
    def remove_trust(*args):
        result=encrypt(*args); device.pop('verified_fingerprint'); return result
    monkeypatch.setattr(owner,'encrypt_message',remove_trust)
    assert not screen._send_system_payload('bob',{'type':'typing'}) and len(workers)==1


def test_system_worker_limit_and_start_failure_cleanup():
    from app.recipient_context import capture_recipient, recipient_is_verified
    owner,peer=CryptoManager(),CryptoManager(); owner.generate_new_keypair(); peer.generate_new_keypair()
    pub=peer.get_public_key_b64()
    state=SimpleNamespace(username='a',server_url='https://node',device_id='mine',token='t',
        current_chat_type='ally',current_chat_username='bob',current_chat_device_id='p',
        allies={'bob':{'devices':[{'device_id':'p','public_key':pub,'verified_fingerprint':fingerprint_public_key(pub),
                    'verified_scope':{'username':'a','device_id':'mine','server_url':'https://node'}}]}})
    class Signal:
        def connect(self,*args): pass
    class Worker:
        def __init__(self,*args): self.finished=Signal()
        def start(self): raise RuntimeError('failed')
    env={'state':state,'crypto':owner,'json':json,'capture_recipient':capture_recipient,
         'recipient_is_verified':recipient_is_verified,'SendMessageWorker':Worker,
         'QMessageBox':SimpleNamespace(warning=lambda *a:None),'Qt':SimpleNamespace(QueuedConnection=0)}
    method=extract_method('_send_system_payload',env)
    class Screen:
        _send_system_payload=method
        def __init__(self): self._net_workers=[]
        def _on_send_finished(self,*a): pass
    screen=Screen()
    assert not screen._send_system_payload('bob',{'type':'typing'}) and screen._net_workers==[]
    screen._net_workers=[Worker() for _ in range(16)]
    assert not screen._send_system_payload('bob',{'type':'typing'}) and len(screen._net_workers)==16


def test_durable_send_aborts_before_queue_if_session_changes_while_encrypting(monkeypatch):
    from app.recipient_context import capture_recipient, recipient_is_verified
    owner,peer=CryptoManager(),CryptoManager(); owner.generate_new_keypair(); peer.generate_new_keypair()
    pub=peer.get_public_key_b64(); scope={'username':'a','device_id':'mine','server_url':'https://node'}
    state=SimpleNamespace(username='a',server_url='https://node',device_id='mine',token='old',
        current_chat_type='ally',current_chat_username='bob',current_chat_device_id='p',
        allies={'bob':{'devices':[{'device_id':'p','public_key':pub,
          'verified_fingerprint':fingerprint_public_key(pub),'verified_scope':scope}]}})
    enqueued=[]; encrypt=owner.encrypt_message
    def change_token(*args):
        value=encrypt(*args); state.token='new'; return value
    monkeypatch.setattr(owner,'encrypt_message',change_token)
    env={'state':state,'crypto':owner,'json':json,'capture_recipient':capture_recipient,
         'recipient_is_verified':recipient_is_verified,'outbox':SimpleNamespace(enqueue=lambda *a,**kw:enqueued.append(a)),
         'QMessageBox':SimpleNamespace(warning=lambda *a:None),'SendMessageWorker':type('Worker',(),{})}
    method=extract_method('_send_system_payload',env)
    class Screen:
        _send_system_payload=method
        def _try_outbox(self): pytest.fail('stale queue must not start')
    assert not Screen()._send_system_payload('bob',{'type':'text','text':'hello'})
    assert not enqueued
