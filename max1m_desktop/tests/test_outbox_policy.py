import json
from types import SimpleNamespace
import pytest
from app.crypto_box import CryptoManager
from app.contact_keys import fingerprint_public_key
from app.outbox_policy import verify_queued_recipient, OutboxRecipientError
from app import outbox, secure_storage


@pytest.fixture
def peers(tmp_path, monkeypatch):
    alice, bob, other = CryptoManager(), CryptoManager(), CryptoManager()
    for peer in (alice, bob, other): peer.generate_new_keypair()
    pub = bob.get_public_key_b64()
    device = {"device_id": "bob-device", "public_key": pub,
              "verified_fingerprint": fingerprint_public_key(pub),
              "verified_scope": {"username": "alice", "device_id": "mine", "server_url": "https://node"}}
    state = SimpleNamespace(username="alice", device_id="mine", server_url="https://node/",
                            allies={"bob": {"devices": [device]}})
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    store = {}
    monkeypatch.setattr(secure_storage.keyring, "get_password", lambda svc, key: store.get(key))
    monkeypatch.setattr(secure_storage.keyring, "set_password", lambda svc, key, val: store.__setitem__(key, val))
    return state, alice, bob, other


def record(alice, peer, history=True):
    envelope = alice.encrypt_message(json.dumps({"type": "text", "text": "private", "msg_id": "id"}), peer.get_public_key_b64())
    return {"receiver_device_id": "bob-device", **envelope,
            **({"_local_history": {"ally_username": "bob", "text": "private", "msg_id": "id"}} if history else {})}


def test_original_and_legacy_records_retry_only_for_verified_real_recipient(peers):
    state, alice, bob, _ = peers
    for legacy in (False, True):
        message = record(alice, bob, history=not legacy)
        outbox.enqueue("alice", "https://node", "mine", message)
        path, loaded = outbox.next_message("alice", "https://node", "mine")
        assert verify_queued_recipient(state, alice, loaded).username == "bob"
        assert b"private" not in path.read_bytes()
        path.unlink()


def test_block_unverified_changed_and_misrouted_keys(peers):
    state, alice, bob, other = peers
    message = record(alice, bob)
    device = state.allies["bob"]["devices"][0]
    device.pop("verified_fingerprint")
    with pytest.raises(OutboxRecipientError): verify_queued_recipient(state, alice, message)
    device.update(public_key=other.get_public_key_b64(), verified_fingerprint=fingerprint_public_key(other.get_public_key_b64()))
    # A verified replacement is not the key used for the queued ciphertext.
    with pytest.raises(OutboxRecipientError): verify_queued_recipient(state, alice, message)
    assert verify_queued_recipient(state, alice, record(alice, other)).username == "bob"
    state.allies["mallory"] = {"devices": [device.copy()]}
    with pytest.raises(OutboxRecipientError): verify_queued_recipient(state, alice, message)


def test_block_forged_sender_wrong_history_and_missing_key(peers):
    state, alice, bob, other = peers
    message = record(alice, bob)
    with pytest.raises(OutboxRecipientError): verify_queued_recipient(state, other, message)
    message["_local_history"]["ally_username"] = "eve"
    with pytest.raises(OutboxRecipientError): verify_queued_recipient(state, alice, message)
    state.allies.clear()
    with pytest.raises(OutboxRecipientError): verify_queued_recipient(state, alice, record(alice, bob))


def test_block_modified_signature_and_unexpected_type(peers):
    state, alice, bob, _ = peers
    message = record(alice, bob)
    message["signature"] = alice.encrypt_message("different", bob.get_public_key_b64())["signature"]
    with pytest.raises(OutboxRecipientError): verify_queued_recipient(state, alice, message)
    bad = {"receiver_device_id": "bob-device", **alice.encrypt_message('{"type":"typing"}', bob.get_public_key_b64())}
    with pytest.raises(OutboxRecipientError): verify_queued_recipient(state, alice, bad)


def test_blocked_record_does_not_starve_verified_record(peers):
    import ast
    from pathlib import Path
    state, alice, bob, other = peers
    state.token = "token"
    state.allies["eve"] = {"devices": [{"device_id": "eve-device", "public_key": other.get_public_key_b64()}]}
    blocked = record(alice, other, history=False)
    blocked["receiver_device_id"] = "eve-device"
    mid1 = outbox.enqueue("alice", "https://node", "mine", blocked)
    mid2 = outbox.enqueue("alice", "https://node", "mine", record(alice, bob, history=False))
    source = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(source.read_text())
    nodes = [node for cls in tree.body if isinstance(cls, ast.ClassDef) for node in cls.body
             if isinstance(node, ast.FunctionDef) and node.name == "_try_outbox"]
    assert len(nodes) == 1
    started, warnings = [], []
    class Signal:
        def connect(self, *args): pass
    class Worker:
        def __init__(self, server, token, payload):
            self.payload, self.finished = payload, Signal()
        def start(self): started.append(self.payload)
        def isRunning(self): return False
    env = dict(state=state, crypto=alice, outbox=outbox,
               verify_queued_recipient=verify_queued_recipient, OutboxRecipientError=OutboxRecipientError,
               ReliableSendWorker=Worker, Qt=SimpleNamespace(QueuedConnection=1),
               QTimer=SimpleNamespace(singleShot=lambda *a: None),
               QMessageBox=SimpleNamespace(warning=lambda *args: warnings.append(args)))
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source), "exec"), env)
    class Screen:
        _try_outbox = env["_try_outbox"]
        _outbox_worker = None
        _outbox_management_active = False
        _outbox_identity_warning_shown = False
        _outbox_warning_shown = False
        def __init__(self): self._outbox_skipped = set()
        def _on_outbox_finished(self, *args): pass
    screen = Screen()
    screen._try_outbox()
    assert warnings and not started and len(screen._outbox_skipped) == 1
    screen._try_outbox()
    assert len(started) == 1 and started[0]["client_message_id"] == mid2
    assert len(outbox.pending_paths("alice", "https://node", "mine")) == 2
    assert mid1 != mid2


def test_cancel_only_snapshot_of_requested_account(peers, tmp_path):
    state, alice, bob, _ = peers
    mid1 = outbox.enqueue("alice", "https://node", "mine", record(alice, bob, False))
    snapshot = outbox.pending_paths("alice", "https://node", "mine")
    mid2 = outbox.enqueue("alice", "https://node", "mine", record(alice, bob, False))
    with pytest.raises(ValueError):
        outbox.discard_paths([tmp_path / "outside.enc"], "alice", "https://node", "mine")
    outbox.discard_paths(snapshot, "alice", "https://node", "mine")
    remaining = outbox.next_message("alice", "https://node", "mine")
    assert remaining[1]["client_message_id"] == mid2 and mid1 != mid2


def test_queue_cancel_rechecks_account_after_confirmation(peers):
    import ast
    from pathlib import Path
    state, alice, bob, _ = peers
    outbox.enqueue("alice", "https://node", "mine", record(alice, bob, False))
    source = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(source.read_text())
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) for n in cls.body
             if isinstance(n, ast.FunctionDef) and n.name == "_cancel_pending_outbox"]
    warnings = []
    def confirm(*args):
        state.username = "other-account"
        return 1
    env = dict(state=state, outbox=outbox, QMessageBox=SimpleNamespace(
        Yes=1, No=2, question=confirm, warning=lambda *a: warnings.append(a), information=lambda *a: None))
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source), "exec"), env)
    class Screen:
        _cancel_pending_outbox = env["_cancel_pending_outbox"]
        _outbox_worker = None
        _attachment_worker = None
        _outbox_management_active = False
        _outbox_skipped = set()
    screen = Screen()
    screen._cancel_pending_outbox()
    assert warnings and not screen._outbox_management_active
    assert len(outbox.pending_paths("alice", "https://node", "mine")) == 1


def test_attachment_job_must_match_signed_payload_and_history(peers):
    import uuid
    state,alice,bob,_=peers
    file_id=str(uuid.uuid4()); other_id=str(uuid.uuid4()); secret=alice.generate_file_key()
    message={'type':'image','file_id':file_id,'secret_key':secret,'msg_id':'m'}
    def envelope(content, history_id='m'):
        return {'receiver_device_id':'bob-device',**alice.encrypt_message(json.dumps(content),bob.get_public_key_b64()),
                '_local_history':{'ally_username':'bob','msg_id':history_id,'text':f"[IMAGE_META]|{file_id}|{secret}|"}}
    assert verify_queued_recipient(state,alice,envelope(message),attachment_file_id=file_id).username=='bob'
    for content, job_id, history_id in [
        (message, other_id, 'm'), ({**message,'type':'text'},file_id,'m'),
        ({**message,'secret_key':'bad'},file_id,'m'), (message,file_id,'wrong'),
        ({**message,'msg_id':''},file_id,''),
    ]:
        with pytest.raises(OutboxRecipientError):
            verify_queued_recipient(state,alice,envelope(content,history_id),attachment_file_id=job_id)


def test_queued_text_history_matches_signed_content_and_reply(peers):
    state,alice,bob,_=peers
    message={'type':'text','text':'private','msg_id':'id',
             'reply_to':{'msg_id':'prev','text':'quoted','sender':'bob'}}
    history={'ally_username':'bob','text':'private','msg_id':'id','timestamp':'time',
             'reply_to_msg_id':'prev','reply_to_text':'quoted','reply_to_sender':'bob'}
    envelope={'receiver_device_id':'bob-device',**alice.encrypt_message(json.dumps(message),bob.get_public_key_b64())}
    assert verify_queued_recipient(state,alice,{**envelope,'_local_history':history}).username=='bob'
    for change in ({'text':'wrong'}, {'msg_id':'other'}, {'timestamp':{}},
                   {'reply_to_msg_id':'different'}, {'reply_to_text':'changed'}, {'reply_to_sender':'eve'}):
        with pytest.raises(OutboxRecipientError):
            verify_queued_recipient(state,alice,{**envelope,'_local_history':{**history,**change}})
    # Old envelopes without local history remain sendable; an incompatible
    # record that *does* claim local history is retained instead of guessed.
    assert verify_queued_recipient(state,alice,envelope).username=='bob'
    missing_id={**message}; missing_id.pop('msg_id')
    old={**envelope,**alice.encrypt_message(json.dumps(missing_id),bob.get_public_key_b64()),'_local_history':history}
    with pytest.raises(OutboxRecipientError): verify_queued_recipient(state,alice,old)


@pytest.mark.parametrize('kind',['image','voice'])
def test_queued_attachment_history_matches_payload_and_metadata(peers,kind):
    import uuid
    state,alice,bob,_=peers; file_id=str(uuid.uuid4()); key=alice.generate_file_key()
    message={'type':kind,'msg_id':'id','file_id':file_id,'secret_key':key}
    if kind=='image':
        message['caption']='hello'; text=f'[IMAGE_META]|{file_id}|{key}|hello'
    else:
        message['duration']=1.25; text=f'[VOICE_META]|{file_id}|{key}|{1.25:.1f}'
    history={'ally_username':'bob','text':text,'msg_id':'id'}
    envelope={'receiver_device_id':'bob-device',**alice.encrypt_message(json.dumps(message),bob.get_public_key_b64()),
              '_local_history':history}
    assert verify_queued_recipient(state,alice,envelope).username=='bob'
    for bad_text in ('different',text+'x',text.replace(file_id,str(uuid.uuid4()))):
        with pytest.raises(OutboxRecipientError):
            verify_queued_recipient(state,alice,{**envelope,'_local_history':{**history,'text':bad_text}})


def test_mismatched_history_is_retained_and_skipped_before_any_write_or_network(peers):
    import ast
    from pathlib import Path
    state,alice,bob,_=peers; state.token='token'
    bad=record(alice,bob); bad['_local_history']['text']='not the signed text'
    good=record(alice,bob); good['_local_history']['msg_id']='id'
    first_id=outbox.enqueue('alice','https://node','mine',bad)
    second_id=outbox.enqueue('alice','https://node','mine',good)
    source=Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    tree=ast.parse(source.read_text()); nodes=[n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='MainScreen'
        for n in c.body if isinstance(n,ast.FunctionDef) and n.name=='_try_outbox']
    sent=[]
    class Signal:
        def connect(self,*a): pass
    class Worker:
        def __init__(self,server,token,payload): self.payload=payload; self.finished=Signal()
        def start(self): sent.append(self.payload)
        def isRunning(self): return False
    env={'state':state,'crypto':alice,'outbox':outbox,'verify_queued_recipient':verify_queued_recipient,
         'OutboxRecipientError':OutboxRecipientError,'ReliableSendWorker':Worker,
         'Qt':SimpleNamespace(QueuedConnection=0),'QTimer':SimpleNamespace(singleShot=lambda *a:None),
         'QMessageBox':SimpleNamespace(warning=lambda *a:None)}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(source),'exec'),env)
    class Screen:
        _try_outbox=env['_try_outbox']
        _outbox_worker=None; _outbox_management_active=False; _outbox_identity_warning_shown=False; _outbox_warning_shown=False
        def __init__(self): self._outbox_skipped=set()
        def _on_outbox_finished(self,*args): pass
    screen=Screen(); screen._try_outbox()
    assert not sent and secure_storage.SecureStorage.load_messages_strict('alice','bob')==[]
    assert len(screen._outbox_skipped)==1
    screen._try_outbox()
    assert len(sent)==1 and sent[0]['client_message_id']==second_id
    assert secure_storage.SecureStorage.load_messages_strict('alice','bob')[0]['text']=='private'
    assert len(outbox.pending_paths('alice','https://node','mine'))==2 and first_id!=second_id


def test_unknown_local_fields_rejected_before_history_or_attachment_upload(peers):
    state,alice,bob,_=peers
    queued=record(alice,bob)
    queued['_future_local_secret']='sensitive'
    with pytest.raises(OutboxRecipientError): verify_queued_recipient(state,alice,queued)
