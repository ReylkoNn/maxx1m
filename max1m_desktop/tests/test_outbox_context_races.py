"""Exercise the actual queue callbacks against session/key changes."""
import ast
from pathlib import Path
from types import SimpleNamespace
from app.outbox_policy import OutboxRecipientError
from app.recipient_context import RecipientContext


def method(name,env):
    path=Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    tree=ast.parse(path.read_text())
    nodes=[n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='MainScreen'
           for n in c.body if isinstance(n,ast.FunctionDef) and n.name==name]
    assert len(nodes)==1
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(path),'exec'),env)
    return env[name]

class Signal:
    def connect(self,*args): pass
class Worker:
    instances=[]
    def __init__(self,*args): self.args=args; self.finished=Signal(); self.started=False; self.instances.append(self)
    def start(self): self.started=True
    def isRunning(self): return self.started


def setup_message_queue(on_prepare,verify):
    state=SimpleNamespace(username='alice',server_url='https://node',device_id='mine',token='old')
    path=Path('/queue/item.enc'); record={'client_message_id':'id','_local_history':{'ally_username':'bob'}}
    class QueueRecordError(Exception): pass
    queue=SimpleNamespace(QueueRecordError=QueueRecordError,next_message=lambda *a:(path,record),
                          prepare_network_payload=lambda owner,rec:on_prepare(state,owner,rec))
    env={'state':state,'outbox':queue,'crypto':object(),'verify_queued_recipient':lambda *a:verify(state),
         'OutboxRecipientError':OutboxRecipientError,'ReliableSendWorker':Worker,
         'QMessageBox':SimpleNamespace(warning=lambda *a:None),
         'QTimer':SimpleNamespace(singleShot=lambda *a:None),'Qt':SimpleNamespace(QueuedConnection=1)}
    Screen=type('Screen',(),{'_try_outbox':method('_try_outbox',env)})
    screen=Screen(); screen._outbox_worker=None; screen._outbox_management_active=False
    screen._outbox_skipped=set(); screen._outbox_identity_warning_shown=False; screen._outbox_warning_shown=False
    Worker.instances=[]
    return screen,state,path


def test_message_queue_does_not_send_under_new_account_after_history_write():
    def prepare(state,owner,record): state.username='new'; state.token='new-token'; return {'client_message_id':'id'}
    screen,state,path=setup_message_queue(prepare,lambda state:'recipient')
    screen._try_outbox()
    assert not Worker.instances and screen._outbox_worker is None and not screen._outbox_skipped


def test_message_queue_rechecks_recipient_after_history_write():
    calls=[]
    def verify(state):
        calls.append(True)
        if len(calls)==2: raise OutboxRecipientError('changed')
        return 'old-recipient'
    screen,state,path=setup_message_queue(lambda *a:{'client_message_id':'id'},verify)
    screen._try_outbox()
    assert len(calls)==2 and not Worker.instances and path.name in screen._outbox_skipped


def test_message_queue_uses_captured_token_for_stable_session():
    calls=[]
    screen,state,path=setup_message_queue(lambda *a:{'client_message_id':'id'},lambda state:calls.append(True) or 'same')
    screen._try_outbox()
    assert len(calls)==2 and len(Worker.instances)==1 and Worker.instances[0].started
    assert Worker.instances[0].args[:2]==('https://node','old')


def setup_attachment_queue(on_prepare,verify):
    state=SimpleNamespace(username='alice',server_url='https://node',device_id='mine',token='old')
    context=RecipientContext('bob','their-device','key','alice','mine','https://node')
    job={'context':context.__dict__,'file_id':'file','payload':{'receiver_device_id':'their-device'},'history':{'ally_username':'bob'},'size':10,'sha256':'a'*64}
    path,blob=Path('/queue/item.job'),Path('/queue/item.blob')
    class QueueRecordError(Exception): pass
    outbox=SimpleNamespace(QueueRecordError=QueueRecordError,prepare_network_payload=lambda owner,rec:on_prepare(state,owner,rec))
    attachments=SimpleNamespace(next_job=lambda *a:(path,blob,job),validate_blob=lambda *a:None)
    env={'state':state,'outbox':outbox,'attachment_outbox':attachments,'RecipientContext':RecipientContext,
         'recipient_is_verified':lambda *args:True,'verify_queued_recipient':lambda *a,**kw:(verify(state,context), 'key') if kw.get('return_attachment_key') else verify(state,context),
         'crypto':object(),'ReliableUploadFileWorker':Worker,'time':SimpleNamespace(monotonic=lambda:1),
         'QMessageBox':SimpleNamespace(warning=lambda *a:None),
         'QTimer':SimpleNamespace(singleShot=lambda *a:None),'Qt':SimpleNamespace(QueuedConnection=1)}
    Screen=type('Screen',(),{'_try_attachment_outbox':method('_try_attachment_outbox',env)})
    screen=Screen(); screen._attachment_worker=None; screen._outbox_management_active=False
    screen._attachment_retry_after={}; screen._attachment_skipped=set(); screen._attachment_warning_shown=False; screen._net_workers=[]
    screen._on_queued_upload_finished=lambda *a:None; Worker.instances=[]
    return screen,state,path,context


def test_attachment_does_not_upload_if_account_changes_during_prepare():
    def prepare(state,*args): state.token='different'
    screen,state,path,context=setup_attachment_queue(prepare,lambda state,ctx:ctx)
    screen._try_attachment_outbox()
    assert not Worker.instances and screen._attachment_worker is None


def test_attachment_requires_matching_verified_envelope_before_upload():
    screen,state,path,context=setup_attachment_queue(lambda *a:None,lambda state,ctx:None)
    screen._try_attachment_outbox()
    assert not Worker.instances and path.name in screen._attachment_skipped


def test_attachment_rechecks_verified_recipient_and_pins_account():
    calls=[]
    def verify(state,context): calls.append(True); return context
    screen,state,path,context=setup_attachment_queue(lambda *a:None,verify)
    screen._try_attachment_outbox()
    assert len(calls)==2 and len(Worker.instances)==1 and Worker.instances[0].started
    assert Worker.instances[0].args[:2]==('https://node','old')
    assert Worker.instances[0].account_context==('alice','https://node','mine','old')


def test_real_crypto_attachment_is_verified_before_upload(tmp_path,monkeypatch):
    import json
    import time
    import uuid
    import nacl.secret
    from app import attachment_outbox, outbox, secure_storage
    from app.crypto_box import CryptoManager
    from app.contact_keys import fingerprint_public_key
    from app.outbox_policy import verify_queued_recipient
    from app.recipient_context import recipient_is_verified
    alice,bob,other=CryptoManager(),CryptoManager(),CryptoManager()
    for peer in (alice,bob,other): peer.generate_new_keypair()
    public=bob.get_public_key_b64()
    state=SimpleNamespace(username='alice',server_url='https://node',device_id='mine',token='token',
        allies={'bob':{'devices':[{'device_id':'bob-device','public_key':public,
          'verified_fingerprint':fingerprint_public_key(public),
          'verified_scope':{'username':'alice','device_id':'mine','server_url':'https://node'}}]}})
    keys={}
    monkeypatch.setattr(secure_storage,'BASE_DIR',tmp_path)
    monkeypatch.setattr(secure_storage.keyring,'get_password',lambda service,name:keys.get(name))
    monkeypatch.setattr(secure_storage.keyring,'set_password',lambda service,name,value:keys.__setitem__(name,value))
    context=RecipientContext('bob','bob-device',public,'alice','mine','https://node')
    file_id,message_id=str(uuid.uuid4()),str(uuid.uuid4())
    secret=alice.generate_file_key()
    plaintext=json.dumps({'type':'image','msg_id':'msg','file_id':file_id,'secret_key':secret,'caption':''})
    payload={'receiver_device_id':'bob-device',**alice.encrypt_message(plaintext,public)}
    history={'ally_username':'bob','text':f'[IMAGE_META]|{file_id}|{secret}|','msg_id':'msg'}
    path=attachment_outbox.enqueue(context,b'cipher-file',file_id,message_id,payload,history)
    env={'state':state,'outbox':outbox,'attachment_outbox':attachment_outbox,'RecipientContext':RecipientContext,
         'recipient_is_verified':recipient_is_verified,'verify_queued_recipient':verify_queued_recipient,
         'crypto':alice,'ReliableUploadFileWorker':Worker,'time':time,
         'QMessageBox':SimpleNamespace(warning=lambda *a:None),
         'QTimer':SimpleNamespace(singleShot=lambda *a:None),'Qt':SimpleNamespace(QueuedConnection=1)}
    Screen=type('Screen',(),{'_try_attachment_outbox':method('_try_attachment_outbox',env)})
    screen=Screen(); screen._attachment_worker=None; screen._outbox_management_active=False
    screen._attachment_retry_after={}; screen._attachment_skipped=set(); screen._attachment_warning_shown=False; screen._net_workers=[]
    screen._on_queued_upload_finished=lambda *a:None; Worker.instances=[]
    screen._try_attachment_outbox()
    assert len(Worker.instances)==1 and Worker.instances[0].started and path.exists()
    assert secure_storage.SecureStorage.load_messages_strict('alice','bob')[0]['msg_id']=='msg'
    box=nacl.secret.SecretBox(secure_storage.SecureStorage._get_or_create_local_key('alice'))
    job=json.loads(box.decrypt(path.read_bytes()))
    # Modified local metadata is rejected before upload, even if the encrypted message is valid.
    saved_history=job['history'].copy()
    job['history']['text']='incorrect local content'
    path.write_bytes(box.encrypt(json.dumps(job).encode()))
    screen._attachment_worker=None; screen._net_workers=[]; Worker.instances=[]
    screen._try_attachment_outbox()
    assert not Worker.instances and path.exists() and path.name in screen._attachment_skipped
    assert secure_storage.SecureStorage.load_messages_strict('alice','bob')[0]['text']==saved_history['text']
    screen._attachment_skipped.clear(); screen._attachment_retry_after.clear()
    job['history']=saved_history
    # A validly signed envelope pointing to another file must never upload this blob.
    mismatched=json.loads(plaintext); mismatched['file_id']=str(uuid.uuid4())
    job['payload']={'receiver_device_id':'bob-device',**alice.encrypt_message(json.dumps(mismatched),public)}
    path.write_bytes(box.encrypt(json.dumps(job).encode()))
    screen._attachment_worker=None; screen._net_workers=[]; Worker.instances=[]
    screen._try_attachment_outbox()
    assert not Worker.instances and path.exists() and path.name in screen._attachment_skipped
    # An otherwise signed payload encrypted to a different key never uploads or grants.
    screen._attachment_skipped.clear(); screen._attachment_retry_after.clear()
    job['payload']={'receiver_device_id':'bob-device',**alice.encrypt_message(plaintext,other.get_public_key_b64())}
    path.write_bytes(box.encrypt(json.dumps(job).encode()))
    screen._attachment_worker=None; screen._net_workers=[]; Worker.instances=[]
    screen._try_attachment_outbox()
    assert not Worker.instances and path.exists() and path.name in screen._attachment_skipped


def test_failed_local_history_does_not_starve_next_queued_message():
    timers=[]
    def prepare(*args): raise OSError('history unavailable')
    screen,state,path=setup_message_queue(prepare,lambda state:'recipient')
    method_env=screen._try_outbox.__func__.__globals__
    method_env['QTimer']=SimpleNamespace(singleShot=lambda delay,fn:timers.append(fn))
    screen._try_outbox()
    assert path.name in screen._outbox_skipped and len(timers)==1 and not Worker.instances
    queue=method_env['outbox']; second=Path('/queue/next.enc')
    queue.next_message=lambda *a: (second,{'client_message_id':'other'})
    queue.prepare_network_payload=lambda *a:{'client_message_id':'other'}
    screen._on_outbox_finished=lambda *a:None
    timers.pop()()
    assert len(Worker.instances)==1 and Worker.instances[0].started


def test_failed_attachment_preparation_schedules_next_job():
    timers=[]
    def prepare(*args): raise OSError('history unavailable')
    screen,state,path,context=setup_attachment_queue(prepare,lambda state,ctx:ctx)
    env=screen._try_attachment_outbox.__func__.__globals__
    env['QTimer']=SimpleNamespace(singleShot=lambda delay,fn:timers.append(fn))
    screen._try_attachment_outbox()
    assert path.name in screen._attachment_skipped and len(timers)==1 and not Worker.instances
    attachments=env['attachment_outbox']; second=Path('/queue/next.job')
    job={'context':context.__dict__,'file_id':'file','payload':{},'history':{},'size':10,'sha256':'a'*64}
    attachments.next_job=lambda *a:(second,Path('/queue/next.blob'),job)
    env['outbox'].prepare_network_payload=lambda *a:None
    timers.pop()()
    assert len(Worker.instances)==1 and Worker.instances[0].started
