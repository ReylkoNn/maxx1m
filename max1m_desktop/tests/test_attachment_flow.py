"""Exercise the real callbacks without native Qt GUI dependencies."""
import ast
from pathlib import Path
from types import SimpleNamespace
from app.recipient_context import capture_recipient, recipient_still_trusted


def test_grant_before_message_and_contact_change():
    source = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(source.read_text())
    names = {"_on_queued_upload_finished", "_on_queued_grant_finished"}
    methods = [node for cls in tree.body if isinstance(cls, ast.ClassDef) for node in cls.body
               if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(methods) == len(names)
    state = SimpleNamespace(username="alice", device_id="mine", server_url="https://node", token="token",
                            current_chat_type="ally", current_chat_username="bob", current_chat_device_id="b",
                            allies={"bob": {"devices": [{"device_id": "b", "public_key": "key"}]}})
    ctx = capture_recipient(state)
    enqueued, finished, grants, failures = [], [], [], []
    class Signal:
        def connect(self, cb, *_): self.cb = cb
    class Worker:
        def __init__(self, *args):
            self.args, self.finished = args, Signal()
            grants.append(self)
        def start(self): pass
        def wait(self): pass
    env = dict(state=state, recipient_is_verified=recipient_still_trusted, GrantFileAccessWorker=Worker,
               Qt=SimpleNamespace(QueuedConnection=1), QTimer=SimpleNamespace(singleShot=lambda *a: None),
               outbox=SimpleNamespace(enqueue=lambda *a, **kw: enqueued.append((a, kw))),
               attachment_outbox=SimpleNamespace(finish=lambda *a: finished.append(a)))
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])), str(source), "exec"), env)
    class Screen:
        _on_queued_upload_finished = env["_on_queued_upload_finished"]
        _on_queued_grant_finished = env["_on_queued_grant_finished"]
        def __init__(self): self._net_workers, self._attachment_skipped = [], set(); self._attachment_worker = None
        def _attachment_failure(self, item, detail): failures.append(detail)
        def _try_outbox(self): pass
        def _try_attachment_outbox(self): pass
    screen = Screen()
    job = {"file_id": "file", "message_id": "message", "payload": {"receiver_device_id": "b"}, "history": {}}
    item = (Path("job"), Path("blob"), job)
    upload = Worker()
    upload.queue_item, upload.recipient_context = item, ctx
    upload.account_context = (state.username, state.server_url, state.device_id, state.token)
    screen._attachment_worker=upload
    screen._on_queued_upload_finished(False, {}, upload)
    assert failures and not enqueued and len(grants) == 1
    screen._attachment_worker=upload
    screen._on_queued_upload_finished(True, {}, upload)
    grant = grants[-1]
    assert grant.args[-1] == "b" and grant in screen._net_workers
    grant.finished.cb(False, {})
    assert not enqueued and not finished
    screen._attachment_worker=upload
    screen._on_queued_upload_finished(True, {}, upload)
    state.current_chat_username, state.current_chat_device_id = "eve", "e"
    grants[-1].finished.cb(True, {})
    assert enqueued[0][0][3]["receiver_device_id"] == "b"
    assert enqueued[0][1]["message_id"] == "message" and finished
    screen._attachment_worker=upload
    screen._on_queued_upload_finished(True, {}, upload)
    state.allies["bob"]["devices"][0]["public_key"] = "changed"
    grants[-1].finished.cb(True, {})
    assert len(enqueued) == 1


def test_old_token_never_continues_upload_or_grant():
    source=Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    tree=ast.parse(source.read_text()); names={'_on_queued_upload_finished','_on_queued_grant_finished'}
    methods=[n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='MainScreen'
             for n in c.body if isinstance(n,ast.FunctionDef) and n.name in names]
    state=SimpleNamespace(username='alice',server_url='https://node',device_id='mine',token='old',
        current_chat_type='ally',current_chat_username='bob',current_chat_device_id='b',
        allies={'bob':{'devices':[{'device_id':'b','public_key':'key'}]}})
    context=capture_recipient(state); grants=[]; enqueued=[]; failures=[]
    class Signal:
        def connect(self,fn,*args): self.fn=fn
    class Worker:
        def __init__(self,*args): self.args=args; self.finished=Signal(); grants.append(self)
        def start(self): pass
        def wait(self): pass
    env={'state':state,'recipient_is_verified':recipient_still_trusted,'GrantFileAccessWorker':Worker,
         'Qt':SimpleNamespace(QueuedConnection=0),'QTimer':SimpleNamespace(singleShot=lambda *a:None),
         'outbox':SimpleNamespace(enqueue=lambda *a,**kw:enqueued.append(a)),
         'attachment_outbox':SimpleNamespace(finish=lambda *a:pytest.fail('must preserve job'))}
    import pytest
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods,type_ignores=[])),str(source),'exec'),env)
    class Screen:
        _on_queued_upload_finished=env['_on_queued_upload_finished']
        _on_queued_grant_finished=env['_on_queued_grant_finished']
        def __init__(self): self._net_workers=[]; self._attachment_skipped=set(); self._attachment_worker=None
        def _attachment_failure(self,item,detail): failures.append(detail)
        def _try_outbox(self): pass
        def _try_attachment_outbox(self): pass
    screen=Screen(); item=(Path('job'),Path('blob'),{'file_id':'id','payload':{},'history':{},'message_id':'id'})
    upload=Worker(); upload.queue_item=item; upload.recipient_context=context
    upload.account_context=('alice','https://node','mine','old')
    state.token='new'
    screen._attachment_worker=upload
    screen._on_queued_upload_finished(True,{},upload)
    assert len(grants)==1 and not enqueued and failures
    state.token='old'; screen._attachment_worker=upload; screen._on_queued_upload_finished(True,{},upload); grant=grants[-1]
    assert grant.account_context==upload.account_context
    state.token='new'; grant.finished.fn(True,{})
    assert not enqueued and len(failures)==2


def test_stale_worker_completions_never_replace_current_queue_worker():
    source=Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    names={'_on_queued_upload_finished','_on_queued_grant_finished','_on_outbox_finished'}
    tree=ast.parse(source.read_text())
    nodes=[n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='MainScreen'
           for n in c.body if isinstance(n,ast.FunctionDef) and n.name in names]
    assert len(nodes)==len(names)
    env={}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(source),'exec'),env)
    screen=type('Screen',(),{name:env[name] for name in names})()
    current=object(); stale=SimpleNamespace(wait=lambda:None)
    screen._attachment_worker=current; screen._outbox_worker=current; screen._net_workers=[stale,current]
    screen._on_queued_upload_finished(True,{},stale)
    screen._on_queued_grant_finished(True,{},stale)
    screen._on_outbox_finished(True,{},stale)
    assert screen._attachment_worker is current and screen._outbox_worker is current
    assert screen._net_workers == [current]
