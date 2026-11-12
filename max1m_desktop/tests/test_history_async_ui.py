"""QCore + extracted real callbacks; does not claim full widget GUI coverage."""
import ast
from pathlib import Path
from types import SimpleNamespace
import threading
import time
from PySide6.QtCore import QCoreApplication, QEventLoop, QTimer, Qt
from app.history_paging import HistoryView, check_cancel
from app.workers import HistoryPageWorker


def methods(env):
    path=Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    tree=ast.parse(path.read_text())
    names={'_render_history_page','_start_history_worker','_on_history_worker_finished','_retry_history_scan',
           '_request_history_target','_reveal_history_message'}
    nodes=[n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='MainScreen'
           for n in c.body if isinstance(n,ast.FunctionDef) and n.name in names]
    assert len(nodes)==len(names)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(path),'exec'),env)
    return {name:env[name] for name in names}

class Label:
    def __init__(self,text=''): self.text=text
    def setVisible(self,*a): pass
    def setWordWrap(self,*a): pass
    def setText(self,text): self.text=text
    def setAlignment(self,*a): pass

class Layout:
    def __init__(self): self.items=[]
    def count(self): return len(self.items)+1
    def insertWidget(self,pos,widget): self.items.insert(pos,widget)
    def itemAt(self,index): return SimpleNamespace(widget=lambda:self.items[index])


def make_screen(storage):
    state=SimpleNamespace(username='alice',server_url='https://node',device_id='dev',token='token',
                          current_chat_type='ally',current_chat_username='bob',current_group_id=None)
    env={'state':state,'storage':storage,'HistoryPageWorker':HistoryPageWorker,'Qt':Qt,'QTimer':QTimer,
         'QLabel':Label,'QMessageBox':SimpleNamespace(warning=lambda *a: None, information=lambda *a: None),
         'searchable_text':lambda m:m['text'], 'MessageBubble':lambda **kw: SimpleNamespace(**kw)}
    class Base:
        def __init__(self):
            self._history_offset=0; self._history_query=None; self._history_available=False
            self._history_worker=None; self._history_pending=None; self._history_serial=0; self._history_reveal_callback=None
            self.history_nav=Label(); self.messages_layout=Layout(); self.shown=[]; self.sent=[]
            self.chat_area=object(); self.right_stack=SimpleNamespace(currentWidget=lambda:self.chat_area)
            self.card=SimpleNamespace(unread_count=0,badge=Label()); self.rendered=threading.Event()
        def clear_messages(self): self.messages_layout.items=[]
        def _update_history_navigation(self): pass
        def window(self): return SimpleNamespace(isActiveWindow=lambda:True)
        def isVisible(self): return True
        def _load_message_history(self,chat,msgs):
            self.shown.append((chat,[x['msg_id'] for x in msgs],threading.get_ident()))
            self.rendered.set()
        def _load_group_message_history(self,*args): raise AssertionError('unexpected group')
        def _get_ally_card(self,chat): return self.card
        def _connect_bubble_signals(self,*args): pass
        def _send_system_payload(self,chat,payload): self.sent.append((chat,payload))
    Screen=type('Screen',(Base,),methods(env))
    return Screen(), state


def test_rapid_chat_switches_coalesce_and_never_render_stale_result():
    app=QCoreApplication.instance() or QCoreApplication([])
    gui_thread=threading.get_ident(); started=threading.Event(); active=[]; peak=[]
    def load(owner,chat,offset,*,page_size,query,cancel):
        active.append(chat); peak.append(len(active)); started.set()
        try:
            if chat=='bob':
                while True:
                    check_cancel(cancel); time.sleep(.005)
            return HistoryView([{'msg_id':chat,'text':chat,'is_mine':False,'is_read':False}],0,1,1,False,False),(0,0)
        finally: active.remove(chat)
    store=SimpleNamespace(history_background_enabled=lambda *a:True,
         load_history_page_background=load, history_revision=lambda owner:(0,0),
         mark_messages_as_read_if_revision=lambda owner,chat,ids,rev:True)
    screen,state=make_screen(store); loop=QEventLoop()
    screen._render_history_page()
    assert started.wait(2)
    def switch():
        state.current_chat_username='carol'; screen._render_history_page()
        state.current_chat_username='dave'; screen._render_history_page()
    QTimer.singleShot(10,switch)
    def poll():
        if screen.rendered.is_set(): loop.quit()
        else: QTimer.singleShot(10,poll)
    QTimer.singleShot(20,poll); QTimer.singleShot(4000,loop.quit); loop.exec()
    assert screen._history_worker is None
    assert screen.shown==[('dave',['dave'],gui_thread)] and max(peak)==1
    assert screen.sent==[('dave',{'type':'read_ack','msg_ids':['dave']})]


def test_result_revision_changed_before_callback_is_retried_without_read_ack():
    app=QCoreApplication.instance() or QCoreApplication([])
    revision=[(0,0)]; calls=[]; timers=[]
    def load(owner,chat,offset,*,page_size,query,cancel):
        calls.append(revision[0])
        rev=revision[0]
        if len(calls)==1: revision[0]=(2,0)
        return HistoryView([{'msg_id':f'id-{rev[0]}','text':'text','is_mine':False,'is_read':False}],0,1,1,False,False), rev
    store=SimpleNamespace(history_background_enabled=lambda *a:True,
         load_history_page_background=load,history_revision=lambda owner:revision[0],
         mark_messages_as_read_if_revision=lambda owner,chat,ids,rev:rev==revision[0])
    screen,state=make_screen(store); loop=QEventLoop()
    screen._render_history_page()
    def poll():
        if screen.rendered.is_set(): loop.quit()
        else: QTimer.singleShot(10,poll)
    QTimer.singleShot(10,poll); QTimer.singleShot(4000,loop.quit); loop.exec()
    assert len(calls)==2 and screen.shown[0][1]==['id-2']
    assert screen.sent==[('bob',{'type':'read_ack','msg_ids':['id-2']})]
    assert screen._history_worker is None


def test_revision_changes_during_render_do_not_send_stale_receipt():
    app=QCoreApplication.instance() or QCoreApplication([])
    revision=[(0,0)]; calls=[]
    def load(owner,chat,offset,*,page_size,query,cancel):
        rev=revision[0]; calls.append(rev)
        return HistoryView([{'msg_id':f'id-{rev[0]}','text':'text','is_mine':False,'is_read':False}],0,1,1,False,False),rev
    store=SimpleNamespace(history_background_enabled=lambda *a:True,load_history_page_background=load,
        history_revision=lambda owner:revision[0],
        mark_messages_as_read_if_revision=lambda owner,chat,ids,rev:True if rev==revision[0] else None)
    screen,state=make_screen(store); loop=QEventLoop()
    original=screen._load_message_history
    def load_and_mutate(chat,msgs):
        original(chat,msgs)
        if len(screen.shown)==1: revision[0]=(2,0)
    screen._load_message_history=load_and_mutate
    screen._render_history_page()
    def poll():
        if len(screen.shown)==2 and screen._history_worker is None: loop.quit()
        else: QTimer.singleShot(10,poll)
    QTimer.singleShot(10,poll); QTimer.singleShot(4000,loop.quit); loop.exec()
    assert len(calls)==2 and [x[1] for x in screen.shown]==[['id-0'],['id-2']]
    assert screen.sent==[('bob',{'type':'read_ack','msg_ids':['id-2']})]


def test_real_worker_reads_and_marks_both_legacy_and_migrated_history(tmp_path, monkeypatch):
    from app import secure_storage, history_activation
    app=QCoreApplication.instance() or QCoreApplication([])
    keys={}
    monkeypatch.setattr(secure_storage,'BASE_DIR',tmp_path)
    monkeypatch.setattr(secure_storage.keyring,'get_password',lambda service,name:keys.get(name))
    monkeypatch.setattr(secure_storage.keyring,'set_password',lambda service,name,value:keys.__setitem__(name,value))
    store=secure_storage.SecureStorage
    for chat in ('bob','carol'):
        for i in range(30): assert store.save_message('alice',chat,f'text {i}',False,msg_id=f'{chat}-{i}')
    history_activation.migrate_chat('alice','carol')
    screen,state=make_screen(store)
    for chat in ('bob','carol'):
        state.current_chat_username=chat
        screen.rendered.clear(); loop=QEventLoop()
        screen._render_history_page()
        def poll():
            if screen.rendered.is_set() and screen._history_worker is None: loop.quit()
            else: QTimer.singleShot(10,poll)
        QTimer.singleShot(10,poll); QTimer.singleShot(4000,loop.quit); loop.exec()
        assert screen._history_worker is None
        ids=[f'{chat}-{i}' for i in range(5,30)]
        assert screen.shown[-1][0:2]==(chat,ids)
        assert screen.sent[-1]==(chat,{'type':'read_ack','msg_ids':ids})
        messages=store.load_messages_strict('alice',chat)
        assert [m['is_read'] for m in messages]==[False]*5+[True]*25


def test_real_background_reply_lookup_for_legacy_and_migrated_history(tmp_path, monkeypatch):
    from app import secure_storage, history_activation
    app=QCoreApplication.instance() or QCoreApplication([])
    keys={}
    monkeypatch.setattr(secure_storage,'BASE_DIR',tmp_path)
    monkeypatch.setattr(secure_storage.keyring,'get_password',lambda service,name:keys.get(name))
    monkeypatch.setattr(secure_storage.keyring,'set_password',lambda service,name,value:keys.__setitem__(name,value))
    store=secure_storage.SecureStorage
    for chat in ('bob','carol'):
        for i in range(65): assert store.save_message('alice',chat,f'text {i}',True,msg_id=f'{chat}-{i}')
    history_activation.migrate_chat('alice','carol')
    screen,state=make_screen(store); revealed=[]
    screen._reveal_history_message=lambda target,context:revealed.append((target,context))
    for chat in ('bob','carol'):
        state.current_chat_username=chat; screen._history_offset=0; screen._history_query='old'
        screen.rendered.clear(); loop=QEventLoop()
        screen._request_history_target(f'{chat}-20')
        def poll():
            if revealed and revealed[-1][0]==f'{chat}-20': loop.quit()
            else: QTimer.singleShot(10,poll)
        QTimer.singleShot(10,poll); QTimer.singleShot(4000,loop.quit); loop.exec()
        assert screen._history_worker is None
        assert screen._history_query is None and screen._history_offset==44
        assert screen.shown[-1][1]==[f'{chat}-{i}' for i in range(21)]
        assert revealed[-1][0]==f'{chat}-20'
        page,revision=store.load_history_page_background('alice',chat,target_id='missing')
        assert page is None and revision == store.history_revision('alice')


def test_target_lookup_is_cancelled_when_chat_changes():
    app=QCoreApplication.instance() or QCoreApplication([])
    started=threading.Event(); calls=[]
    def load(owner,chat,offset,*,page_size,query,cancel,target_id=None):
        calls.append((chat,target_id))
        if target_id:
            started.set()
            while True:
                check_cancel(cancel); time.sleep(.005)
        return HistoryView([{'msg_id':chat,'text':chat,'is_mine':True}],0,1,0,False,False),(0,0)
    store=SimpleNamespace(history_background_enabled=lambda *a:True, load_history_page_background=load,
        history_revision=lambda owner:(0,0))
    screen,state=make_screen(store); loop=QEventLoop(); screen._request_history_target('old-target')
    assert started.wait(2)
    def switch():
        state.current_chat_username='carol'; screen._render_history_page()
    QTimer.singleShot(10,switch)
    def poll():
        if screen.rendered.is_set(): loop.quit()
        else: QTimer.singleShot(10,poll)
    QTimer.singleShot(20,poll); QTimer.singleShot(4000,loop.quit); loop.exec()
    assert screen._history_worker is None
    assert calls==[('bob','old-target'),('carol',None)]
    assert screen.shown[0][0:2]==('carol',['carol']) and not screen.sent


def test_target_lookup_retries_the_target_when_revision_changes_during_render():
    app=QCoreApplication.instance() or QCoreApplication([])
    revision=[(0,0)]; calls=[]; revealed=[]
    def load(owner,chat,offset,*,page_size,query,cancel,target_id=None):
        calls.append(target_id); rev=revision[0]
        return HistoryView([{'msg_id':'target','text':'text','is_mine':False,'is_read':False}],
                           5 if rev==(0,0) else 6,7,1,False,True),rev
    store=SimpleNamespace(history_background_enabled=lambda *a:True,load_history_page_background=load,
        history_revision=lambda owner:revision[0],
        mark_messages_as_read_if_revision=lambda owner,chat,ids,rev:True if rev==revision[0] else None)
    screen,state=make_screen(store); loop=QEventLoop()
    screen._reveal_history_message=lambda target,context:revealed.append((target,context))
    original=screen._load_message_history
    def render(chat,msgs):
        original(chat,msgs)
        if len(screen.shown)==1: revision[0]=(2,0)
    screen._load_message_history=render
    screen._request_history_target('target')
    def poll():
        if revealed: loop.quit()
        else: QTimer.singleShot(10,poll)
    QTimer.singleShot(10,poll); QTimer.singleShot(4000,loop.quit); loop.exec()
    assert screen._history_worker is None and calls==['target','target']
    assert screen._history_offset==6 and revealed[0][0]=='target'
    assert screen.sent==[('bob',{'type':'read_ack','msg_ids':['target']})]
