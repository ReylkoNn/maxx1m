import ast
from pathlib import Path
from types import SimpleNamespace
from app.delivery import process_delivery_page


def methods(names, env):
    path = Path(__file__).resolve().parents[1] / 'app/windows/app_window.py'
    tree = ast.parse(path.read_text())
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'AppWindow'
             for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(nodes) == len(names)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), env)
    return dict(zip(names, (env[name] for name in names)))

class Signal:
    def connect(self, handler, *args): self.handler = handler
    def emit(self, *args): self.handler(*args)
class Ack:
    instances = []
    def __init__(self, server, token, ids):
        self.ids, self.finished = ids, Signal(); Ack.instances.append(self)
    def start(self): self.started = True
    def wait(self): pass


def test_next_page_waits_for_ack_and_retry_scan_preserves_cursor():
    state = SimpleNamespace(username='a', server_url='s', device_id='d', token='t')
    timers = []
    env = {'state': state, 'AcknowledgeMessagesWorker': Ack, 'process_delivery_page': process_delivery_page,
           'Qt': SimpleNamespace(QueuedConnection=0),
           'QTimer': SimpleNamespace(singleShot=lambda delay, fn: timers.append(fn))}
    names = ['_on_sync_finished', '_on_delivery_ack_finished', '_continue_message_sync', '_start_message_sync']
    Screen = type('Screen', (), methods(names, env)); screen = Screen()
    screen._ack_worker = None; screen._sync_cursor = None; screen._sync_restart_requested = False
    screen._sync_version_warning_shown = False
    screen.main_screen = SimpleNamespace(process_incoming_message=lambda message, is_sync: True)
    w = SimpleNamespace(account_context=('a','s','d','t'), wait=lambda: None)
    screen.sync_worker = w
    page = [{'id': str(i)} for i in range(20)]
    screen._on_sync_finished(True, page, w)
    assert screen.sync_worker is None and screen._ack_worker.ids == [str(i) for i in range(20)]
    assert not timers and screen._sync_cursor is None
    # A periodic sync during in-flight ACK cannot spawn a second sync worker.
    screen._start_message_sync()
    assert screen.sync_worker is None
    screen._ack_worker.finished.emit(False, 503)
    assert screen._ack_worker is None and screen._sync_cursor == '19' and len(timers) == 1


def test_ws_delivery_releases_slots_for_stale_or_failed_callbacks():
    state = SimpleNamespace(username='a', server_url='s', device_id='d', token='t')
    env = {'state':state, 'Qt': SimpleNamespace(QueuedConnection=0)}
    Screen = type('Screen', (), methods(['_connect_ws_event'], env)); screen = Screen()
    released = []
    worker = SimpleNamespace(account_context=('a','s','d','t'), release_event=lambda: released.append(True))
    screen.ws_worker = worker; signal = Signal()
    def crash(_): raise RuntimeError('handler failed')
    screen._connect_ws_event(worker, signal, crash)
    try: signal.emit({'x': 1})
    except RuntimeError: pass
    assert released == [True]
    state.username = 'other'
    signal.emit({'x': 2})
    assert released == [True, True]


def test_ack_completion_after_verification_change_restarts_from_beginning():
    state = SimpleNamespace(username='a', server_url='s', device_id='d', token='t')
    timers = []
    env = {'state':state, 'QTimer':SimpleNamespace(singleShot=lambda delay, fn: timers.append(fn))}
    names = ['_on_delivery_ack_finished', '_continue_message_sync']
    screen = type('Screen', (), methods(names, env))()
    screen._sync_restart_requested = True
    screen._sync_cursor = 'previous'
    screen._start_message_sync = lambda: None
    worker = SimpleNamespace(account_context=('a','s','d','t'), next_cursor='cursor', wait=lambda: None)
    screen._ack_worker = worker
    screen._on_delivery_ack_finished(True, 200, worker)
    assert screen._ack_worker is None and screen._sync_cursor is None
    assert not screen._sync_restart_requested and len(timers) == 1


def test_ack_from_previous_account_never_advances_current_cursor():
    state = SimpleNamespace(username='new', server_url='s', device_id='d', token='newtoken')
    env = {'state':state}
    screen = type('Screen', (), methods(['_on_delivery_ack_finished'], env))()
    screen._sync_cursor = 'oldcursor'
    worker = SimpleNamespace(account_context=('old','s','d','oldtoken'), next_cursor='bad', wait=lambda: None)
    screen._ack_worker = worker
    screen._on_delivery_ack_finished(True, 200, worker)
    assert screen._ack_worker is None and screen._sync_cursor is None


def test_account_change_mid_page_never_acks_or_processes_later_messages():
    state=SimpleNamespace(username='a',server_url='s',device_id='d',token='t')
    calls=[]
    env={'state':state,'process_delivery_page':process_delivery_page,
         'AcknowledgeMessagesWorker':lambda *a: (_ for _ in ()).throw(AssertionError('stale ack'))}
    screen=type('Screen',(),methods(['_on_sync_finished'],env))()
    screen._sync_cursor='prior'; screen._sync_restart_requested=False
    def process(message,is_sync):
        calls.append(message['id'])
        state.username='new'; state.token='new-token'
        return True
    screen.main_screen=SimpleNamespace(process_incoming_message=process)
    worker=SimpleNamespace(account_context=('a','s','d','t'),wait=lambda:None)
    screen.sync_worker=worker
    screen._on_sync_finished(True,[{'id':'first'},{'id':'second'}],worker)
    assert calls==['first'] and screen._sync_cursor is None and screen.sync_worker is None


def test_replaced_screen_mid_page_never_acks_old_results():
    state=SimpleNamespace(username='a',server_url='s',device_id='d',token='t')
    calls=[]
    env={'state':state,'process_delivery_page':process_delivery_page,
         'AcknowledgeMessagesWorker':lambda *a: (_ for _ in ()).throw(AssertionError('stale ack'))}
    screen=type('Screen',(),methods(['_on_sync_finished'],env))()
    screen._sync_cursor='prior'; screen._sync_restart_requested=False
    def process(message,is_sync):
        calls.append(message['id']); screen.main_screen=SimpleNamespace()
        return True
    screen.main_screen=SimpleNamespace(process_incoming_message=process)
    worker=SimpleNamespace(account_context=('a','s','d','t'),wait=lambda:None)
    screen.sync_worker=worker
    screen._on_sync_finished(True,[{'id':'first'},{'id':'second'}],worker)
    assert calls==['first'] and screen._sync_cursor is None


def test_exception_isolated_and_only_successful_messages_acked():
    state=SimpleNamespace(username='a',server_url='s',device_id='d',token='t')
    calls=[]
    env={'state':state,'process_delivery_page':process_delivery_page,'AcknowledgeMessagesWorker':Ack,
         'Qt':SimpleNamespace(QueuedConnection=0)}
    screen=type('Screen',(),methods(['_on_sync_finished'],env))()
    def process(message,is_sync):
        calls.append(message['id'])
        if message['id']=='broken': raise RuntimeError('sensitive contents')
        return True
    screen.main_screen=SimpleNamespace(process_incoming_message=process)
    screen._sync_cursor=None; screen._sync_restart_requested=False
    worker=SimpleNamespace(account_context=('a','s','d','t'),wait=lambda:None); screen.sync_worker=worker
    screen._on_sync_finished(True,[{'id':'first'},{'id':'broken'},{'id':'last'}],worker)
    assert calls==['first','broken','last'] and screen._ack_worker.ids==['first','last']


def test_duplicate_delivery_ids_do_not_process_or_ack():
    calls=[]
    page=[{'id':'duplicate','payload':'a'},{'id':'duplicate','payload':'b'}]
    assert process_delivery_page(page,lambda m:calls.append(m) or True)==([],None)
    assert not calls
