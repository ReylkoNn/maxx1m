"""Exercise actual closeEvent control flow without importing QtGui widgets."""
import ast
from pathlib import Path
from types import SimpleNamespace


def window_class(env):
    path=Path(__file__).resolve().parents[1]/'app/windows/app_window.py'
    tree=ast.parse(path.read_text())
    cls=next(c for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='AppWindow')
    method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='closeEvent')
    wrapper=ast.ClassDef(name='Window',bases=[ast.Name(id='Base',ctx=ast.Load())],keywords=[],body=[method],decorator_list=[])
    exec(compile(ast.fix_missing_locations(ast.Module(body=[wrapper],type_ignores=[])),str(path),'exec'),env)
    return env['Window']

class Event:
    def __init__(self): self.ignored=False; self.closed=False
    def ignore(self): self.ignored=True
class Base:
    def closeEvent(self,event): event.closed=True
class Worker:
    def __init__(self,running=True,wait_result=False): self.running=running; self.wait_result=wait_result; self.cancelled=False
    def isRunning(self): return self.running
    def wait(self,*args): return self.wait_result
    def cancel(self): self.cancelled=True


def make_window():
    alerts=[]; shutdown=[]
    env={'Base':Base,'QMessageBox':SimpleNamespace(warning=lambda *a: alerts.append(a)),
         'rtc':SimpleNamespace(shutdown=lambda:shutdown.append(True))}
    Window=window_class(env); window=Window()
    timer=SimpleNamespace(stop=lambda:None,start=lambda:None)
    window.main_screen=SimpleNamespace(find_worker=None,_net_workers=[],_media_queue=SimpleNamespace(active=False),
                    _history_worker=None,_history_pending='old',_outbox_timer=timer,_outbox_worker=None)
    window.worker=None; window.sync_worker=None; window._ack_worker=None; window.ws_worker=None
    return window,alerts,shutdown


def test_close_refuses_to_destroy_active_auth_or_search_threads():
    window,alerts,shutdown=make_window(); event=Event()
    window.worker=Worker()
    window.closeEvent(event)
    assert event.ignored and not event.closed and not shutdown
    window.worker=None; window.main_screen.find_worker=Worker(); event=Event()
    window.closeEvent(event)
    assert event.ignored and not event.closed and len(alerts)==2


def test_close_cancels_history_and_refuses_until_thread_stops():
    window,alerts,shutdown=make_window(); event=Event()
    worker=Worker(wait_result=False); window.main_screen._history_worker=worker
    window.closeEvent(event)
    assert worker.cancelled and event.ignored and not event.closed and not shutdown
    assert window.main_screen._history_pending is None
    worker.wait_result=True; event=Event(); window.closeEvent(event)
    assert event.closed and shutdown == [True]


def test_close_refuses_any_live_network_worker():
    window,alerts,shutdown=make_window(); event=Event()
    window.main_screen._net_workers=[Worker()]
    window.closeEvent(event)
    assert event.ignored and not event.closed and not shutdown


def test_close_refuses_while_microphone_thread_did_not_stop():
    window,alerts,shutdown=make_window(); event=Event(); cancelled=[]
    thread=SimpleNamespace(is_alive=lambda:True)
    window.main_screen._voice_thread=thread
    window.main_screen._is_recording=True
    window.main_screen._cancel_voice_recording=lambda:cancelled.append(True)
    window.closeEvent(event)
    assert cancelled==[True] and event.ignored and not event.closed and not shutdown


def test_close_refuses_until_playback_thread_terminates():
    window,alerts,shutdown=make_window(); event=Event(); calls=[]
    window.main_screen._voice_playback=SimpleNamespace(stop_and_wait=lambda timeout:calls.append(timeout) or False)
    window.main_screen._stop_voice_playback=lambda:calls.append('stop')
    window.closeEvent(event)
    assert calls==['stop',.3] and event.ignored and not event.closed and not shutdown
