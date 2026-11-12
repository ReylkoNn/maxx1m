import asyncio
import json
import threading
import pytest
from app.workers import WebSocketWorker, MAX_PENDING_WS_EVENTS, MAX_PENDING_WS_SENDS


def test_websocket_pauses_before_unbounded_gui_queue(monkeypatch):
    worker = WebSocketWorker('https://example.test', 'token', 'dev')
    received = []
    worker.new_message_received.connect(received.append)
    class Connection:
        def __init__(self): self.count = 0
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def recv(self):
            self.count += 1
            return json.dumps({'type': 'new_message', 'id': str(self.count)})
    connection = Connection()
    def connect(url, *, additional_headers=None, **kwargs): return connection
    monkeypatch.setattr('app.workers.websockets.connect', connect)
    async def scenario():
        task = asyncio.create_task(worker._connect_loop())
        await asyncio.sleep(0.15)
        assert len(received) == MAX_PENDING_WS_EVENTS and connection.count == MAX_PENDING_WS_EVENTS
        worker.release_event()
        await asyncio.sleep(0.08)
        assert len(received) == MAX_PENDING_WS_EVENTS + 1
        worker._is_running = False
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(scenario())


def test_outgoing_websocket_queue_is_bounded_and_old_socket_not_reused():
    worker = WebSocketWorker('https://example.test', 'token', 'dev')
    class Socket:
        def __init__(self): self.sent = []; self.event = asyncio.Event()
        async def send(self, data):
            await self.event.wait()
            self.sent.append(data)
    async def scenario():
        ws = Socket()
        worker._loop = asyncio.get_running_loop(); worker._ws = ws
        for i in range(MAX_PENDING_WS_SENDS):
            assert worker.send_signal({'type':'call_offer', 'i':i})
        assert not worker.send_signal({'type':'call_offer'})
        assert not worker.send_signal({'type':'call_offer', 'x':'x'*(128*1024+1)})
        await asyncio.sleep(0.05)
        ws.event.set()
        await asyncio.sleep(0.05)
        assert len(ws.sent) == MAX_PENDING_WS_SENDS
        assert worker.send_signal({'type':'call_ended'})
        worker._ws = Socket()  # Scheduled signal cannot migrate to a new connection.
        await asyncio.sleep(0.05)
        assert len(ws.sent) == MAX_PENDING_WS_SENDS and not worker._ws.sent
    asyncio.run(scenario())


def test_stop_interrupts_idle_websocket_worker(monkeypatch):
    worker = WebSocketWorker('https://example.test', 'token', 'dev')
    entered = threading.Event()
    class Connection:
        async def __aenter__(self): entered.set(); return self
        async def __aexit__(self, *args): return False
        async def recv(self): await asyncio.Event().wait()
    def connect(url, *, additional_headers=None, **kwargs): return Connection()
    monkeypatch.setattr('app.workers.websockets.connect', connect)
    worker.start()
    try:
        assert entered.wait(3)
        worker.stop()
        assert worker.wait(3000)
    finally:
        worker.stop(); worker.wait(3000)


def test_queued_qt_delivery_runs_on_gui_thread_and_releases(monkeypatch):
    import ast
    from pathlib import Path
    from types import SimpleNamespace
    from PySide6.QtCore import QCoreApplication, QEventLoop, QTimer, Qt
    app = QCoreApplication.instance() or QCoreApplication([])
    main_thread = threading.get_ident()
    path = Path(__file__).resolve().parents[1] / 'app/windows/app_window.py'
    tree = ast.parse(path.read_text())
    node = next(n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'AppWindow'
                for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_connect_ws_event')
    state = SimpleNamespace(username='a', server_url='https://example.test', device_id='dev', token='token')
    env = {'state':state, 'Qt':Qt}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(path), 'exec'), env)
    Screen = type('Screen', (), {'_connect_ws_event': env['_connect_ws_event']})
    screen = Screen()
    worker = WebSocketWorker(state.server_url, state.token, state.device_id)
    worker.account_context = ('a', 'https://example.test', 'dev', 'token')
    screen.ws_worker = worker
    class Connection:
        def __init__(self): self.sent = False
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def recv(self):
            if not self.sent:
                self.sent = True
                return json.dumps({'type':'new_message', 'id':'test'})
            await asyncio.Event().wait()
    def connect(url, *, additional_headers=None, **kwargs): return Connection()
    monkeypatch.setattr('app.workers.websockets.connect', connect)
    loop = QEventLoop(); seen = []
    def handle(data):
        seen.append((threading.get_ident(), data['id']))
        worker.stop(); loop.quit()
    screen._connect_ws_event(worker, worker.new_message_received, handle)
    QTimer.singleShot(3000, loop.quit)
    worker.start(); loop.exec()
    worker.stop()
    assert worker.wait(3000)
    assert seen == [(main_thread, 'test')]
    # All event slots, including the one held by recv() during cancellation, return.
    for _ in range(MAX_PENDING_WS_EVENTS): assert worker._event_slots.acquire(blocking=False)
    assert not worker._event_slots.acquire(blocking=False)
    for _ in range(MAX_PENDING_WS_EVENTS): worker._event_slots.release()
