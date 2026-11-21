"""Run the real manager methods with synthetic audio/RTC and a real event loop.

No devices, aiortc, network, GUI, TLS or TURN are involved in these tests.
"""
import ast
import asyncio
import logging
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional

import pytest
from app.call_lifecycle import CallLifecycle


def manager_class(session_class):
    source = Path(__file__).resolve().parents[1] / 'app/webrtc_manager.py'
    tree = ast.parse(source.read_text())
    cls = next(c for c in tree.body if isinstance(c, ast.ClassDef) and c.name == 'WebRTCManager')
    env = dict(asyncio=asyncio, threading=threading, Callable=Callable, Dict=Dict, List=List, Optional=Optional,
               VoicePeerSession=session_class, CallLifecycle=CallLifecycle, logger=logging.getLogger('test'),
               ice_server_settings=lambda: [], CALL_STATE_IDLE='idle', CALL_STATE_CALLING='calling',
               CALL_STATE_CONNECTING='connecting', CALL_STATE_CONNECTED='connected',
               SignalCrypto=SimpleNamespace(encrypt_signal=lambda data, key: ('cipher', 'signature')))
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), str(source), 'exec'), env)
    return env['WebRTCManager']


class Audio:
    def __init__(self): self._running = False; self.stops = 0
    def start(self): self._running = True
    def stop(self): self._running = False; self.stops += 1


def make_manager(Session):
    cls = manager_class(Session)
    manager = cls.__new__(cls)
    manager.audio_io = Audio()
    manager._voice_peers = {}
    manager._lifecycle = CallLifecycle()
    manager._voice_gate = asyncio.Lock()
    manager.screen = SimpleNamespace(is_sharing=False)
    manager._voice_loop = asyncio.new_event_loop()
    manager._voice_thread = threading.Thread(target=manager._voice_loop.run_forever, daemon=True)
    manager._voice_thread.start()
    manager.get_peer_public_key = lambda peer: 'key'
    manager.input_device_index = manager.output_device_index = None
    manager.on_state_change = None
    manager.on_signal_generated = None
    manager.call_state = 'idle'
    return manager


def barrier(manager):
    async def wait():
        async with manager._voice_gate:
            pass
    asyncio.run_coroutine_threadsafe(wait(), manager._voice_loop).result(timeout=3)


def shutdown(manager):
    manager.end_call()
    barrier(manager)
    manager._voice_loop.call_soon_threadsafe(manager._voice_loop.stop)
    manager._voice_thread.join(timeout=3)
    manager._voice_loop.close()


def test_end_during_offer_then_new_call_same_peer_does_not_reuse_or_leak():
    blocked, second_sent, closed, signals = threading.Event(), threading.Event(), [], []
    class Session:
        def __init__(self, *args): self.pc = SimpleNamespace(connectionState='new')
        async def create(self): pass
        async def close(self): closed.append(self.call_id)
        async def create_offer(self):
            if self.call_id == 'old':
                blocked.set()
                await asyncio.Event().wait()
            return 'new sdp'
    manager = make_manager(Session)
    def signal(data):
        signals.append(data)
        second_sent.set()
    manager.on_signal_generated = signal
    try:
        manager.start_call('peer', 'old')
        assert blocked.wait(3)
        manager.end_call()
        manager.start_call('peer', 'new')
        assert second_sent.wait(3)
        assert [event['_local_call_id'] for event in signals] == ['new']
        assert closed == ['old']
        assert manager._voice_peers['peer'].call_id == 'new' and manager.audio_io._running
    finally:
        shutdown(manager)
    assert closed == ['old', 'new'] and not manager.audio_io._running


def test_end_during_session_create_stops_capture_and_does_not_send():
    entered, closed, signals = threading.Event(), [], []
    class Session:
        def __init__(self, *args): pass
        async def create(self):
            entered.set()
            await asyncio.Event().wait()
        async def close(self): closed.append(self.call_id)
    manager = make_manager(Session)
    manager.on_signal_generated = signals.append
    try:
        manager.start_call('peer', 'old')
        assert entered.wait(3) and manager.audio_io._running
        manager.end_call()
        barrier(manager)
        assert not manager.audio_io._running and not manager._voice_peers
        assert closed == ['old'] and signals == []
    finally:
        shutdown(manager)


def test_session_close_failure_still_stops_microphone():
    class Session:
        call_id = 'call'
        async def close(self): raise RuntimeError('broken close')
    manager = make_manager(Session)
    manager.audio_io.start()
    manager._voice_peers['peer'] = Session()
    manager._lifecycle.activate('peer', 'call')
    try:
        with pytest.raises(RuntimeError):
            asyncio.run_coroutine_threadsafe(manager._end_voice_async('peer', 'call'), manager._voice_loop).result(timeout=3)
        assert not manager.audio_io._running and not manager._voice_peers
    finally:
        shutdown(manager)


def test_pending_call_task_limit_rejects_excess_and_old_context(monkeypatch):
    from app import call_lifecycle
    monkeypatch.setattr(call_lifecycle, 'MAX_PENDING_CALL_TASKS', 1)
    lifecycle = CallLifecycle()
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    started = threading.Event()
    async def wait():
        started.set()
        await asyncio.Event().wait()
    lifecycle.activate('peer', 'old')
    try:
        first = lifecycle.submit(loop, 'peer', 'old', wait())
        assert started.wait(3)
        assert lifecycle.submit(loop, 'peer', 'old', wait()) is None
        assert lifecycle.invalidate() == ('peer', 'old')
        lifecycle.activate('peer', 'new')
        assert lifecycle.submit(loop, 'peer', 'old', wait()) is None
        assert first.cancelled()
    finally:
        lifecycle.invalidate()
        # Let the loop process cancellation before closing it.
        asyncio.run_coroutine_threadsafe(asyncio.sleep(0), loop).result(timeout=3)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=3)
        loop.close()
