"""Bounded sends on one socket; offline message recovery stays in the DB."""
import asyncio
from app.api import messages


class Socket:
    def __init__(self):
        self.gate=asyncio.Event(); self.started=asyncio.Event(); self.sent=[]; self.closed=False; self.active=0; self.peak=0
    async def accept(self): pass
    async def close(self,code): self.closed=True
    async def send_json(self,data):
        self.active+=1; self.peak=max(self.peak,self.active); self.started.set()
        try:
            await self.gate.wait(); self.sent.append(data)
        finally: self.active-=1
    async def send_bytes(self,data): await self.send_json(data)


def test_sends_are_serialized_and_pending_count_is_bounded(monkeypatch):
    monkeypatch.setattr(messages,'MAX_WS_PENDING_SENDS',3)
    async def run():
        manager=messages.ConnectionManager(); socket=Socket(); await manager.connect(socket,'dev')
        first=asyncio.create_task(manager.send_personal_message({'n':1},'dev'))
        await socket.started.wait()
        second=asyncio.create_task(manager.send_personal_message({'n':2},'dev'))
        third=asyncio.create_task(manager.send_personal_binary(b'3','dev'))
        await asyncio.sleep(.02)
        assert manager._send_states[socket].pending==3
        assert not await manager.send_personal_message({'n':4},'dev')
        socket.gate.set()
        assert await asyncio.gather(first,second,third)==[True,True,True]
        assert socket.sent==[{'n':1},{'n':2},b'3'] and socket.peak==1
        assert manager._send_states[socket].pending==0
        manager.disconnect('dev'); assert not manager._send_states
    asyncio.run(run())


def test_slow_send_times_out_and_is_disconnected(monkeypatch):
    monkeypatch.setattr(messages,'WS_SEND_TIMEOUT',.03)
    async def run():
        manager=messages.ConnectionManager(); socket=Socket(); await manager.connect(socket,'dev')
        assert not await manager.send_personal_message({'n':1},'dev')
        assert socket.closed and 'dev' not in manager.active_connections and not manager._send_states
    asyncio.run(run())


def test_old_socket_failure_does_not_disconnect_replacement():
    async def run():
        manager=messages.ConnectionManager(); old=Socket(); new=Socket()
        await manager.connect(old,'dev')
        async def fail(data):
            old.started.set(); await old.gate.wait(); raise OSError('failed')
        old.send_json=fail
        task=asyncio.create_task(manager.send_personal_message({},'dev')); await old.started.wait()
        await manager.connect(new,'dev'); old.gate.set()
        assert not await task and manager.active_connections['dev'] is new
        new.gate.set(); assert await manager.send_personal_message({'new':True},'dev')
        assert new.sent==[{'new':True}]
    asyncio.run(run())


def test_cancelled_waiter_releases_capacity():
    async def run():
        manager=messages.ConnectionManager(); socket=Socket(); await manager.connect(socket,'dev')
        first=asyncio.create_task(manager.send_personal_message({},'dev')); await socket.started.wait()
        waiter=asyncio.create_task(manager.send_personal_message({},'dev')); await asyncio.sleep(.02)
        waiter.cancel()
        try: await waiter
        except asyncio.CancelledError: pass
        assert manager._send_states[socket].pending==1
        socket.gate.set(); assert await first
        assert manager._send_states[socket].pending==0
    asyncio.run(run())


def test_cancelling_active_send_disconnects_socket():
    async def run():
        manager=messages.ConnectionManager(); socket=Socket(); await manager.connect(socket,'dev')
        task=asyncio.create_task(manager.send_personal_message({},'dev')); await socket.started.wait()
        task.cancel()
        try: await task
        except asyncio.CancelledError: pass
        assert socket.closed and 'dev' not in manager.active_connections and not manager._send_states
    asyncio.run(run())


def test_unresponsive_old_socket_cannot_block_replacement(monkeypatch):
    monkeypatch.setattr(messages,'WS_CLOSE_TIMEOUT',.02)
    async def run():
        manager=messages.ConnectionManager(); old=Socket(); new=Socket()
        await manager.connect(old,'dev')
        async def stalled_close(code): await asyncio.Event().wait()
        old.close=stalled_close
        await asyncio.wait_for(manager.connect(new,'dev'),timeout=.5)
        assert manager.active_connections['dev'] is new
        new.gate.set(); assert await manager.send_personal_message({'ok':True},'dev')
    asyncio.run(run())
