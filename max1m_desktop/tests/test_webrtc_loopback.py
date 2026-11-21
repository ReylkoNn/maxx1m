"""Optional real aiortc loopback; no GUI, audio hardware, tunnel or TURN."""
import ast
import asyncio
import fractions
import logging
from pathlib import Path
from typing import Callable, Optional

import pytest

aiortc = pytest.importorskip('aiortc')
np = pytest.importorskip('numpy')
from aiortc import (RTCPeerConnection, RTCSessionDescription, RTCIceCandidate,
                    RTCConfiguration, RTCIceServer, MediaStreamTrack)
from aiortc.mediastreams import MediaStreamError
from aiortc.sdp import candidate_from_sdp, candidate_to_sdp
from av.audio.frame import AudioFrame


def session_classes(ice_fn=None):
    source = Path(__file__).resolve().parents[1] / 'app/webrtc_manager.py'
    tree = ast.parse(source.read_text())
    names = {'AudioCaptureTrack', 'VoicePeerSession'}
    nodes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name in names]
    env = dict(asyncio=asyncio, fractions=fractions, np=np, AudioFrame=AudioFrame,
               MediaStreamTrack=MediaStreamTrack, MediaStreamError=MediaStreamError,
               RTCPeerConnection=RTCPeerConnection, RTCSessionDescription=RTCSessionDescription,
               RTCIceCandidate=RTCIceCandidate, RTCConfiguration=RTCConfiguration, RTCIceServer=RTCIceServer,
               candidate_from_sdp=candidate_from_sdp, candidate_to_sdp=candidate_to_sdp,
               Callable=Callable, Optional=Optional, PyAudioIO=object,
               ice_server_settings=(lambda: []) if ice_fn is None else ice_fn,
               logger=logging.getLogger('loopback'), RATE=48000, CHANNELS=1, CHUNK_SAMPLES=960)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source), 'exec'), env)
    return env['VoicePeerSession']


def test_local_offer_answer_and_audio_with_real_aiortc():
    Session = session_classes()
    async def exercise():
        connected = {name: asyncio.Event() for name in ('alice', 'bob')}
        sound = {name: asyncio.Event() for name in ('alice', 'bob')}
        class Audio:
            def __init__(self, name): self.name = name
            def read(self): return None  # Real AudioCaptureTrack emits silence.
            def write(self, pcm):
                if pcm: sound[self.name].set()
        def on_state(name):
            return lambda peer, status: connected[name].set() if status == 'connected' else None
        a = Session('bob', Audio('alice'), lambda *args: None, on_state('alice'))
        b = Session('alice', Audio('bob'), lambda *args: None, on_state('bob'))
        try:
            await a.create(); await b.create()
            offer = await a.create_offer()
            answer = await b.handle_offer(offer)
            await a.handle_answer(answer)
            await asyncio.wait_for(asyncio.gather(*(event.wait() for event in connected.values())), timeout=10)
            await asyncio.wait_for(asyncio.gather(*(event.wait() for event in sound.values())), timeout=10)
        finally:
            await a.close(); await b.close()
    asyncio.run(exercise())


def test_real_aiortc_candidate_parsing():
    Session = session_classes()
    async def exercise():
        received = []
        class PC:
            async def addIceCandidate(self, candidate): received.append(candidate)
        session = Session('peer', None, None, None)
        session.pc = PC()
        await session.add_ice({'candidate': 'candidate:0 1 udp 2122252543 192.0.2.1 12345 typ host',
                               'sdpMid': '0', 'sdpMLineIndex': 0})
        assert len(received) == 1 and received[0].ip == '192.0.2.1'
        assert received[0].sdpMid == '0' and received[0].sdpMLineIndex == 0
        await session.add_ice({'candidate': 'not a valid candidate'})
        assert len(received) == 1
    asyncio.run(exercise())


def test_early_trickle_ice_buffered_until_remote_description_ready():
    Session = session_classes()
    async def exercise():
        received = []
        class PC:
            remoteDescription = None
            async def setRemoteDescription(self, desc):
                self.remoteDescription = desc
            async def addIceCandidate(self, candidate):
                received.append(candidate)
        session = Session('peer', None, None, None, relay_only=False)
        session.pc = PC()
        await session.add_ice({'candidate': 'candidate:0 1 udp 2122252543 192.0.2.9 22222 typ host',
                               'sdpMid': '0', 'sdpMLineIndex': 0})
        assert received == [] and len(session._pending_remote_ice) == 1
        await session.handle_answer('v=0\r\n')
        assert len(received) == 1 and received[0].ip == '192.0.2.9' and session._pending_remote_ice == []
    asyncio.run(exercise())


def test_relay_only_turn_call_with_real_aiortc_and_remote_volume():
    """Exercise two real aiortc sessions over a local RFC 5766 UDP TURN relay."""
    import struct
    from aioice import stun, turn
    from app.ice_config import ice_server_settings

    REALM = 'max1m.local'
    NONCE = b'testnonce'
    USERS = {'alice': 'turn-secret'}

    class RelayEndpoint(asyncio.DatagramProtocol):
        def __init__(self, server_proto, client_addr):
            self.server_proto = server_proto
            self.client_addr = client_addr
            self.transport = None
            self.peer_to_channel = {}
            self.channel_to_peer = {}

        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, peer_addr):
            channel = self.peer_to_channel.get(peer_addr)
            if channel is not None:
                header = struct.pack('!HH', channel, len(data))
                pad = b'\x00' * ((4 - (len(data) % 4)) % 4)
                self.server_proto.transport.sendto(header + data + pad, self.client_addr)
            else:
                ind = stun.Message(message_method=stun.Method.DATA, message_class=stun.Class.INDICATION)
                ind.attributes['XOR-PEER-ADDRESS'] = peer_addr
                ind.attributes['DATA'] = data
                self.server_proto.transport.sendto(bytes(ind), self.client_addr)

        def close(self):
            if self.transport:
                self.transport.close()

    class LocalTurnServer(asyncio.DatagramProtocol):
        def __init__(self, loop):
            self.loop = loop
            self.transport = None
            self.allocations = {}

        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            if len(data) >= 4 and turn.is_channel_data(data):
                alloc = self.allocations.get(addr)
                if not alloc:
                    return
                channel, length = struct.unpack('!HH', data[:4])
                peer = alloc.channel_to_peer.get(channel)
                if peer and len(data) >= 4 + length:
                    alloc.transport.sendto(data[4:4 + length], peer)
                return
            try:
                msg = stun.parse_message(data)
            except ValueError:
                return
            if msg.message_class != stun.Class.REQUEST:
                return
            username = msg.attributes.get('USERNAME')
            if not username or 'MESSAGE-INTEGRITY' not in msg.attributes or username not in USERS:
                err = stun.Message(msg.message_method, stun.Class.ERROR, msg.transaction_id)
                err.attributes['ERROR-CODE'] = (401, 'Unauthorized')
                err.attributes['REALM'] = REALM
                err.attributes['NONCE'] = NONCE
                self.transport.sendto(bytes(err), addr)
                return
            key = turn.make_integrity_key(username, REALM, USERS[username])
            try:
                msg.check_message_integrity(key)
            except ValueError:
                err = stun.Message(msg.message_method, stun.Class.ERROR, msg.transaction_id)
                err.attributes['ERROR-CODE'] = (401, 'Bad integrity')
                self.transport.sendto(bytes(err), addr)
                return
            if msg.message_method == stun.Method.ALLOCATE:
                asyncio.ensure_future(self._handle_allocate(msg, addr, key))
            elif msg.message_method == stun.Method.CHANNEL_BIND:
                alloc = self.allocations.get(addr)
                if alloc:
                    ch = msg.attributes['CHANNEL-NUMBER']
                    peer = msg.attributes['XOR-PEER-ADDRESS']
                    alloc.channel_to_peer[ch] = peer
                    alloc.peer_to_channel[peer] = ch
                    resp = stun.Message(stun.Method.CHANNEL_BIND, stun.Class.RESPONSE, msg.transaction_id)
                    resp.add_message_integrity(key)
                    self.transport.sendto(bytes(resp), addr)
            elif msg.message_method == stun.Method.REFRESH:
                lifetime = msg.attributes.get('LIFETIME', 600)
                if lifetime == 0:
                    alloc = self.allocations.pop(addr, None)
                    if alloc:
                        alloc.close()
                resp = stun.Message(stun.Method.REFRESH, stun.Class.RESPONSE, msg.transaction_id)
                resp.attributes['LIFETIME'] = lifetime
                resp.add_message_integrity(key)
                self.transport.sendto(bytes(resp), addr)

        async def _handle_allocate(self, msg, addr, key):
            alloc = self.allocations.get(addr)
            if alloc is None:
                relay_proto = RelayEndpoint(self, addr)
                await self.loop.create_datagram_endpoint(lambda: relay_proto, local_addr=('127.0.0.1', 0))
                self.allocations[addr] = relay_proto
                alloc = relay_proto
            relay_addr = alloc.transport.get_extra_info('sockname')
            resp = stun.Message(stun.Method.ALLOCATE, stun.Class.RESPONSE, msg.transaction_id)
            resp.attributes['LIFETIME'] = 600
            resp.attributes['XOR-MAPPED-ADDRESS'] = addr
            resp.attributes['XOR-RELAYED-ADDRESS'] = (relay_addr[0], relay_addr[1])
            resp.add_message_integrity(key)
            self.transport.sendto(bytes(resp), addr)

        def close(self):
            for alloc in list(self.allocations.values()):
                alloc.close()
            self.allocations.clear()
            if self.transport:
                self.transport.close()

    async def exercise():
        loop = asyncio.get_running_loop()
        turn_proto = LocalTurnServer(loop)
        await loop.create_datagram_endpoint(lambda: turn_proto, local_addr=('127.0.0.1', 0))
        turn_host, turn_port = turn_proto.transport.get_extra_info('sockname')[:2]
        env_vars = {
            'MAX1M_ICE_RELAY_ONLY': '1',
            'MAX1M_TURN_URL': f'turn:{turn_host}:{turn_port}?transport=udp',
            'MAX1M_TURN_USERNAME': 'alice',
            'MAX1M_TURN_PASSWORD': 'turn-secret',
        }
        Session = session_classes(lambda: ice_server_settings(env_vars))
        trickle = []
        connected = {name: asyncio.Event() for name in ('alice', 'bob')}
        tone = (np.sin(np.linspace(0, 2 * np.pi * 8, 960, endpoint=False)) * 12000).astype(np.int16).tobytes()

        class Audio:
            def __init__(self, remote_volume=1.0):
                self.remote_volume = remote_volume
                self.frames = []
                self.got_audio = asyncio.Event()
            def read(self):
                return tone
            def write(self, pcm):
                self.frames.append(pcm)
                if len(self.frames) >= 6:
                    self.got_audio.set()

        alice_audio = Audio(remote_volume=0.0)   # Muted remote volume -> must output zeros!
        bob_audio = Audio(remote_volume=0.5)     # Scaled remote volume -> non-zero!
        a = Session('bob', alice_audio, lambda p, ice, ch: trickle.append(ice['candidate']),
                    lambda p, st: connected['alice'].set() if st == 'connected' else None, relay_only=True)
        b = Session('alice', bob_audio, lambda p, ice, ch: trickle.append(ice['candidate']),
                    lambda p, st: connected['bob'].set() if st == 'connected' else None, relay_only=True)
        try:
            await a.create(); await b.create()
            offer = await a.create_offer()
            answer = await b.handle_offer(offer)
            await a.handle_answer(answer)
            # Relay-only policy must expose ONLY relay candidates in SDP and trickle ICE.
            for sdp in (offer, answer):
                assert 'typ relay' in sdp
                assert 'typ host' not in sdp
                assert 'typ srflx' not in sdp
            for cand in trickle:
                assert 'typ relay' in cand and 'typ host' not in cand and 'typ srflx' not in cand
            await asyncio.wait_for(asyncio.gather(*(ev.wait() for ev in connected.values())), timeout=10)
            await asyncio.wait_for(asyncio.gather(alice_audio.got_audio.wait(), bob_audio.got_audio.wait()), timeout=10)
            assert len(turn_proto.allocations) == 2
            assert all(int(np.abs(np.frombuffer(f, dtype=np.int16)).max()) == 0 for f in alice_audio.frames)
            assert any(int(np.abs(np.frombuffer(f, dtype=np.int16)).max()) > 100 for f in bob_audio.frames)
        finally:
            await a.close(); await b.close()
            turn_proto.close()

    asyncio.run(exercise())
