"""Exercise real async session setup without Qt, an audio device or a network."""
import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
import pytest


def load_create(env):
    source = Path(__file__).resolve().parents[1] / "app/webrtc_manager.py"
    tree = ast.parse(source.read_text())
    method = next(n for c in tree.body if isinstance(c, ast.ClassDef) and c.name == "WebRTCManager"
                  for n in c.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "_create_voice_session")
    # Annotation references a runtime class; test with our stub.
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), str(source), "exec"), env)
    return env["_create_voice_session"]


def test_invalid_configuration_and_identity_loss_do_not_leave_capture_running():
    events = []
    class Audio:
        _running = False
        def start(self): self._running = True; events.append("start")
        def stop(self): self._running = False; events.append("stop")
    class Session:
        def __init__(self, *args): pass
        async def create(self): events.append("create")
        async def close(self): events.append("close")
    class Sleep:
        @staticmethod
        async def sleep(_): manager.valid = False
    manager = SimpleNamespace(_voice_peers={}, audio_io=Audio(), input_device_index=None, output_device_index=None,
                              valid=True, _on_peer_ice=None, _on_voice_state=None, _lifecycle=SimpleNamespace(matches=lambda *args: True))
    manager.get_peer_public_key = lambda peer: "key" if manager.valid else None
    env = {"VoicePeerSession": Session, "ice_server_settings": lambda: [], "asyncio": Sleep,
           "logger": SimpleNamespace(info=lambda *args: None)}
    create = load_create(env)
    with pytest.raises(ValueError): asyncio.run(create(manager, "peer", "call"))
    assert events == ["start", "stop"] and not manager.audio_io._running and not manager._voice_peers
    events.clear()
    manager.valid = True
    env["ice_server_settings"] = lambda: (_ for _ in ()).throw(ValueError("bad config"))
    with pytest.raises(ValueError): asyncio.run(create(manager, "peer", "call"))
    assert events == [] and not manager.audio_io._running


def test_session_creation_failure_closes_session_and_microphone():
    events = []
    class Audio:
        _running = False
        def start(self): self._running = True; events.append("start")
        def stop(self): self._running = False; events.append("stop")
    class Session:
        def __init__(self, *args): pass
        async def create(self): raise RuntimeError("failed")
        async def close(self): events.append("close")
    manager = SimpleNamespace(_voice_peers={}, audio_io=Audio(), input_device_index=None, output_device_index=None,
                              _on_peer_ice=None, _on_voice_state=None, get_peer_public_key=lambda peer: "key",
                              _lifecycle=SimpleNamespace(matches=lambda *args: True))
    env = {"VoicePeerSession": Session, "ice_server_settings": lambda: [], "asyncio": asyncio,
           "logger": SimpleNamespace(info=lambda *args: None)}
    create = load_create(env)
    with pytest.raises(RuntimeError): asyncio.run(create(manager, "peer", "call"))
    assert events == ["start", "stop", "close"] and not manager.audio_io._running


def test_capture_is_stopped_if_audio_start_raises_after_opening():
    events = []
    class Audio:
        _running = False
        def start(self):
            self._running = True
            events.append('start')
            raise RuntimeError('thread start failed')
        def stop(self): self._running = False; events.append('stop')
    manager = SimpleNamespace(_voice_peers={}, audio_io=Audio(), input_device_index=None, output_device_index=None,
                              _on_peer_ice=None, _on_voice_state=None, get_peer_public_key=lambda peer: 'key',
                              _lifecycle=SimpleNamespace(matches=lambda *args: True))
    env = {'VoicePeerSession': object, 'ice_server_settings': lambda: [], 'asyncio': asyncio,
           'logger': SimpleNamespace(info=lambda *args: None)}
    with pytest.raises(RuntimeError): asyncio.run(load_create(env)(manager, 'peer', 'call'))
    assert events == ['start', 'stop'] and not manager.audio_io._running


def test_audio_stop_closes_stream_even_if_stop_stream_raises():
    import threading
    from collections import deque
    from typing import Optional
    source = Path(__file__).resolve().parents[1] / 'app/webrtc_manager.py'
    tree = ast.parse(source.read_text())
    cls = next(c for c in tree.body if isinstance(c, ast.ClassDef) and c.name == 'PyAudioIO')
    env = {'Optional': Optional, 'threading': threading, 'deque': deque,
           'pyaudio': SimpleNamespace(Stream=object), 'logger': SimpleNamespace(info=lambda *args: None)}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), str(source), 'exec'), env)
    audio = env['PyAudioIO'].__new__(env['PyAudioIO'])
    closed = []
    class Stream:
        def stop_stream(self): raise OSError('failed')
        def close(self): closed.append(True)
    audio._input_stream, audio._output_stream = Stream(), Stream()
    audio._running = True
    audio._playback_thread = audio._capture_thread = None
    audio._playback_lock = threading.Lock(); audio._capture_lock = threading.Lock()
    audio._playback_buffer = deque(); audio._capture_queue = deque()
    audio.stop()
    assert closed == [True, True] and not audio._running


def test_pyaudio_init_failure_does_not_crash_startup_and_retries_later():
    import threading
    from collections import deque
    from typing import Optional
    source = Path(__file__).resolve().parents[1] / 'app/webrtc_manager.py'
    tree = ast.parse(source.read_text())
    cls = next(c for c in tree.body if isinstance(c, ast.ClassDef) and c.name == 'PyAudioIO')
    attempts = {'count': 0}
    class FakePA:
        def get_device_count(self): return 1
        def get_device_info_by_index(self, i):
            return {'name': 'USB Mic', 'maxInputChannels': 1, 'maxOutputChannels': 0}
    def make_pa():
        attempts['count'] += 1
        if attempts['count'] == 1:
            raise OSError('audio driver unavailable at boot')
        return FakePA()
    env = {'Optional': Optional, 'threading': threading, 'deque': deque,
           'pyaudio': SimpleNamespace(PyAudio=make_pa, Stream=object),
           'logger': SimpleNamespace(warning=lambda *a: None, error=lambda *a: None, info=lambda *a: None)}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), str(source), 'exec'), env)
    audio = env['PyAudioIO']()
    assert audio.pa is None
    devices = audio.enumerate_devices()
    assert devices == {'inputs': [{'index': 0, 'name': 'USB Mic'}], 'outputs': []}
    assert audio.pa is not None


def test_pre_session_ice_candidates_buffered_replayed_and_cleared_on_end():
    source = Path(__file__).resolve().parents[1] / 'app/webrtc_manager.py'
    tree = ast.parse(source.read_text())
    wanted = {'_create_voice_session', '_handle_voice_ice', '_end_voice_async'}
    methods = [n for c in tree.body if isinstance(c, ast.ClassDef) and c.name == 'WebRTCManager'
               for n in c.body if isinstance(n, ast.AsyncFunctionDef) and n.name in wanted]
    replayed = []
    class Session:
        def __init__(self, *args): pass
        async def create(self): pass
        async def add_ice(self, data): replayed.append(data)
        async def close(self): pass
    class Audio:
        _running = True
        def stop(self): self._running = False
    env = {'VoicePeerSession': Session, 'ice_server_settings': lambda: [], 'asyncio': asyncio,
           'CALL_STATE_IDLE': 'idle', 'logger': SimpleNamespace(info=lambda *a: None)}
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])), str(source), 'exec'), env)
    manager = SimpleNamespace(
        _voice_peers={}, _pending_ice={}, audio_io=Audio(),
        input_device_index=None, output_device_index=None, remote_volume=0.8,
        _on_peer_ice=None, _on_voice_state=None, get_peer_public_key=lambda peer: 'key',
        _lifecycle=SimpleNamespace(matches=lambda peer, cid: (peer, cid) == ('peer1', 'call1'), idle=lambda: True),
        screen=SimpleNamespace(is_sharing=False), call_state='calling',
    )
    async def run():
        await env['_handle_voice_ice'](manager, 'peer1', 'call1', {'candidate': 'early1'})
        await env['_handle_voice_ice'](manager, 'other', 'wrong', {'candidate': 'ignored'})
        assert len(manager._pending_ice[('peer1', 'call1')]) == 1
        assert ('other', 'wrong') not in manager._pending_ice
        await env['_create_voice_session'](manager, 'peer1', 'call1')
        assert replayed == [{'candidate': 'early1'}]
        assert ('peer1', 'call1') not in manager._pending_ice
        manager._pending_ice[('peer1', 'call1')] = [{'candidate': 'leftover'}]
        await env['_end_voice_async'](manager, 'peer1', 'call1')
        assert ('peer1', 'call1') not in manager._pending_ice
    asyncio.run(run())


def test_settings_refresh_updates_account_fingerprint_and_audio_combos():
    source = Path(__file__).resolve().parents[1] / 'app/windows/settings_screen.py'
    tree = ast.parse(source.read_text())
    wanted = {'_populate_audio_combos', 'refresh'}
    methods = [n for c in tree.body if isinstance(c, ast.ClassDef) and c.name == 'SettingsScreen'
               for n in c.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    class Combo:
        def __init__(self): self.items, self.blocked, self.index = [], [], 0
        def blockSignals(self, flag): self.blocked.append(flag)
        def clear(self): self.items.clear()
        def addItem(self, label, data): self.items.append((label, data))
        def findData(self, val):
            for idx, (_, d) in enumerate(self.items):
                if d == val: return idx
            return -1
        def setCurrentIndex(self, idx): self.index = idx
    state = SimpleNamespace(username='alice', device_name='Linux Laptop', device_id='dev-42')
    crypto = SimpleNamespace(get_fingerprint=lambda: 'AA:BB:CC')
    rtc = SimpleNamespace(
        input_device_index=3, output_device_index=7,
        get_audio_devices=lambda: {'inputs': [{'index': 3, 'name': 'Ext Mic'}],
                                   'outputs': [{'index': 7, 'name': 'Headphones'}]},
    )
    env = {'state': state, 'crypto': crypto, 'rtc': rtc}
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])), str(source), 'exec'), env)
    Screen = type('Screen', (), {name: env[name] for name in wanted})
    screen = Screen()
    labels = {}
    for attr in ('_username_value', '_device_name_value', '_device_id_value', '_fp_box'):
        setattr(screen, attr, SimpleNamespace(setText=lambda text, a=attr: labels.__setitem__(a, text)))
    screen.mic_combo = Combo(); screen.spk_combo = Combo()
    screen.refresh()
    assert labels['_username_value'] == '@alice'
    assert labels['_device_name_value'] == 'Linux Laptop'
    assert labels['_device_id_value'] == 'dev-42'
    assert 'AA:BB:CC' in labels['_fp_box']
    assert screen.mic_combo.index == 1 and screen.spk_combo.index == 1
    assert screen.mic_combo.blocked == [True, False] and screen.spk_combo.blocked == [True, False]
