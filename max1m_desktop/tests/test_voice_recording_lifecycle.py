"""Recording lifecycle with real threads and a simulated blocking microphone."""
import ast
import io
import struct
import threading
import wave
from pathlib import Path
from types import SimpleNamespace
import pytest


def make_screen():
    path=Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    tree=ast.parse(path.read_text())
    names={'_start_voice_recording','_record_voice','_on_voice_recording_limit',
           '_on_voice_recording_error','_stop_voice_recording','_cancel_voice_recording','_on_voice_level_update'}
    nodes=[n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='MainScreen'
           for n in c.body if isinstance(n,ast.FunctionDef) and n.name in names]
    assert len(nodes)==len(names)
    warnings=[]; entered=threading.Event(); release=threading.Event(); sent=[]; emitted=[]
    class Stream:
        def __init__(self): self.closed=False
        def read(self,*a,**kw): entered.set(); release.wait(5); return b'\0\0'*1024
        def stop_stream(self): pass
        def close(self): self.closed=True
    stream=Stream()
    opened={}
    class PA:
        def open(self,**kw):
            opened.update(kw)
            return stream
        def terminate(self): pass
    class Signal:
        def emit(self,*args): emitted.append(args)
    state=SimpleNamespace(
        current_chat_type='ally', current_group_id=None, groups={},
        username='alice', server_url='https://server.test', device_id='alice-device', token='token',
    )
    env={'threading':threading,'pyaudio':SimpleNamespace(PyAudio=PA,paInt16=8),
         'struct':struct,'wave':wave,'io':io,'state':state,
         'rtc':SimpleNamespace(input_device_index=4), 'GROUP_CHAT_SEND_ENABLED':True,
         'capture_recipient':lambda state:'recipient', 'is_active_recipient':lambda state,context:True,
         'QMessageBox':SimpleNamespace(warning=lambda *args:warnings.append(args))}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(path),'exec'),env)
    class Base:
        def __init__(self):
            self._is_recording=False; self._voice_thread=None; self._voice_stream=None
            self._voice_cancelled=False; self._voice_frames=[]; self._voice_recording_generation=0
            self._voice_recording_error=Signal(); self._voice_recording_limit=Signal(); self._voice_level_signal=Signal()
            self.voice_recording_bar=SimpleNamespace(push_level=lambda rms:emitted.append(('level',rms)),
                _sec_timer=SimpleNamespace(stop=lambda:emitted.append('limit')),
                _rec_label=SimpleNamespace(setText=lambda text:None))
        def _show_voice_recording_bar(self): pass
        def _hide_voice_recording_bar(self): pass
        def _send_voice_message(self,*args): sent.append(args)
        def _send_group_attachment(self,*args,**kwargs): sent.append(('group',args,kwargs))
    Screen=type('Screen',(Base,),{name:env[name] for name in names})
    screen=Screen()
    screen.audio_open_kwargs=opened
    screen.test_state=state
    return screen,warnings,entered,release,stream,sent,emitted


def test_blocked_microphone_is_not_sent_or_reused_until_old_thread_stops():
    screen,warnings,entered,release,stream,sent,emitted=make_screen()
    screen._start_voice_recording()
    try:
        assert entered.wait(2)
        old_thread=screen._voice_thread
        screen._stop_voice_recording()
        assert old_thread.is_alive() and not sent and warnings
        screen._start_voice_recording()
        assert screen._voice_thread is old_thread and not screen._is_recording
    finally:
        release.set()
        screen._voice_thread.join(3)
    assert not screen._voice_thread.is_alive() and stream.closed and not screen._voice_frames
    assert not sent


def test_old_recording_signals_do_not_cancel_or_modify_new_recording():
    screen,warnings,entered,release,stream,sent,emitted=make_screen()
    screen._is_recording=True; screen._voice_recording_generation=2
    screen._on_voice_recording_error(1,'old error')
    screen._on_voice_recording_limit(1)
    screen._on_voice_level_update(1,.9)
    assert screen._is_recording and not warnings and not emitted
    screen._on_voice_level_update(2,.5)
    assert emitted==[('level',.5)]


def test_finished_recording_encodes_only_captured_frames():
    screen,warnings,entered,release,stream,sent,emitted=make_screen()
    screen._is_recording=True; screen._voice_recipient_context='recipient'
    screen._voice_frames=[b'\1\0'*1024 for _ in range(8)]
    screen._stop_voice_recording()
    assert len(sent)==1 and sent[0][2]=='recipient' and not warnings
    with wave.open(io.BytesIO(sent[0][0]),'rb') as reader:
        assert reader.getnframes()==8*1024 and reader.getframerate()==16000


def test_group_recording_pins_group_and_uses_selected_microphone():
    screen,warnings,entered,release,stream,sent,emitted=make_screen()
    screen.test_state.current_chat_type='group'
    screen.test_state.current_group_id='group-1'
    screen.test_state.groups={'group-1':{'archived':False}}
    screen._start_voice_recording()
    try:
        assert entered.wait(2)
        assert screen._voice_recipient_context==('group','group-1')
        assert screen.audio_open_kwargs['input_device_index']==4
        assert not warnings and not sent
    finally:
        screen._is_recording=False
        release.set()
        screen._voice_thread.join(3)
    assert stream.closed and not sent


def test_recorded_group_voice_message_uses_group_attachment_pipeline():
    screen,warnings,entered,release,stream,sent,emitted=make_screen()
    screen.test_state.current_chat_type='group'
    screen.test_state.current_group_id='group-1'
    screen.test_state.groups={'group-1':{'archived':False}}
    screen._voice_account_context=(
        screen.test_state.username, screen.test_state.server_url,
        screen.test_state.device_id, screen.test_state.token,
    )
    screen._voice_recipient_context=('group','group-1')
    screen._is_recording=True
    screen._voice_frames=[b'\x01\x00'*1024 for _ in range(8)]
    screen._stop_voice_recording()
    assert len(sent)==1 and sent[0][0]=='group'
    assert sent[0][1][0:1]==('group-1',)
    assert sent[0][1][2]=='voice'
    assert sent[0][2]['duration']==pytest.approx(8*1024/16000)
    assert not warnings
