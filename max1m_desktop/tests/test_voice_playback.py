"""Single bounded playback worker, including blocked simulated audio drivers."""
import ast
import io
import threading
import time
import wave
from pathlib import Path
from types import SimpleNamespace
import pytest
from app.voice_playback import VoicePlayback


def wav(frames=4096):
    data=io.BytesIO()
    with wave.open(data,'wb') as out:
        out.setnchannels(1); out.setsampwidth(2); out.setframerate(16000)
        out.writeframes(b'\0\0'*frames)
    return data.getvalue()

class Audio:
    def __init__(self,block_first=False):
        self.entered=threading.Event(); self.release=threading.Event(); self.block_first=block_first
        self.opens=[]; self.writes=[]; self.closed=[]; self.active=0; self.peak=0
    def get_format_from_width(self,width): return width
    def open(self,**kw):
        index=len(self.opens); self.opens.append(kw); self.active+=1; self.peak=max(self.peak,self.active)
        audio=self
        class Stream:
            def write(self,data):
                audio.writes.append((index,len(data))); audio.entered.set()
                if index==0 and audio.block_first: assert audio.release.wait(5)
            def stop_stream(self): pass
            def close(self): audio.closed.append(index); audio.active-=1
        return Stream()


def test_many_seeks_coalesce_to_one_pending_playback():
    audio=Audio(block_first=True); events=[]; done=threading.Event()
    player=VoicePlayback(lambda:(audio,None),lambda *x:events.append(('progress',*x)),
                         lambda gen:(events.append(('done',gen)),done.set()))
    first=player.start(wav())
    try:
        assert audio.entered.wait(2)
        thread=player._thread
        for i in range(1000): last=player.start(wav(32), (i%10)/10)
        assert player._thread is thread and len(audio.opens)==1 and player._pending[0]==last
    finally: audio.release.set()
    assert done.wait(3)
    assert player.stop_and_wait(1)
    assert len(audio.opens)==2 and audio.peak==1 and audio.closed==[0,1]
    assert ('done',first) not in events and ('done',last) in events


def test_blocked_audio_shutdown_refuses_until_driver_returns():
    audio=Audio(block_first=True); completed=[]
    player=VoicePlayback(lambda:(audio,None),lambda *args:None,lambda gen:completed.append(gen))
    player.start(wav())
    try:
        assert audio.entered.wait(2)
        assert not player.stop_and_wait(.02)
        assert player._thread is not None
    finally: audio.release.set()
    assert player.stop_and_wait(2)
    assert not completed and audio.closed==[0]


def test_validation_failure_never_opens_audio_and_reports_completion():
    audio=Audio(); done=threading.Event(); result=[]
    player=VoicePlayback(lambda:(audio,None),lambda *args:None,lambda gen:(result.append(gen),done.set()))
    generation=player.start(b'not a wav')
    assert done.wait(2) and player.stop_and_wait(1)
    assert result==[generation] and not audio.opens
    for progress in (-1,2,float('nan'),float('inf')):
        with pytest.raises(ValueError): player.start(wav(),progress)


def test_stop_stream_failure_still_closes_device():
    done=threading.Event(); closed=[]
    class Stream:
        def write(self,data): pass
        def stop_stream(self): raise OSError('driver failure')
        def close(self): closed.append(True)
    device=SimpleNamespace(get_format_from_width=lambda x:x,open=lambda **kw:Stream())
    player=VoicePlayback(lambda:(device,None),lambda *args:None,lambda gen:done.set())
    player.start(wav(2)); assert done.wait(2) and player.stop_and_wait(1)
    assert closed == [True]


def test_ui_ignores_stale_playback_callbacks():
    path=Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    tree=ast.parse(path.read_text()); names={'_stop_voice_playback','_start_playback','_seek_voice_message',
        '_on_voice_playback_finished','_on_voice_progress_update'}
    nodes=[n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='MainScreen'
           for n in c.body if isinstance(n,ast.FunctionDef) and n.name in names]
    env={'MessageBubble':object}; exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(path),'exec'),env)
    calls=[]
    class Bubble:
        def __init__(self,name): self.name=name; self._voice_data=b'raw'; self._is_playing=False
        def set_playing(self,value): self._is_playing=value; calls.append((self.name,'playing',value))
        def update_playback_progress(self,value): calls.append((self.name,'progress',value))
    class Player:
        generation=0
        def start(self,data,progress): self.generation+=1; return self.generation
        def stop(self): self.generation+=1; return self.generation
    Screen=type('Screen',(),{name:env[name] for name in names})
    screen=Screen(); screen._voice_playback=Player(); screen._current_playing_bubble=None; screen._voice_playback_generation=0; screen._voice_request_serial=0
    first,second=Bubble('first'),Bubble('second')
    screen._start_playback(first,b'raw'); old=screen._voice_playback_generation
    screen._start_playback(second,b'raw'); new=screen._voice_playback_generation
    before=calls[:]
    screen._on_voice_progress_update(old,.5); screen._on_voice_playback_finished(old)
    assert calls==before and screen._current_playing_bubble is second
    screen._on_voice_progress_update(new,.7); screen._on_voice_playback_finished(new)
    assert calls[-3:]==[('second','progress',.7),('second','playing',False),('second','progress',0)]
    assert screen._current_playing_bubble is None


def test_seeking_invalidates_pending_voice_download_autoplay():
    path=Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    tree=ast.parse(path.read_text()); names={'_seek_voice_message','_on_voice_download_finished'}
    nodes=[n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='MainScreen'
           for n in c.body if isinstance(n,ast.FunctionDef) and n.name in names]
    cached=[]; started=[]
    env={'MessageBubble':object,'DownloadFileWorker':object,
         'crypto':SimpleNamespace(decrypt_file=lambda data,key:b'decoded'),
         'voice_cache':SimpleNamespace(save=lambda *args:cached.append(args))}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(path),'exec'),env)
    Screen=type('Screen',(),{name:env[name] for name in names})
    screen=Screen(); screen._voice_request_serial=1
    screen._finish_media_download=lambda worker:True
    screen._start_playback=lambda bubble,data,progress:started.append((bubble,data,progress))
    screen._play_voice_message=lambda *args,**kw:pytest.fail('stale download must not autoplay')
    active=SimpleNamespace(_voice_data=b'current')
    delayed=SimpleNamespace(parent=lambda:True,msg_label=SimpleNamespace(setVisible=lambda value:None),
                            set_voice_data=lambda data:pytest.fail('stale download must not change widget'))
    worker=SimpleNamespace(bubble=delayed,secret_key='key',voice_group='group',voice_asset='asset',voice_request_serial=1)
    screen._seek_voice_message(active,.5)
    screen._on_voice_download_finished(True,b'encrypted',worker)
    assert screen._voice_request_serial==2 and started==[(active,b'current',.5)]
    assert cached==[('group','asset',b'decoded')]


def test_real_worker_queues_widget_updates_on_qcore_thread():
    from PySide6.QtCore import QObject, Signal, QCoreApplication, QEventLoop, QTimer
    app=QCoreApplication.instance() or QCoreApplication([])
    gui_thread=threading.get_ident(); events=[]
    path=Path(__file__).resolve().parents[1]/'app/windows/main_screen.py'
    tree=ast.parse(path.read_text()); names={'_stop_voice_playback','_start_playback',
                                             '_on_voice_playback_finished','_on_voice_progress_update'}
    nodes=[n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='MainScreen'
           for n in c.body if isinstance(n,ast.FunctionDef) and n.name in names]
    env={'MessageBubble':object}; exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(path),'exec'),env)
    class Screen(QObject):
        progress=Signal(object,float)
        finished=Signal(object)
        _stop_voice_playback=env['_stop_voice_playback']
        _start_playback=env['_start_playback']
        _on_voice_playback_finished=env['_on_voice_playback_finished']
        _on_voice_progress_update=env['_on_voice_progress_update']
    class Bubble:
        def set_playing(self,value): events.append(('playing',value,threading.get_ident()))
        def update_playback_progress(self,value): events.append(('progress',value,threading.get_ident()))
    screen=Screen(); audio=Audio(); loop=QEventLoop()
    screen._voice_request_serial=0; screen._current_playing_bubble=None; screen._voice_playback_generation=0
    screen._voice_playback=VoicePlayback(lambda:(audio,None),screen.progress.emit,screen.finished.emit)
    screen.progress.connect(screen._on_voice_progress_update)
    screen.finished.connect(screen._on_voice_playback_finished)
    screen.finished.connect(lambda gen:QTimer.singleShot(0,loop.quit))
    screen._start_playback(Bubble(),wav())
    QTimer.singleShot(4000,loop.quit); loop.exec()
    assert screen._voice_playback.stop_and_wait(1)
    assert events and events[-2][:2]==('playing',False)
    assert all(event[-1]==gui_thread for event in events)


def test_stop_during_blocked_open_closes_stream_without_playing():
    entered=threading.Event(); release=threading.Event(); closed=[]; played=[]; finished=[]
    class Stream:
        def write(self,data): played.append(data)
        def stop_stream(self): pass
        def close(self): closed.append(True)
    class Device:
        def get_format_from_width(self,width): return width
        def open(self,**kw):
            entered.set(); assert release.wait(5); return Stream()
    player=VoicePlayback(lambda:(Device(),None),lambda *args:None,lambda gen:finished.append(gen))
    player.start(wav())
    try:
        assert entered.wait(2)
        assert not player.stop_and_wait(.02)
    finally: release.set()
    assert player.stop_and_wait(2)
    assert closed==[True] and not played and not finished
