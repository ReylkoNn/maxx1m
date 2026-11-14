"""Bounded, generation-scoped voice playback without worker-side Qt access."""
import math
import threading
import time

from app.voice_format import MAX_VOICE_WAV_BYTES, open_voice_wave


class VoicePlayback:
    """One native thread and at most one replaceable pending playback.

    Audio-driver operations can block; cancellation takes effect between calls.
    Progress and completion callbacks execute on the worker and must marshal to
    the GUI. The callbacks carry a generation and must discard stale events.
    """
    def __init__(self, audio_device, on_progress, on_finished):
        self._audio_device = audio_device
        self._on_progress = on_progress
        self._on_finished = on_finished
        self._lock = threading.Lock()
        self._generation = 0
        self._pending = None
        self._thread = None

    def start(self, data, progress=0.0):
        if not isinstance(data, bytes) or not data or len(data) > MAX_VOICE_WAV_BYTES:
            raise ValueError('Invalid voice size')
        if not isinstance(progress, (int, float)) or not math.isfinite(progress) or not 0 <= progress <= 1:
            raise ValueError('Invalid voice position')
        with self._lock:
            self._generation += 1
            generation = self._generation
            self._pending = (generation, data, float(progress))
            if self._thread is None:
                thread = threading.Thread(target=self._run, name='Voice playback', daemon=True)
                self._thread = thread
                try:
                    thread.start()
                except BaseException:
                    self._thread = None
                    self._pending = None
                    raise
            return generation

    def stop(self):
        with self._lock:
            self._generation += 1
            self._pending = None
            return self._generation

    def stop_and_wait(self, timeout=0.3):
        with self._lock:
            self._generation += 1
            self._pending = None
            thread = self._thread
        if thread is not None:
            thread.join(timeout)
            return not thread.is_alive()
        return True

    def _current(self, generation):
        with self._lock:
            return self._generation == generation

    def _run(self):
        while True:
            with self._lock:
                job, self._pending = self._pending, None
                if job is None:
                    # No callbacks or device operations occur after this point.
                    self._thread = None
                    return
            generation, data, start_pos = job
            stream = None
            try:
                if not self._current(generation):
                    continue
                with open_voice_wave(data) as wf:
                    if not self._current(generation):
                        continue
                    sample_rate, channels, sample_width = wf.getframerate(), wf.getnchannels(), wf.getsampwidth()
                    total_frames = wf.getnframes()
                    start_frame = int(start_pos * total_frames)
                    wf.setpos(start_frame)
                    if start_frame == total_frames:
                        continue
                    pa, device_index = self._audio_device()
                    if not self._current(generation):
                        continue
                    audio_format = pa.get_format_from_width(sample_width)
                    if not self._current(generation):
                        continue
                    stream = pa.open(format=audio_format, channels=channels,
                                     rate=sample_rate, output=True, output_device_index=device_index)
                    frames_played = start_frame
                    last_update = 0.0
                    while self._current(generation):
                        chunk = wf.readframes(1024)
                        if not chunk or not self._current(generation):
                            break
                        stream.write(chunk)  # A driver may block indefinitely here.
                        frames_played += len(chunk) // (channels * sample_width)
                        now = time.monotonic()
                        if now - last_update >= 0.1 and self._current(generation):
                            self._on_progress(generation, min(1.0, frames_played / total_frames))
                            last_update = now
            except Exception as exc:
                # Do not log untrusted data or exception strings from drivers.
                print(f'[VOICE] Ошибка воспроизведения: {type(exc).__name__}')
            finally:
                if stream is not None:
                    try:
                        stream.stop_stream()
                    except Exception:
                        pass
                    try:
                        stream.close()
                    except Exception:
                        pass
                if self._current(generation):
                    try:
                        self._on_finished(generation)
                    except Exception as exc:
                        print(f'[VOICE] Ошибка завершения воспроизведения: {type(exc).__name__}')
