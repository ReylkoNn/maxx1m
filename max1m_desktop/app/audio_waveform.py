"""Bounded sampling of WAV data for a small visual waveform."""
import io
import struct
import wave


def waveform_bars(wav_data, bar_count=30, frames_per_bar=512):
    if not 1 <= bar_count <= 100 or not 1 <= frames_per_bar <= 2048:
        raise ValueError("Invalid waveform sampling limits")
    with wave.open(io.BytesIO(wav_data), 'rb') as wav:
        frames, channels, width = wav.getnframes(), wav.getnchannels(), wav.getsampwidth()
        if not frames or not 1 <= channels <= 8 or width not in (1, 2):
            raise ValueError("Unsupported WAV")
        bars = []
        for i in range(bar_count):
            start = (i * frames) // bar_count
            wav.setpos(start)
            chunk = wav.readframes(min(frames_per_bar, frames - start))
            if width == 2:
                values = struct.unpack('<' + 'h' * (len(chunk) // 2), chunk)
            else:
                values = (v - 128 for v in chunk)
            # Each sample tuple is bounded by frames_per_bar * 8 channels.
            samples = tuple(values)[::channels]
            bars.append((sum(v * v for v in samples) / len(samples)) ** 0.5 if samples else 0)
        maximum = max(bars) or 1
        return [v / maximum for v in bars]
