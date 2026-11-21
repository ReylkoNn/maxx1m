"""Validate untrusted decrypted voice data before allocating an audio stream."""
import io
import wave

# Downloaded ciphertext is limited separately; keep an independent plaintext cap.
MAX_VOICE_WAV_BYTES = 21 * 1024 * 1024
MIN_SAMPLE_RATE = 8000
MAX_SAMPLE_RATE = 192000


def open_voice_wave(data):
    """Open a bounded PCM WAV; caller owns and must close the returned reader.

    This checks inexpensive structural bounds, not complete audio correctness
    or platform audio-driver behavior. Refuse rather than allocate streams from
    implausible channel/rate/width/frame headers.
    """
    if not isinstance(data, bytes) or not data or len(data) > MAX_VOICE_WAV_BYTES:
        raise ValueError('Invalid voice size')
    reader = None
    try:
        reader = wave.open(io.BytesIO(data), 'rb')
        channels, width = reader.getnchannels(), reader.getsampwidth()
        rate, frames = reader.getframerate(), reader.getnframes()
        if (channels not in (1, 2) or width not in (1, 2, 3, 4)
                or not MIN_SAMPLE_RATE <= rate <= MAX_SAMPLE_RATE
                or frames <= 0 or frames * channels * width > len(data)
                or reader.getcomptype() != 'NONE'):
            raise ValueError('Unsupported or truncated voice format')
        remaining = frames
        frame_size = channels * width
        while remaining:
            count = min(remaining, 65536 // frame_size)
            chunk = reader.readframes(count)
            if len(chunk) != count * frame_size:
                raise ValueError('Truncated voice samples')
            remaining -= count
        reader.rewind()
        return reader
    except Exception:
        if reader is not None:
            reader.close()
        raise
