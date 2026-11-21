import io
import struct
import wave
import pytest
from app.voice_format import open_voice_wave, MAX_VOICE_WAV_BYTES


def wav(channels=1,width=2,rate=16000,frames=10):
    buf=io.BytesIO()
    with wave.open(buf,'wb') as writer:
        writer.setnchannels(channels); writer.setsampwidth(width); writer.setframerate(rate)
        writer.writeframes(b'\0'*(channels*width*frames))
    return buf.getvalue()


def test_valid_mono_and_stereo_wav():
    for data in (wav(),wav(channels=2,width=4,rate=48000)):
        with open_voice_wave(data) as reader:
            assert reader.getnframes()==10 and reader.readframes(10)


@pytest.mark.parametrize('data', [wav(channels=3),wav(rate=4000),wav(rate=384000),wav(frames=0),
                                 b'garbage', b'a'*(MAX_VOICE_WAV_BYTES+1)])
def test_invalid_formats_rejected_before_audio_open(data):
    with pytest.raises((ValueError,wave.Error,EOFError)): open_voice_wave(data)


def test_forged_length_cannot_trigger_large_audio_allocation():
    data=bytearray(wav())
    # data chunk claims 2GB, but its actual data ends after 20 bytes.
    offset=data.index(b'data')
    data[offset+4:offset+8]=struct.pack('<I',2**31)
    with pytest.raises(ValueError): open_voice_wave(bytes(data))


def test_truncated_pcm_data_with_plausible_header_is_rejected():
    data=wav(frames=10)[:-6]
    with pytest.raises(ValueError, match='Truncated'): open_voice_wave(data)
