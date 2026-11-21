"""Regression tests for Package #9 desktop security & resilience hardening:
- MainScreen._handle_decrypted_payload bounds (depth, RecursionError, NaN/Infinity, text/caption/reply sizes)
- SignalCrypto & VoicePeerSession SDP/ICE validation + 0-sample AudioFrame survival without amplitude logging
- VoiceCache & history_activation POSIX 0700/0600 modes and symlink refusal + CryptoManager key/file bounds
"""
import ast
import asyncio
import base64
import fractions
import json
import logging
import os
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Optional

import nacl.secret
import nacl.utils
import pytest

from app import history_activation, voice_cache
from app.crypto_box import CryptoManager


def _extract_main_screen_method(name: str, namespace: dict):
    source = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "MainScreen")
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), str(source), "exec"), namespace)
    return namespace[name]


def test_decrypted_chat_payload_rejects_deep_nesting_nan_and_oversized_fields():
    env = {
        "json": json,
        "state": SimpleNamespace(username="alice", current_chat_username=None),
        "storage": SimpleNamespace(
            save_message=lambda *a, **kw: pytest.fail("malformed message must not be persisted"),
            delete_incoming_message=lambda *a, **kw: pytest.fail("malformed delete must not run"),
        ),
    }
    handle = _extract_main_screen_method("_handle_decrypted_payload", env)
    screen = SimpleNamespace(window=lambda: SimpleNamespace(isActiveWindow=lambda: True))

    # 1. Extreme bracket nesting must NOT raise RecursionError — returns False cleanly
    deep_brackets = "[" * 1800 + "]" * 1800
    assert handle(screen, "bob", deep_brackets, "sig-1") is False

    # 2. Dict nesting > 16 rejected
    nested: dict = {"leaf": "x"}
    for _ in range(18):
        nested = {"child": nested}
    nested_msg = json.dumps({"type": "text", "text": "ok", "msg_id": "m-deep", "extra": nested})
    assert handle(screen, "bob", nested_msg, "sig-2") is False

    # 3. Non-finite JSON constants (NaN / Infinity) rejected
    assert handle(screen, "bob", '{"type":"voice","duration":NaN,"msg_id":"m-nan"}', "sig-3") is False
    assert handle(screen, "bob", '{"type":"voice","duration":Infinity,"msg_id":"m-inf"}', "sig-4") is False

    # 4. Oversized text, caption, and reply_to fields rejected
    assert handle(
        screen,
        "bob",
        json.dumps({"type": "text", "text": "t" * (256 * 1024 + 1), "msg_id": "m-big"}),
        "sig-5",
    ) is False
    assert handle(
        screen,
        "bob",
        json.dumps({"type": "image", "caption": "c" * 8193, "msg_id": "m-cap"}),
        "sig-6",
    ) is False
    assert handle(
        screen,
        "bob",
        json.dumps({
            "type": "text",
            "text": "ok",
            "msg_id": "m-rep",
            "reply_to": {"msg_id": "r1", "text": "r" * 4097, "sender": "bob"},
        }),
        "sig-7",
    ) is False
    assert handle(
        screen,
        "bob",
        json.dumps({
            "type": "text",
            "text": "ok",
            "msg_id": "m-sender",
            "reply_to": {"msg_id": "r1", "text": "hi", "sender": "s" * 65},
        }),
        "sig-8",
    ) is False


def test_webrtc_signal_bounds_sdp_ice_validation_and_zero_sample_frame_survival(caplog):
    aiortc = pytest.importorskip("aiortc")
    np = pytest.importorskip("numpy")
    from aiortc import (
        MediaStreamTrack,
        RTCConfiguration,
        RTCIceCandidate,
        RTCIceServer,
        RTCPeerConnection,
        RTCSessionDescription,
    )
    from aiortc.mediastreams import MediaStreamError
    from aiortc.sdp import candidate_from_sdp, candidate_to_sdp
    from av.audio.frame import AudioFrame
    import app.crypto_box as crypto_box_mod

    source = Path(__file__).resolve().parents[1] / "app/webrtc_manager.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    wanted = {"SignalCrypto", "AudioCaptureTrack", "VoicePeerSession"}
    nodes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name in wanted]
    log = logging.getLogger("test.webrtc.pkg9")
    env = dict(
        asyncio=asyncio,
        fractions=fractions,
        json=json,
        np=np,
        AudioFrame=AudioFrame,
        MediaStreamTrack=MediaStreamTrack,
        MediaStreamError=MediaStreamError,
        RTCPeerConnection=RTCPeerConnection,
        RTCSessionDescription=RTCSessionDescription,
        RTCIceCandidate=RTCIceCandidate,
        RTCConfiguration=RTCConfiguration,
        RTCIceServer=RTCIceServer,
        candidate_from_sdp=candidate_from_sdp,
        candidate_to_sdp=candidate_to_sdp,
        Callable=Callable,
        Optional=Optional,
        PyAudioIO=object,
        ice_server_settings=lambda: [],
        logger=log,
        RATE=48000,
        CHANNELS=1,
        CHUNK_SAMPLES=960,
    )
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source), "exec"), env)
    SignalCrypto = env["SignalCrypto"]
    VoicePeerSession = env["VoicePeerSession"]

    # 1. SignalCrypto bounds, NaN rejection, and depth limit
    sender, receiver = CryptoManager(), CryptoManager()
    sender.generate_new_keypair()
    receiver.generate_new_keypair()
    saved_priv, saved_pub = crypto_box_mod.crypto.private_key, crypto_box_mod.crypto.public_key
    try:
        crypto_box_mod.crypto.private_key = sender.private_key
        crypto_box_mod.crypto.public_key = sender.public_key
        enc_ok, sig_ok = SignalCrypto.encrypt_signal(
            {"signal_type": "ice", "channel": "voice", "candidate": "c"},
            receiver.get_public_key_b64(),
        )
        raw_nan = sender.encrypt_message('{"signal_type":"ice","val":NaN}', receiver.get_public_key_b64())
        deep_obj: dict = {"leaf": 1}
        for _ in range(18):
            deep_obj = {"next": deep_obj}
        raw_deep = sender.encrypt_message(json.dumps(deep_obj), receiver.get_public_key_b64())

        crypto_box_mod.crypto.private_key = receiver.private_key
        crypto_box_mod.crypto.public_key = receiver.public_key
        assert SignalCrypto.decrypt_signal(enc_ok, sig_ok, sender.get_public_key_b64()) == {
            "signal_type": "ice",
            "channel": "voice",
            "candidate": "c",
        }
        assert SignalCrypto.decrypt_signal(raw_nan["encrypted_blob"], raw_nan["signature"], sender.get_public_key_b64()) is None
        assert SignalCrypto.decrypt_signal(raw_deep["encrypted_blob"], raw_deep["signature"], sender.get_public_key_b64()) is None
        assert SignalCrypto.decrypt_signal("x" * (128 * 1024 + 1), sig_ok, sender.get_public_key_b64()) is None
    finally:
        crypto_box_mod.crypto.private_key, crypto_box_mod.crypto.public_key = saved_priv, saved_pub

    # 2. VoicePeerSession SDP/ICE validation + 0-sample AudioFrame survival without amplitude leaks
    async def exercise():
        written_pcm: list[bytes] = []

        class StubAudio:
            remote_volume = 1.0

            def read(self):
                return b"\x01"  # Odd 1-byte buffer: AudioCaptureTrack must safely substitute silence

            def write(self, pcm: bytes):
                written_pcm.append(pcm)

        received_ice = []

        class StubPC:
            remoteDescription = True

            async def setRemoteDescription(self, desc):
                self.remoteDescription = desc

            async def addIceCandidate(self, cand):
                received_ice.append(cand)

        session = VoicePeerSession("peer-dev", StubAudio(), lambda *a: None, lambda *a: None, relay_only=False)
        session.pc = StubPC()

        for bad_sdp in ("", "   ", None, 123, "v=0\r\n" + "a" * (64 * 1024)):
            with pytest.raises(ValueError):
                await session.handle_offer(bad_sdp)
            with pytest.raises(ValueError):
                await session.handle_answer(bad_sdp)

        valid_cand = "candidate:0 1 udp 2122252543 192.0.2.1 12345 typ host"
        await session.add_ice({"candidate": valid_cand, "sdpMid": "0", "sdpMLineIndex": True})
        await session.add_ice({"candidate": valid_cand, "sdpMid": "0", "sdpMLineIndex": -1})
        await session.add_ice({"candidate": valid_cand, "sdpMid": "0", "sdpMLineIndex": 99})
        await session.add_ice({"candidate": valid_cand, "sdpMid": "x" * 65, "sdpMLineIndex": 0})
        assert received_ice == []

        await session.add_ice({"candidate": valid_cand, "sdpMid": "0", "sdpMLineIndex": 0})
        assert len(received_ice) == 1

        # Zero-sample frame followed by real frame must NOT crash _play_loop or log min=/max=/rms=
        class FakeFrame:
            def __init__(self, samples: list[int]):
                self._arr = np.array(samples, dtype=np.int16)
                self.format = SimpleNamespace(is_planar=True)
                self.sample_rate = 48000

            def to_ndarray(self):
                return self._arr

        class FakeTrack:
            def __init__(self):
                self._items = [FakeFrame([]), FakeFrame([1200, -1200, 500, -500])]

            async def recv(self):
                if self._items:
                    return self._items.pop(0)
                raise MediaStreamError

        with caplog.at_level(logging.INFO, logger="test.webrtc.pkg9"):
            await session._play_loop(FakeTrack())
            tx_track = env["AudioCaptureTrack"](StubAudio())
            out_frame = await tx_track.recv()
            assert out_frame.samples == 960

        assert len(written_pcm) == 1 and len(written_pcm[0]) == 8
        for rec in caplog.records:
            msg = rec.getMessage()
            assert "rms=" not in msg and "min=" not in msg and "max=" not in msg

    asyncio.run(exercise())


def test_voice_cache_history_catalog_modes_symlinks_and_crypto_bounds(tmp_path, monkeypatch):
    keyring_store: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(voice_cache.keyring, "get_password", lambda s, k: keyring_store.get((s, k)))
    monkeypatch.setattr(voice_cache.keyring, "set_password", lambda s, k, v: keyring_store.__setitem__((s, k), v))

    cache_dir = tmp_path / "voice_cache"
    vc = voice_cache.VoiceCache(cache_dir=cache_dir)
    grp = voice_cache.message_scope("alice", "https://node.test", "bob", "m1")
    ast_key = voice_cache.asset_scope("fid-1", "skey-1")
    assert vc.save(grp, ast_key, b"RIFF-fake-wav") is True
    assert vc.load(grp, ast_key) == b"RIFF-fake-wav"

    entry_file = cache_dir / f"v2_{grp}_{ast_key}.bin"
    if os.name == "posix":
        assert stat.S_IMODE(os.lstat(cache_dir).st_mode) == 0o700
        assert stat.S_IMODE(os.lstat(entry_file).st_mode) == 0o600

        # Symlinked cache entry is refused on both load() and save(), and ignored by get_cache_size_mb()
        outside = tmp_path / "outside_secret.bin"
        outside.write_bytes(entry_file.read_bytes())
        sym_grp = voice_cache.message_scope("alice", "https://node.test", "bob", "m2")
        sym_path = cache_dir / f"v2_{sym_grp}_{ast_key}.bin"
        sym_path.symlink_to(outside)
        assert vc.load(sym_grp, ast_key) is None
        assert vc.save(sym_grp, ast_key, b"overwrite-attempt") is False

    # history_activation catalog permissions & symlink rejection
    cat_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    cat_path = tmp_path / "history_catalog.enc"
    chats = {"bob": {"db_id": str(uuid.uuid4()), "source_hash": "a" * 64}}
    history_activation.write_catalog(cat_path, cat_key, "alice", chats)
    assert history_activation.read_catalog(cat_path, cat_key, "alice") == chats
    if os.name == "posix":
        assert stat.S_IMODE(os.lstat(cat_path).st_mode) == 0o600
        sym_cat = tmp_path / "sym_catalog.enc"
        sym_cat.symlink_to(cat_path)
        with pytest.raises(ValueError):
            history_activation.read_catalog(sym_cat, cat_key, "alice")
        with pytest.raises(ValueError):
            history_activation.write_catalog(sym_cat, cat_key, "alice", chats)

    # CryptoManager strict 32-byte key/file validation and clear()
    cm = CryptoManager()
    with pytest.raises(ValueError):
        cm.load_private_key(base64.b64encode(b"short").decode("ascii"))
    cm.generate_new_keypair()
    fkey = cm.generate_file_key()
    enc = cm.encrypt_file(b"hello-attachment", fkey)
    assert cm.decrypt_file(enc, fkey) == b"hello-attachment"
    with pytest.raises(ValueError):
        cm.decrypt_file(b"tiny", fkey)
    with pytest.raises(ValueError):
        cm.encrypt_file(b"data", base64.b64encode(b"bad-len").decode("ascii"))
    cm.clear()
    assert cm.private_key is None and cm.public_key is None
    with pytest.raises(ValueError):
        cm.get_public_key_b64()
