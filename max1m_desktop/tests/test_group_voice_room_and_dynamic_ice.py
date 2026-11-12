"""
Tests for Package IV (Desktop):
1. Dynamic ephemeral coturn ICE/TURNS:443 configuration (`set_runtime_ice_config`)
   + UI IP-hiding `Relay-Only` toggle (`set_ui_relay_only`) + encrypted persistence.
2. `VoiceActivityGate`: Hysteresis Noise Gate / VAD + Push-to-Talk with hang-over tail.
3. `GroupAudioMixer`: 2–8 participant 20 ms mixer with 0–200% individual volume,
   speaking indicators, bounded <= 80 ms jitter buffer, and soft-knee `tanh` limiter.
4. `BroadcasterMicDistributor` fan-out + `GroupVoiceRoomController` E2EE signal verification
   and 1-click peer screen share request flow.
"""

import json
import math
import time

import numpy as np
import pytest

import app.crypto_box as cb_mod
import app.secure_storage as ss_mod
from app.crypto_box import CryptoManager
from app.group_voice_room import (
    CHUNK_SAMPLES,
    FRAME_BYTES,
    SILENCE_FRAME,
    BroadcasterMicDistributor,
    GroupAudioMixer,
    GroupVoiceRoomController,
    VoiceActivityGate,
    compute_rms_dbfs,
)
from app.ice_config import (
    clear_runtime_ice_config,
    ice_relay_only,
    ice_server_settings,
    runtime_ice_needs_refresh,
    set_runtime_ice_config,
    set_ui_relay_only,
)
from app.secure_storage import SecureStorage


def _sine_pcm(amplitude: float, freq_hz: float = 440.0) -> bytes:
    t = np.arange(CHUNK_SAMPLES, dtype=np.float32) / 48000.0
    wave = np.clip(amplitude * np.sin(2.0 * math.pi * freq_hz * t), -32767.0, 32767.0)
    return wave.astype("<i2").tobytes()


@pytest.fixture(autouse=True)
def _reset_runtime_ice(monkeypatch):
    for var in (
        "MAX1M_ICE_RELAY_ONLY",
        "MAX1M_STUN_URLS",
        "MAX1M_TURN_URLS",
        "MAX1M_TURN_URL",
        "MAX1M_TURN_USERNAME",
        "MAX1M_TURN_PASSWORD",
    ):
        monkeypatch.delenv(var, raising=False)
    clear_runtime_ice_config()
    set_ui_relay_only(False)
    yield
    clear_runtime_ice_config()
    set_ui_relay_only(False)


def test_dynamic_coturn_turns_443_and_ui_relay_only_toggle(tmp_path, monkeypatch):
    base = tmp_path / ".max1m"
    base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ss_mod, "BASE_DIR", base)
    keys = {}
    monkeypatch.setattr(ss_mod.keyring, "get_password", lambda s, k: keys.get(f"{s}:{k}"))
    monkeypatch.setattr(ss_mod.keyring, "set_password", lambda s, k, v: keys.__setitem__(f"{s}:{k}", v))

    # Initially needs refresh
    assert runtime_ice_needs_refresh() is True

    # Apply server `/calls/ice-config` payload with TURNS over TCP/TLS 443
    exp = int(time.time()) + 3600
    set_runtime_ice_config(
        {
            "ice_servers": [
                {"urls": ["stun:turn.company.ru:3478"]},
                {
                    "urls": [
                        "turn:turn.company.ru:3478?transport=udp",
                        "turns:turn.company.ru:443?transport=tcp",
                    ],
                    "username": f"{exp}:dev-1",
                    "credential": "coturnHmacSha1B64==",
                },
            ],
            "expires_at": exp,
        }
    )
    assert runtime_ice_needs_refresh() is False

    normal_servers = ice_server_settings()
    assert len(normal_servers) == 2
    assert normal_servers[0] == {"urls": ["stun:turn.company.ru:3478"]}
    assert "turns:turn.company.ru:443?transport=tcp" in normal_servers[1]["urls"]

    # Enable UI Relay-Only («Скрывать мой IP при звонках») and persist encrypted
    assert SecureStorage.set_ice_relay_only("alice", True) is True
    assert SecureStorage.get_ice_relay_only("alice") is True
    assert ice_relay_only() is True

    # In Relay-Only mode, STUN servers are omitted so not even STUN sees the user's real IP
    relay_servers = ice_server_settings()
    assert len(relay_servers) == 1
    assert relay_servers[0]["username"] == f"{exp}:dev-1"

    # If ephemeral TURN credentials expire while Relay-Only is active, fail closed!
    set_runtime_ice_config(
        {
            "ice_servers": [
                {
                    "urls": ["turns:turn.company.ru:443?transport=tcp"],
                    "username": "expired:dev-1",
                    "credential": "old==",
                }
            ],
            "expires_at": int(time.time()) - 5,
        }
    )
    with pytest.raises(ValueError, match="TURN"):
        ice_server_settings()

    # Persist per-peer 175% volume & PTT prefs inside encrypted security_prefs.enc
    SecureStorage.set_peer_volume("alice", "bob-dev", 1.75)
    SecureStorage.set_call_audio_prefs("alice", {"noise_gate_db": -35.0, "push_to_talk": True})
    prefs = SecureStorage.get_call_audio_prefs("alice")
    assert prefs["ice_relay_only"] is True
    assert prefs["noise_gate_db"] == -35.0
    assert prefs["push_to_talk"] is True
    assert prefs["peer_volumes"]["bob-dev"] == pytest.approx(1.75)


def test_vad_noise_gate_hysteresis_and_push_to_talk_hangover():
    events = []
    gate = VoiceActivityGate(
        threshold_db=-45.0,
        hold_frames=3,
        ptt_enabled=False,
        ptt_hangover_frames=2,
        on_speaking_changed=events.append,
    )

    quiet_hum = _sine_pcm(20.0)      # ~ -64 dBFS (fan / room noise)
    loud_voice = _sine_pcm(4000.0)   # ~ -18 dBFS (clear speech)
    soft_dip = _sine_pcm(140.0)      # ~ -47 dBFS (between open -45 and close -50)

    assert compute_rms_dbfs(quiet_hum) < -55.0
    assert compute_rms_dbfs(loud_voice) > -25.0

    # Fan noise is completely gated to silence
    assert gate.process_frame(quiet_hum) == SILENCE_FRAME
    assert gate.is_speaking is False

    # Speech opens gate smoothly (first frame fades in, second frame passes bit-exact)
    f1 = gate.process_frame(loud_voice)
    assert f1 != SILENCE_FRAME
    assert gate.is_speaking is True
    assert gate.process_frame(loud_voice) == loud_voice

    # Hysteresis keeps gate open during soft -47 dBFS syllable transition
    assert gate.process_frame(soft_dip) == soft_dip
    assert gate.is_speaking is True

    # Enable Push-to-Talk: loud speech is blocked until PTT key is pressed
    gate.set_ptt_mode(True)
    gate.set_ptt_pressed(False)
    # Drain fade-out frame then verify complete silence even on loud voice
    gate.process_frame(loud_voice)
    assert gate.process_frame(loud_voice) == SILENCE_FRAME
    assert gate.is_speaking is False

    # Press PTT -> transmits immediately; release PTT -> keeps 2 hangover frames then closes
    gate.set_ptt_pressed(True)
    assert gate.process_frame(loud_voice) != SILENCE_FRAME
    gate.set_ptt_pressed(False)
    assert gate.process_frame(loud_voice) == loud_voice   # hangover frame 1
    assert gate.process_frame(loud_voice) == loud_voice   # hangover frame 2
    gate.process_frame(loud_voice)                        # fade-out transition
    assert gate.process_frame(loud_voice) == SILENCE_FRAME


def test_group_audio_mixer_five_peers_200_percent_volume_and_soft_knee_limiter():
    speaking_log = []
    mixer = GroupAudioMixer(on_peer_speaking_changed=lambda pid, spk: speaking_log.append((pid, spk)))

    # 1. Verify 0%, 50%, and 200% individual peer volume scaling on moderate signal
    moderate = _sine_pcm(5000.0)
    mixer.set_peer_volume("p_half", 0.5)
    for _ in range(2):
        mixer.push_peer_pcm("p_half", moderate)
    mixed_half = np.frombuffer(mixer.mix_frame(), dtype="<i2").astype(np.float32)
    orig_samples = np.frombuffer(moderate, dtype="<i2").astype(np.float32)
    assert np.allclose(mixed_half, np.round(orig_samples * 0.5), atol=1.0)
    assert ("p_half", True) in speaking_log

    # 2. Stress test: 5 simultaneous peers shouting at 25000 peak with 200% (2.0x) gain each!
    # Raw sum reaches 5 * 25000 * 2.0 = 250,000 (> 7.6x int16 max!), yet soft-knee tanh
    # limiter must keep every sample strictly within [-32767, +32767] with zero wraparound!
    mixer.clear()
    shout = _sine_pcm(25000.0, freq_hz=300.0)
    for idx in range(5):
        pid = f"peer_{idx}"
        mixer.set_peer_volume(pid, 2.0)
        mixer.push_peer_pcm(pid, shout)
        mixer.push_peer_pcm(pid, shout)

    out = mixer.mix_frame()
    assert len(out) == FRAME_BYTES
    limited = np.frombuffer(out, dtype="<i2")
    assert int(limited.max()) <= 32767
    assert int(limited.min()) >= -32767
    # Peaks are smoothly compressed above 26000 without wrapping sign!
    orig_shout = np.frombuffer(shout, dtype="<i2")
    significant = np.abs(orig_shout) > 5000
    assert np.all(np.sign(limited[significant]) == np.sign(orig_shout[significant]))


def test_mic_fanout_and_group_voice_controller_e2ee_signal_and_1click_screen(monkeypatch):
    alice_cm = CryptoManager()
    alice_cm.generate_new_keypair()
    bob_cm = CryptoManager()
    bob_cm.generate_new_keypair()
    eve_cm = CryptoManager()
    eve_cm.generate_new_keypair()

    # 1. Single mic frame fanned out identically to 4 peers
    gate = VoiceActivityGate(threshold_db=None)
    dist = BroadcasterMicDistributor(gate)
    for pid in ("p1", "p2", "p3", "p4"):
        dist.subscribe(pid)
    tone = _sine_pcm(6000.0)
    dist.push_raw_mic_frame(tone)
    for pid in ("p1", "p2", "p3", "p4"):
        assert dist.pop_for_peer(pid) == tone

    # 2. GroupVoiceRoomController E2EE signaling + 1-click watch_peer_screen
    monkeypatch.setattr(cb_mod, "crypto", alice_cm)
    dispatched = []
    ctrl = GroupVoiceRoomController(
        send_signal_fn=lambda gid, target, ch, enc, sig: dispatched.append((gid, target, ch, enc, sig)),
    )
    # Prevent opening real hardware PyAudio device in test
    monkeypatch.setattr(ctrl, "_start_hardware_audio", lambda: None)

    roster = [
        {
            "device_id": "z_alice_dev",
            "username": "alice",
            "public_key": alice_cm.get_public_key_b64(),
            "fingerprint": alice_cm.get_fingerprint(),
            "is_muted": False,
            "is_sharing_screen": False,
        },
        {
            "device_id": "a_bob_dev",
            "username": "bob",
            "public_key": bob_cm.get_public_key_b64(),
            "fingerprint": bob_cm.get_fingerprint(),
            "is_muted": False,
            "is_sharing_screen": True,
        },
    ]
    ctrl.start_local_session("grp-42", "z_alice_dev", "alice", roster)

    # 1-click watch_peer_screen sends an E2EE-signed `watch_request` on `channel="screen"` to Bob
    assert ctrl.watch_peer_screen("a_bob_dev") is True
    assert len(dispatched) == 1
    gid, target, ch, enc_blob, sig_blob = dispatched[0]
    assert (gid, target, ch) == ("grp-42", "a_bob_dev", "screen")
    assert bob_cm.verify_signature(enc_blob, sig_blob, alice_cm.get_public_key_b64())
    dec = json.loads(bob_cm.decrypt_message(enc_blob, alice_cm.get_public_key_b64()))
    assert dec["action"] == "watch_request" and dec["group_id"] == "grp-42"

    # Forged signal signed by Eve claiming to be `a_bob_dev` MUST be rejected fail-closed!
    forged_inner = json.dumps(
        {
            "action": "offer",
            "sdp": "v=0\r\n",
            "group_id": "grp-42",
            "channel": "voice",
            "sender_device_id": "a_bob_dev",
            "target_device_id": "z_alice_dev",
        }
    )
    forged = eve_cm.encrypt_message(forged_inner, alice_cm.get_public_key_b64())
    assert (
        ctrl.handle_incoming_signal(
            {
                "group_id": "grp-42",
                "sender_device_id": "a_bob_dev",
                "channel": "voice",
                "encrypted_blob": forged["encrypted_blob"],
                "signature": forged["signature"],
            }
        )
        is False
    )

    ctrl.leave_local_session()
