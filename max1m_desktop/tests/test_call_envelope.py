import uuid
import pytest
from app.crypto_box import CryptoManager
from app import call_envelope, secure_storage


@pytest.fixture
def peers():
    alice, bob, mallory = CryptoManager(), CryptoManager(), CryptoManager()
    for peer in (alice, bob, mallory):
        peer.generate_new_keypair()
    return alice, bob, mallory


def incoming(alice, bob, kind="call_offer", call_id=None):
    call_id = call_id or str(uuid.uuid4())
    data = call_envelope.seal(alice, kind, "alice", "bob", call_id, bob.get_public_key_b64(), now=1000)
    data["from_device_id"] = "alice"
    return data


def test_signed_envelope_binds_kind_sender_recipient_and_time(peers):
    alice, bob, mallory = peers
    data = incoming(alice, bob)
    event = call_envelope.open_envelope(bob, data, "bob", alice.get_public_key_b64(), now=1000)
    assert event["kind"] == "call_offer" and event["sender"] == "alice"
    for changed in ({**data, "type": "call_ended"}, {**data, "from_device_id": "mallory"},
                    {**data, "call_signature": "invalid"}):
        with pytest.raises(ValueError):
            call_envelope.open_envelope(bob, changed, "bob", alice.get_public_key_b64(), now=1000)
    with pytest.raises(ValueError):
        call_envelope.open_envelope(bob, data, "other", alice.get_public_key_b64(), now=1000)
    with pytest.raises(ValueError):
        call_envelope.open_envelope(bob, data, "bob", mallory.get_public_key_b64(), now=1000)
    with pytest.raises(ValueError):
        call_envelope.open_envelope(bob, data, "bob", alice.get_public_key_b64(), now=1301)
    with pytest.raises(ValueError):
        call_envelope.open_envelope(bob, {"type": "call_offer", "from_device_id": "alice"}, "bob", alice.get_public_key_b64(), now=1000)


def test_offer_replay_survives_restart_and_is_isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, "get_password", lambda svc, key: keys.get(key))
    monkeypatch.setattr(secure_storage.keyring, "set_password", lambda svc, key, value: keys.__setitem__(key, value))
    cid = str(uuid.uuid4())
    assert call_envelope.remember_offer("bob", "https://node", "device", "alice", cid, now=1000)
    assert not call_envelope.remember_offer("bob", "https://node", "device", "alice", cid, now=1100)
    assert call_envelope.remember_offer("bob", "https://other", "device", "alice", cid, now=1100)
    assert cid.encode() not in next(tmp_path.rglob("*-call-replay.enc")).read_bytes()
    assert call_envelope.remember_offer("bob", "https://node", "device", "alice", cid, now=1601)


def test_replay_store_failure_and_capacity_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, "get_password", lambda svc, key: keys.get(key))
    monkeypatch.setattr(secure_storage.keyring, "set_password", lambda svc, key, value: keys.__setitem__(key, value))
    monkeypatch.setattr(call_envelope, "MAX_REPLAY_ENTRIES", 1)
    cid = str(uuid.uuid4())
    assert call_envelope.remember_offer("bob", "node", "device", "alice", cid, now=1000)
    with pytest.raises(ValueError):
        call_envelope.remember_offer("bob", "node", "device", "alice", str(uuid.uuid4()), now=1001)
    path = next(tmp_path.rglob("*-call-replay.enc"))
    path.write_bytes(b"corrupt")
    with pytest.raises(Exception):
        call_envelope.remember_offer("bob", "node", "device", "alice", str(uuid.uuid4()), now=1002)


def test_window_callbacks_reject_replay_and_cross_call(peers, tmp_path, monkeypatch):
    import ast
    from pathlib import Path
    from types import SimpleNamespace
    from app.call_policy import allow_webrtc_signal, resolve_call_peer, call_context_valid
    from app.contact_keys import fingerprint_public_key
    alice, bob, _ = peers
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, "get_password", lambda svc, key: keys.get(key))
    monkeypatch.setattr(secure_storage.keyring, "set_password", lambda svc, key, value: keys.__setitem__(key, value))
    source = Path(__file__).resolve().parents[1] / "app/windows/app_window.py"
    names = {"_verified_call_event", "_on_webrtc_signal", "_on_call_accepted", "_on_call_ended", "_on_call_offer"}
    tree = ast.parse(source.read_text())
    methods = [node for cls in tree.body if isinstance(cls, ast.ClassDef) for node in cls.body
               if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(methods) == len(names)
    received, offers, accepted, ended = [], [], [], []
    pub = alice.get_public_key_b64()
    device = {"device_id": "alice", "public_key": pub, "verified_fingerprint": fingerprint_public_key(pub),
              "verified_scope": {"username": "bob", "device_id": "bob", "server_url": "node"}}
    state = SimpleNamespace(device_id="bob", username="bob", server_url="node",
                            allies={"alice": {"devices": [device]}})
    context = resolve_call_peer(state, "alice")
    env = dict(call_envelope=call_envelope, crypto=bob, state=state,
               allow_webrtc_signal=allow_webrtc_signal, resolve_call_peer=resolve_call_peer,
               call_context_valid=call_context_valid,
               rtc=SimpleNamespace(handle_encrypted_signal=lambda data, call_id: received.append(data)))
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])), str(source), "exec"), env)
    Window = type("Window", (), {**{name: env[name] for name in names},
                                    "_get_peer_public_key": lambda self, sender: alice.get_public_key_b64()})
    window = Window()
    cid = str(uuid.uuid4())
    window.main_screen = SimpleNamespace(_active_call_device_id="alice", _active_call_id=cid,
                                         _active_call_context=context, _call_signal_authorized=True,
                                         _on_incoming_call=offers.append, _on_call_accepted=accepted.append,
                                         _on_remote_call_ended=ended.append)
    def packet(kind, call_id, content=None):
        data = call_envelope.seal(alice, kind, "alice", "bob", call_id, bob.get_public_key_b64(), content)
        data["from_device_id"] = "alice"
        return data
    offer = packet("call_offer", cid)
    window._on_call_offer(offer)
    window._on_call_offer(offer)
    assert len(offers) == 1
    accept = packet("call_accept", cid)
    window._on_call_accepted(accept)
    window._on_call_accepted(accept)
    window._on_call_accepted(packet("call_accept", str(uuid.uuid4())))
    window._on_call_accepted({"type": "call_accept", "from_device_id": "alice"})
    assert len(accepted) == 1
    signal = packet("webrtc_signal", cid, {"type": "webrtc_signal", "to_device_id": "bob", "encrypted_signal": "cipher"})
    window._on_webrtc_signal(signal)
    window._on_webrtc_signal(signal)
    assert len(received) == 1 and received[0]["from_device_id"] == "alice"
    window._on_call_ended(packet("call_ended", str(uuid.uuid4())))
    assert not ended


def test_call_events_and_send_stop_when_pinned_key_or_scope_changes(peers):
    import ast
    from pathlib import Path
    from types import SimpleNamespace
    from app.call_policy import resolve_call_peer, call_context_valid
    from app.contact_keys import fingerprint_public_key
    alice, bob, mallory = peers
    key = alice.get_public_key_b64()
    device = {"device_id": "alice-device", "public_key": key,
              "verified_fingerprint": fingerprint_public_key(key),
              "verified_scope": {"username": "bob", "device_id": "bob-device", "server_url": "node"}}
    state = SimpleNamespace(username="bob", device_id="bob-device", server_url="node",
                            allies={"alice": {"devices": [device]}})
    pinned = resolve_call_peer(state, "alice-device")
    call_id = str(uuid.uuid4())
    src = Path(__file__).resolve().parents[1] / "app/windows/app_window.py"
    tree = ast.parse(src.read_text())
    names = {"_verified_call_event", "_send_call_event", "_get_peer_public_key"}
    methods = [n for c in tree.body if isinstance(c, ast.ClassDef) for n in c.body if isinstance(n, ast.FunctionDef) and n.name in names]
    env = {"state": state, "crypto": bob, "call_envelope": call_envelope,
           "resolve_call_peer": resolve_call_peer, "call_context_valid": call_context_valid}
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])), str(src), "exec"), env)
    window = type("Window", (), {name: env[name] for name in names})()
    sent = []
    window.ws_worker = SimpleNamespace(send_signal=lambda value: sent.append(value) or True)
    window.main_screen = SimpleNamespace(_active_call_context=pinned, _active_call_id=call_id,
                                         _active_call_device_id="alice-device")
    def incoming():
        msg = call_envelope.seal(alice, "call_accept", "alice-device", "bob-device", call_id, bob.get_public_key_b64())
        msg["from_device_id"] = "alice-device"
        return msg
    assert window._send_call_event("call_offer", "alice-device", call_id)
    assert window._get_peer_public_key("alice-device") == key
    assert window._verified_call_event(incoming())
    device["public_key"] = mallory.get_public_key_b64()
    assert not window._send_call_event("webrtc_signal", "alice-device", call_id, {})
    assert window._get_peer_public_key("alice-device") is None
    assert window._verified_call_event(incoming()) is None
    device["public_key"] = key
    device.pop("verified_scope")
    assert not window._send_call_event("call_offer", "alice-device", call_id)
    assert window._verified_call_event(incoming()) is None
    assert window._send_call_event("call_ended", "alice-device", call_id)
    assert len(sent) == 2


def test_oversized_call_replay_store_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda svc, key: keys.get(key))
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda svc, key, value: keys.__setitem__(key, value))
    assert call_envelope.remember_offer('bob', 'node', 'device', 'alice', str(uuid.uuid4()), now=1000)
    path = next(tmp_path.rglob('*-call-replay.enc'))
    path.write_bytes(b'x' * 1025)
    monkeypatch.setattr(call_envelope, 'MAX_REPLAY_FILE_BYTES', 1024)
    with pytest.raises(ValueError, match='too large'):
        call_envelope.remember_offer('bob', 'node', 'device', 'alice', str(uuid.uuid4()), now=1001)
    assert path.stat().st_size == 1025


def test_oversized_call_envelope_rejected_before_signature_verification():
    class NeverCrypto:
        def verify_signature(self, *args): raise AssertionError('Do not verify oversized input')
    base = {'type':'call_offer','from_device_id':'sender','encrypted_call':'x','call_signature':'x'}
    for data in ({**base, 'from_device_id':'x'*65}, {**base, 'encrypted_call':'x'*(128*1024+1)},
                 {**base, 'call_signature':'x'*513}):
        with pytest.raises(ValueError):
            call_envelope.open_envelope(NeverCrypto(), data, 'recipient', 'key')
