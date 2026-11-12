from app.call_policy import allow_webrtc_signal


def test_signaling_requires_user_consent_and_matching_device():
    assert not allow_webrtc_signal("alice", "alice", False)
    assert not allow_webrtc_signal("mallory", "alice", True)
    assert not allow_webrtc_signal("alice", None, True)
    assert allow_webrtc_signal("alice", "alice", True)


def test_call_identity_requires_unique_pinned_and_verified_device():
    from types import SimpleNamespace
    from app.call_policy import resolve_call_peer, call_context_valid
    from app.contact_keys import fingerprint_public_key
    from app.crypto_box import CryptoManager
    alice, replacement = CryptoManager(), CryptoManager()
    alice.generate_new_keypair()
    replacement.generate_new_keypair()
    key = alice.get_public_key_b64()
    device = {"device_id": "phone", "public_key": key}
    state = SimpleNamespace(username="me", device_id="mine", server_url="https://node/",
                            allies={"alice": {"devices": [device]}})
    context = resolve_call_peer(state, "phone")
    assert context and call_context_valid(state, context, False)
    assert not call_context_valid(state, context)
    device["verified_fingerprint"] = fingerprint_public_key(key)
    device["verified_scope"] = {"username": "me", "device_id": "mine", "server_url": "https://node"}
    assert call_context_valid(state, context)
    state.allies["mallory"] = {"devices": [device.copy()]}
    assert resolve_call_peer(state, "phone") is None
    assert not call_context_valid(state, context)
    del state.allies["mallory"]
    device["public_key"] = replacement.get_public_key_b64()
    assert not call_context_valid(state, context, False)
    device["public_key"] = key
    state.server_url = "https://elsewhere"
    assert not call_context_valid(state, context)


def test_ui_identity_monitor_and_disconnect_stop_call():
    import ast
    from pathlib import Path
    from types import SimpleNamespace
    source = Path(__file__).resolve().parents[1] / "app/windows/main_screen.py"
    tree = ast.parse(source.read_text())
    names = {"_check_call_identity", "_update_rtc_state"}
    methods = [n for c in tree.body if isinstance(c, ast.ClassDef) for n in c.body if isinstance(n, ast.FunctionDef) and n.name in names]
    stops, warnings, status = [], [], []
    env = {"state": object(), "call_context_valid": lambda *args: False,
           "rtc": SimpleNamespace(end_call=lambda: stops.append(True)),
           "QMessageBox": SimpleNamespace(warning=lambda *args: warnings.append(True))}
    exec(compile(ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])), str(source), "exec"), env)
    Screen = type("Screen", (), {**{name: env[name] for name in names},
                                 "_cleanup_call": lambda self: status.append("clean")})
    screen = Screen()
    screen._active_call_device_id = "peer"
    screen._active_call_context = object()
    screen._call_direction = "outgoing"
    screen._call_signal_authorized = True
    screen._check_call_identity()
    assert stops == [True] and status == ["clean"] and len(warnings) == 1
    screen._update_rtc_state("old-peer", "failed")
    assert stops == [True]
    screen._update_rtc_state("peer", "disconnected")
    assert len(stops) == 2 and status == ["clean", "clean"]


def test_stale_call_callbacks_cannot_act_on_new_call_same_peer():
    import ast
    from pathlib import Path
    from types import SimpleNamespace
    source = Path(__file__).resolve().parents[1] / 'app/windows/app_window.py'
    tree = ast.parse(source.read_text())
    names = {'_send_rtc_signal', '_apply_rtc_state_change'}
    nodes = [n for c in tree.body if isinstance(c, ast.ClassDef) for n in c.body
             if isinstance(n, ast.FunctionDef) and n.name in names]
    env = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source), 'exec'), env)
    sent, states = [], []
    Window = type('Window', (), {**{name: env[name] for name in names},
                                 '_send_call_event': lambda self, *args: sent.append(args)})
    window = Window()
    window.main_screen = SimpleNamespace(_active_call_id='new', _active_call_device_id='peer',
                                         _call_signal_authorized=True,
                                         _update_rtc_state=lambda *args: states.append(args))
    packet = {'type': 'webrtc_signal', 'to_device_id': 'peer', '_local_call_id': 'old'}
    window._send_rtc_signal(packet)
    window._apply_rtc_state_change('peer', 'old', 'failed')
    assert not sent and not states
    window._send_rtc_signal({**packet, '_local_call_id': 'new'})
    window._apply_rtc_state_change('peer', 'new', 'connected')
    assert len(sent) == 1 and sent[0][2] == 'new' and '_local_call_id' not in sent[0][3]
    assert states == [('peer', 'connected')]
