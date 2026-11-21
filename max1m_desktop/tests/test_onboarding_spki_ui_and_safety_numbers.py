"""
Tests for Package VI:
1. 1-Click Team Onboarding (`max1m-join://`) compact base64url JSON & query URI formats,
   strict HTTPS / SPKI pin / invite validation.
2. Pre-login SPKI pin persistence in `local_state.json`, preservation across
   `SecureStorage.save_local_state`, active enforcement in `resolve_spki_pins_for_host`
   prior to login, and promotion into authenticated `tls_pins.enc` upon login/register.
3. Readable 60-digit Safety Numbers (`compute_safety_number`, `format_safety_number_blocks`)
   symmetry (Alice <-> Bob produce identical 60-digit blocks) and collision resistance.
"""

import hashlib
from types import SimpleNamespace

import pytest

import app.secure_storage as ss_mod
import app.tls_pinning as tp_mod
from app.contact_keys import (
    compute_safety_number,
    format_safety_number_blocks,
    safe_safety_number_display,
)
from app.crypto_box import CryptoManager
from app.onboarding import (
    build_join_link,
    parse_join_link,
    promote_prelogin_spki_pins,
    save_prelogin_spki_pins,
)
from app.secure_storage import SecureStorage
from app.tls_pinning import normalize_spki_pin, resolve_spki_pins_for_host


def test_join_link_roundtrip_and_strict_validation():
    pin1 = normalize_spki_pin(hashlib.sha256(b"spki-primary").hexdigest())
    pin2 = normalize_spki_pin(hashlib.sha256(b"spki-backup").hexdigest())

    link = build_join_link(
        "https://chat.company.ru:8443/",
        [pin1, pin2],
        invite_code="TEAM_2026-RU",
        node_title="Офис Калининград",
    )
    assert link.startswith("max1m-join://")

    cfg = parse_join_link(link)
    assert cfg.server_url == "https://chat.company.ru:8443"
    assert cfg.spki_pins == (pin1, pin2)
    assert cfg.invite_code == "TEAM_2026-RU"
    assert cfg.node_title == "Офис Калининград"

    # Query-style URI is also supported for CLI/scripts
    q_uri = f"max1m-join://join?server=https://node.corp.ru&pin={pin1}&invite=INV777"
    q_cfg = parse_join_link(q_uri)
    assert q_cfg.server_url == "https://node.corp.ru"
    assert q_cfg.spki_pins == (pin1,)
    assert q_cfg.invite_code == "INV777"

    # Plain HTTP non-loopback server rejected fail-closed
    with pytest.raises(ValueError):
        build_join_link("http://chat.company.ru", [pin1])

    # Missing or invalid SPKI pin rejected fail-closed
    with pytest.raises(ValueError):
        build_join_link("https://chat.company.ru", ["sha256/not-valid-pin"])


def test_prelogin_spki_pin_survives_local_state_save_and_promotes_to_auth_store(tmp_path, monkeypatch):
    base = tmp_path / ".max1m"
    base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ss_mod, "BASE_DIR", base)
    monkeypatch.setattr(ss_mod, "CONFIG_FILE", base / "local_state.json")
    monkeypatch.delenv("MAX1M_TLS_SPKI_PINS", raising=False)
    keys = {}
    monkeypatch.setattr(ss_mod.keyring, "get_password", lambda s, k: keys.get(f"{s}:{k}"))
    monkeypatch.setattr(ss_mod.keyring, "set_password", lambda s, k, v: keys.__setitem__(f"{s}:{k}", v))

    # Before login (`state.username == ""`)
    monkeypatch.setattr(tp_mod, "state", SimpleNamespace(username=""), raising=False)
    import app.state as state_mod
    monkeypatch.setattr(state_mod, "state", SimpleNamespace(username=""))

    pin = normalize_spki_pin(hashlib.sha256(b"prod-node-cert").hexdigest())
    save_prelogin_spki_pins("https://secure.company.ru", [pin])

    # Pin is immediately enforced for pre-login registration/login TLS handshakes!
    assert resolve_spki_pins_for_host("secure.company.ru") == {pin}

    # Saving device state without `tls_spki_pins` preserves pre-login pins!
    SecureStorage.save_local_state({
        "server_url": "https://secure.company.ru",
        "username": "ivan",
        "device_name": "Work PC",
        "device_id": "dev-1",
    })
    assert resolve_spki_pins_for_host("secure.company.ru") == {pin}

    # Promote into authenticated `tls_pins.enc` upon login
    promoted = promote_prelogin_spki_pins("ivan", "https://secure.company.ru")
    assert promoted == [pin]
    assert SecureStorage.load_tls_pins("ivan") == {"secure.company.ru": [pin]}


def test_safety_number_60_digits_symmetry_and_formatting():
    alice = CryptoManager()
    alice.generate_new_keypair()
    bob = CryptoManager()
    bob.generate_new_keypair()
    mallory = CryptoManager()
    mallory.generate_new_keypair()

    alice_pk = alice.get_public_key_b64()
    bob_pk = bob.get_public_key_b64()
    mallory_pk = mallory.get_public_key_b64()

    sn_ab = compute_safety_number(alice_pk, bob_pk)
    sn_ba = compute_safety_number(bob_pk, alice_pk)
    assert len(sn_ab) == 60 and sn_ab.isdigit()
    assert sn_ab == sn_ba

    sn_am = compute_safety_number(alice_pk, mallory_pk)
    assert sn_am != sn_ab

    formatted = format_safety_number_blocks(sn_ab)
    lines = formatted.splitlines()
    assert len(lines) == 3
    for ln in lines:
        blocks = ln.split(" ")
        assert len(blocks) == 4 and all(len(b) == 5 and b.isdigit() for b in blocks)

    assert safe_safety_number_display(alice_pk, bob_pk) == formatted
    assert safe_safety_number_display("invalid", bob_pk) == ""
