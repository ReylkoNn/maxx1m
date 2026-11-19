from types import SimpleNamespace
import pytest
from app.recipient_context import (
    capture_recipient, recipient_still_trusted, is_active_recipient, choose_online_device,
)


def state():
    return SimpleNamespace(username="alice", device_id="mine", server_url="https://node/",
                           current_chat_type="ally", current_chat_username="bob",
                           current_chat_device_id="bob-device",
                           allies={"bob": {"devices": [{"device_id": "bob-device", "public_key": "key"}]},
                                   "eve": {"devices": [{"device_id": "eve-device", "public_key": "other"}]}})


def test_switch_chat_keeps_snapshot_but_requires_confirmation():
    s = state()
    ctx = capture_recipient(s)
    s.current_chat_username, s.current_chat_device_id = "eve", "eve-device"
    assert ctx.username == "bob" and ctx.device_id == "bob-device" and ctx.public_key == "key"
    assert recipient_still_trusted(s, ctx)
    assert not is_active_recipient(s, ctx)


@pytest.mark.parametrize("change", ["key", "device", "account", "server"])
def test_reject_changed_identity(change):
    s = state()
    ctx = capture_recipient(s)
    if change == "key":
        s.allies["bob"]["devices"][0]["public_key"] = "replaced"
    elif change == "device":
        s.allies["bob"]["devices"] = []
    elif change == "account":
        s.username = "another"
    else:
        s.server_url = "https://other"
    assert not recipient_still_trusted(s, ctx)


def test_groups_and_missing_devices_are_rejected():
    s = state()
    s.current_chat_type = "group"
    with pytest.raises(ValueError):
        capture_recipient(s)
    s.current_chat_type = "ally"
    s.current_chat_device_id = "missing"
    with pytest.raises(ValueError):
        capture_recipient(s)


def test_verification_is_bound_to_actual_device_key_and_account():
    from app.crypto_box import CryptoManager
    from app.contact_keys import fingerprint_public_key
    from app.recipient_context import recipient_is_verified
    crypto = CryptoManager()
    crypto.generate_new_keypair()
    s = state()
    device = s.allies["bob"]["devices"][0]
    device["public_key"] = crypto.get_public_key_b64()
    ctx = capture_recipient(s)
    assert not recipient_is_verified(s, ctx)
    device["verified_fingerprint"] = "server-provided or unrelated"
    assert not recipient_is_verified(s, ctx)
    device["verified_fingerprint"] = fingerprint_public_key(ctx.public_key)
    assert not recipient_is_verified(s, ctx)  # Older unscoped confirmations must be repeated.
    from app.recipient_context import verification_scope
    device["verified_scope"] = verification_scope(ctx)
    assert recipient_is_verified(s, ctx)
    s.server_url = "https://other"
    assert not recipient_is_verified(s, ctx)


def test_invalid_key_cannot_be_verified():
    from app.recipient_context import recipient_is_verified
    s = state()
    ctx = capture_recipient(s)
    s.allies["bob"]["devices"][0]["verified_fingerprint"] = "bad"
    assert not recipient_is_verified(s, ctx)


def test_online_device_selection_requires_a_locally_verified_known_key():
    devices = [
        {"device_id": "old"},
        {"device_id": "phone"},
        {"device_id": "laptop"},
    ]
    # Preserve the user's preferred choice when it is online and trusted.
    assert choose_online_device(devices, ["phone", "laptop"], "phone", {"phone", "laptop"}) == "phone"
    # Otherwise choose an online trusted device; never select a server-only device or unverified key.
    assert choose_online_device(devices, ["old", "phone", "unknown"], "laptop", {"phone"}) == "phone"
    assert choose_online_device(devices, ["phone"], "phone", set()) is None
    assert choose_online_device(devices, ["unknown"], None, {"unknown"}) is None
    assert choose_online_device({}, ["phone"], verified_device_ids={"phone"}) is None
