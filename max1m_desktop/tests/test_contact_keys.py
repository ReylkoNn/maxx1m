import pytest
from app.crypto_box import CryptoManager
from app.contact_keys import fingerprint_public_key, device_key_map, same_contact_keys


def test_fingerprint_matches_local_identity():
    crypto = CryptoManager()
    crypto.generate_new_keypair()
    assert fingerprint_public_key(crypto.get_public_key_b64()) == crypto.get_fingerprint()
    with pytest.raises((ValueError, TypeError)):
        fingerprint_public_key("not a key")


def test_contact_key_changes_and_added_devices_are_not_silently_accepted():
    first, second = CryptoManager(), CryptoManager()
    first.generate_new_keypair()
    second.generate_new_keypair()
    original = {"user_id": "user", "devices": [{"device_id": "device", "public_key": first.get_public_key_b64()}]}
    same = {"user_id": "user", "devices": [{"device_id": "device", "public_key": first.get_public_key_b64(), "fingerprint": "untrusted"}]}
    changed = {"user_id": "user", "devices": [{"device_id": "device", "public_key": second.get_public_key_b64()}]}
    added = {"user_id": "user", "devices": original["devices"] + [{"device_id": "new", "public_key": second.get_public_key_b64()}]}
    assert same_contact_keys(original, same)
    assert not same_contact_keys(original, changed)
    assert not same_contact_keys(original, added)
    assert not same_contact_keys(original, {**same, "user_id": "different"})
    with pytest.raises(ValueError):
        device_key_map({"devices": original["devices"] * 2})


def test_unknown_sender_refresh_adds_only_unverified_server_candidate():
    from app.contact_keys import add_unverified_sender_device

    old_key, new_key, collision_key = CryptoManager(), CryptoManager(), CryptoManager()
    for manager in (old_key, new_key, collision_key):
        manager.generate_new_keypair()
    old_device = {
        "device_id": "old-device",
        "public_key": old_key.get_public_key_b64(),
        "verified_fingerprint": fingerprint_public_key(old_key.get_public_key_b64()),
        "verified_scope": {"username": "alice", "device_id": "mine", "server_url": "https://node"},
    }
    existing = {"user_id": "user-1", "devices": [old_device]}
    allies = {"bob": existing}
    incoming = {
        "username": "bob",
        "user_id": "user-1",
        "devices": [
            {"device_id": "old-device", "public_key": old_key.get_public_key_b64()},
            {
                "device_id": "new-device",
                "public_key": new_key.get_public_key_b64(),
                "fingerprint": "server-claim-is-not-trust",
                "verified_fingerprint": "forged",
                "verified_scope": {"forged": True},
            },
        ],
    }

    updated, changed = add_unverified_sender_device(allies, "bob", "user-1", "new-device", incoming)
    assert changed and updated is not allies
    assert len(allies["bob"]["devices"]) == 1
    added = updated["bob"]["devices"][1]
    assert added["device_id"] == "new-device"
    assert added["public_key"] == new_key.get_public_key_b64()
    assert "verified_fingerprint" not in added and "verified_scope" not in added
    assert updated["bob"]["devices"][0] == old_device

    no_change, changed = add_unverified_sender_device(
        updated, "bob", "user-1", "new-device", incoming
    )
    assert not changed and no_change is updated
    with pytest.raises(ValueError):
        add_unverified_sender_device(allies, "bob", "different-user", "new-device", incoming)
    with pytest.raises(ValueError):
        add_unverified_sender_device(allies, "bob", "user-1", "missing-device", incoming)

    colliding = {
        **allies,
        "carol": {"user_id": "user-2", "devices": [{
            "device_id": "new-device", "public_key": collision_key.get_public_key_b64()
        }]},
    }
    with pytest.raises(ValueError):
        add_unverified_sender_device(colliding, "bob", "user-1", "new-device", incoming)
