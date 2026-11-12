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
