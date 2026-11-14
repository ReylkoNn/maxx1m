"""Client-side cryptographic & storage regression tests for Protected Groups v2."""

from pathlib import Path
import nacl.exceptions
import pytest

from app import secure_storage
from app.crypto_box import CryptoManager
from app.group_crypto import (
    group_crypto,
    lookup_member_sender_key,
    store_member_sender_key,
)
from app.secure_storage import SecureStorage


def _make_identity(name: str) -> tuple[str, CryptoManager, str]:
    cm = CryptoManager()
    cm.generate_new_keypair()
    return f"dev-{name}", cm, cm.get_public_key_b64()


def test_group_crypto_v2_forward_secrecy_out_of_order_replay_and_dos_resistance():
    alice_id, alice_cm, alice_pub = _make_identity("alice")
    bob_id, bob_cm, bob_pub = _make_identity("bob")
    _, _, charlie_pub = _make_identity("charlie")

    group_id = "grp-alpha-001"
    alice_sk = group_crypto.generate_sender_key(group_id=group_id, epoch=1)

    # Seal Alice's SenderKey specifically for Bob
    enc_blob, sig_b64 = group_crypto.encrypt_sender_key_for_member(
        alice_sk,
        bob_pub,
        group_id=group_id,
        sender_device_id=alice_id,
        recipient_device_id=bob_id,
        crypto_mgr=alice_cm,
    )

    # Context binding: wrong group_id, wrong sender pubkey, or wrong recipient_device_id -> None!
    assert (
        group_crypto.decrypt_sender_key(
            enc_blob,
            sig_b64,
            alice_pub,
            expected_group_id="grp-wrong",
            expected_sender_device_id=alice_id,
            expected_recipient_device_id=bob_id,
            crypto_mgr=bob_cm,
        )
        is None
    )
    assert (
        group_crypto.decrypt_sender_key(
            enc_blob,
            sig_b64,
            charlie_pub,
            expected_group_id=group_id,
            expected_sender_device_id=alice_id,
            expected_recipient_device_id=bob_id,
            crypto_mgr=bob_cm,
        )
        is None
    )
    assert (
        group_crypto.decrypt_sender_key(
            enc_blob,
            sig_b64,
            alice_pub,
            expected_group_id=group_id,
            expected_sender_device_id=alice_id,
            expected_recipient_device_id="dev-charlie",
            crypto_mgr=bob_cm,
        )
        is None
    )

    bob_recv_sk = group_crypto.decrypt_sender_key(
        enc_blob,
        sig_b64,
        alice_pub,
        expected_group_id=group_id,
        expected_sender_device_id=alice_id,
        expected_recipient_device_id=bob_id,
        crypto_mgr=bob_cm,
    )
    assert bob_recv_sk is not None
    assert bob_recv_sk["epoch"] == 1
    assert bob_recv_sk["chain_index"] == 0

    # Alice encrypts 5 consecutive messages (ratchet advances 0 -> 5, destroying past chain keys)
    packets = []
    for i in range(5):
        pkt = group_crypto.encrypt_group_message(
            f"secret-{i}",
            alice_sk,
            group_id=group_id,
            sender_device_id=alice_id,
            crypto_mgr=alice_cm,
        )
        assert pkt["chain_index"] == i
        packets.append(pkt)

    assert alice_sk["chain_index"] == 5

    # Forward secrecy proof: someone who compromises `alice_sk` AFTER message 4
    # CANNOT decrypt earlier messages 0..4!
    compromised_copy = dict(alice_sk)
    compromised_copy["skipped_keys"] = dict(alice_sk.get("skipped_keys") or {})
    for pkt in packets:
        assert (
            group_crypto.decrypt_group_message(
                pkt,
                compromised_copy,
                expected_group_id=group_id,
                expected_sender_device_id=alice_id,
                sender_public_key_b64=alice_pub,
            )
            is None
        )

    # DoS resistance: an attacker injecting a huge chain_index (> MAX_SKIP) fails closed
    # WITHOUT advancing or corrupting Bob's ratchet state!
    forged_dos = {**packets[0], "chain_index": 9999}
    assert (
        group_crypto.decrypt_group_message(
            forged_dos,
            bob_recv_sk,
            expected_group_id=group_id,
            expected_sender_device_id=alice_id,
        )
        is None
    )
    assert bob_recv_sk["chain_index"] == 0

    # Out-of-order delivery: Bob receives 4, 1, 3, 0, 2 — all decrypt cleanly!
    for idx in (4, 1, 3, 0, 2):
        pkt = packets[idx]
        pt = group_crypto.decrypt_group_message(
            pkt,
            bob_recv_sk,
            expected_group_id=group_id,
            expected_sender_device_id=alice_id,
            sender_public_key_b64=alice_pub,
        )
        assert pt == f"secret-{idx}"

    # Anti-replay: replaying ANY already-decrypted packet (including skipped ones) returns None!
    for pkt in packets:
        assert (
            group_crypto.decrypt_group_message(
                pkt,
                bob_recv_sk,
                expected_group_id=group_id,
                expected_sender_device_id=alice_id,
                sender_public_key_b64=alice_pub,
            )
            is None
        )

    # Cross-group replay fails closed even on fresh packet #5!
    pkt5 = group_crypto.encrypt_group_message(
        "fresh-5",
        alice_sk,
        group_id=group_id,
        sender_device_id=alice_id,
        crypto_mgr=alice_cm,
    )
    assert (
        group_crypto.decrypt_group_message(
            pkt5,
            bob_recv_sk,
            expected_group_id="grp-other-999",
            expected_sender_device_id=alice_id,
            sender_public_key_b64=alice_pub,
        )
        is None
    )
    # And Bob's state remained intact so real group_id decrypts #5 cleanly:
    assert (
        group_crypto.decrypt_group_message(
            pkt5,
            bob_recv_sk,
            expected_group_id=group_id,
            expected_sender_device_id=alice_id,
            sender_public_key_b64=alice_pub,
        )
        == "fresh-5"
    )


def test_epoch_rotation_revokes_departed_member_and_secure_storage_persists_ratchet(tmp_path: Path, monkeypatch):
    keyring_mem: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(secure_storage, "BASE_DIR", tmp_path)
    monkeypatch.setattr(secure_storage, "CONFIG_FILE", tmp_path / "local_state.json")
    monkeypatch.setattr(
        secure_storage.keyring,
        "get_password",
        lambda svc, key: keyring_mem.get((svc, key)),
    )
    monkeypatch.setattr(
        secure_storage.keyring,
        "set_password",
        lambda svc, key, val: keyring_mem.__setitem__((svc, key), val),
    )

    alice_id, alice_cm, alice_pub = _make_identity("alice2")
    bob_id, bob_cm, bob_pub = _make_identity("bob2")
    charlie_id, charlie_cm, charlie_pub = _make_identity("charlie2")

    group_id = "grp_rot_777"
    alice_ep1 = group_crypto.generate_sender_key(group_id=group_id, epoch=1)

    b_enc1, b_sig1 = group_crypto.encrypt_sender_key_for_member(
        alice_ep1, bob_pub, group_id=group_id, sender_device_id=alice_id, recipient_device_id=bob_id, crypto_mgr=alice_cm
    )
    c_enc1, c_sig1 = group_crypto.encrypt_sender_key_for_member(
        alice_ep1, charlie_pub, group_id=group_id, sender_device_id=alice_id, recipient_device_id=charlie_id, crypto_mgr=alice_cm
    )

    bob_group_entry: dict = {"sender_keys": {}}
    charlie_group_entry: dict = {"sender_keys": {}}

    bob_sk1 = group_crypto.decrypt_sender_key(
        b_enc1, b_sig1, alice_pub,
        expected_group_id=group_id, expected_sender_device_id=alice_id, expected_recipient_device_id=bob_id, crypto_mgr=bob_cm,
    )
    charlie_sk1 = group_crypto.decrypt_sender_key(
        c_enc1, c_sig1, alice_pub,
        expected_group_id=group_id, expected_sender_device_id=alice_id, expected_recipient_device_id=charlie_id, crypto_mgr=charlie_cm,
    )
    assert bob_sk1 is not None and charlie_sk1 is not None
    store_member_sender_key(bob_group_entry, alice_id, bob_sk1)
    store_member_sender_key(charlie_group_entry, alice_id, charlie_sk1)

    # Delayed epoch-1 message encrypted BEFORE Charlie leaves
    delayed_ep1_pkt = group_crypto.encrypt_group_message(
        "before-charlie-left", alice_ep1, group_id=group_id, sender_device_id=alice_id, crypto_mgr=alice_cm
    )

    # Charlie leaves -> Alice rotates to epoch 2 ONLY for Bob!
    alice_ep2 = group_crypto.generate_sender_key(group_id=group_id, epoch=2)
    b_enc2, b_sig2 = group_crypto.encrypt_sender_key_for_member(
        alice_ep2, bob_pub, group_id=group_id, sender_device_id=alice_id, recipient_device_id=bob_id, crypto_mgr=alice_cm
    )
    bob_sk2 = group_crypto.decrypt_sender_key(
        b_enc2, b_sig2, alice_pub,
        expected_group_id=group_id, expected_sender_device_id=alice_id, expected_recipient_device_id=bob_id, crypto_mgr=bob_cm,
    )
    assert bob_sk2 is not None
    store_member_sender_key(bob_group_entry, alice_id, bob_sk2)

    post_leave_pkt = group_crypto.encrypt_group_message(
        "after-charlie-left", alice_ep2, group_id=group_id, sender_device_id=alice_id, crypto_mgr=alice_cm
    )

    # Charlie CANNOT decrypt post-leave epoch-2 packet!
    c_lookup = lookup_member_sender_key(charlie_group_entry, alice_id, post_leave_pkt["key_id"])
    assert c_lookup is None
    assert (
        group_crypto.decrypt_group_message(
            post_leave_pkt,
            charlie_sk1,
            expected_group_id=group_id,
            expected_sender_device_id=alice_id,
            sender_public_key_b64=alice_pub,
        )
        is None
    )

    # Persist Bob's keyring in SecureStorage (group_keys.enc), reload, and verify BOTH
    # the new epoch-2 packet AND the delayed epoch-1 packet decrypt cleanly!
    SecureStorage.save_groups_index(
        "bob_profile",
        {group_id: {"name": "RotGroup", "created_by_device_id": alice_id, "archived": False}},
    )
    SecureStorage.save_group_keys(
        "bob_profile",
        {
            group_id: {
                "epoch": 2,
                "my_sender_key": group_crypto.generate_sender_key(group_id=group_id, epoch=2),
                "sender_keys": bob_group_entry["sender_keys"],
                "distributed_epoch": 2,
            }
        },
    )

    loaded_meta = SecureStorage.load_groups_index("bob_profile")
    assert set(loaded_meta[group_id].keys()) == {"name", "created_by_device_id", "archived"}

    loaded_keys = SecureStorage.load_group_keys("bob_profile")
    assert loaded_keys[group_id]["distributed_epoch"] == 2
    reloaded_entry = loaded_keys[group_id]

    sk_for_ep2 = lookup_member_sender_key(reloaded_entry, alice_id, post_leave_pkt["key_id"])
    assert sk_for_ep2 is not None
    assert (
        group_crypto.decrypt_group_message(
            post_leave_pkt,
            sk_for_ep2,
            expected_group_id=group_id,
            expected_sender_device_id=alice_id,
            sender_public_key_b64=alice_pub,
        )
        == "after-charlie-left"
    )

    sk_for_ep1 = lookup_member_sender_key(reloaded_entry, alice_id, delayed_ep1_pkt["key_id"])
    assert sk_for_ep1 is not None
    assert (
        group_crypto.decrypt_group_message(
            delayed_ep1_pkt,
            sk_for_ep1,
            expected_group_id=group_id,
            expected_sender_device_id=alice_id,
            sender_public_key_b64=alice_pub,
        )
        == "before-charlie-left"
    )

    # Tampering with group_keys.enc MUST fail closed with CryptoError!
    gk_path = SecureStorage._get_group_keys_file("bob_profile")
    raw = bytearray(gk_path.read_bytes())
    raw[-1] ^= 0xFF
    gk_path.write_bytes(bytes(raw))
    with pytest.raises(nacl.exceptions.CryptoError):
        SecureStorage.load_group_keys("bob_profile")
