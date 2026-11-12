import json
import shutil
from types import SimpleNamespace

import keyring
from keyring.backend import KeyringBackend
import pytest

from app import secure_storage
from app.contact_keys import fingerprint_public_key
from app.crypto_box import CryptoManager
from app.delivery import process_delivery_page
from app.double_ratchet import (
    RatchetError,
    RatchetStore,
    ReplayAlreadyProcessed,
    attachment_commitment,
    encrypt_personal_envelope,
    is_double_ratchet_blob,
    sign_dr_blob,
)
from app.incoming_identity import IncomingIdentityError, verify_incoming
from app.outbox_policy import OutboxRecipientError, verify_queued_recipient
from app.secure_storage import SecureStorage


class _MemKeyring(KeyringBackend):
    priority = 10

    def __init__(self):
        self.d = {}

    def get_password(self, svc, user):
        return self.d.get((svc, user))

    def set_password(self, svc, user, pw):
        self.d[(svc, user)] = pw

    def delete_password(self, svc, user):
        self.d.pop((svc, user), None)


@pytest.fixture
def dr_env(tmp_path, monkeypatch):
    keyring.set_keyring(_MemKeyring())
    base = tmp_path / ".max1m"
    monkeypatch.setattr(secure_storage, "BASE_DIR", base)
    monkeypatch.setattr(secure_storage, "CONFIG_FILE", base / "local_state.json")

    alice_cm = CryptoManager()
    bob_cm = CryptoManager()
    eve_cm = CryptoManager()
    for c in (alice_cm, bob_cm, eve_cm):
        c.generate_new_keypair()

    SecureStorage.save_private_key("alice", alice_cm.get_private_key_b64())
    SecureStorage.save_private_key("bob", bob_cm.get_private_key_b64())
    return base, alice_cm, bob_cm, eve_cm


def test_x3dh_double_ratchet_out_of_order_forward_secrecy_and_post_compromise_healing(dr_env, tmp_path):
    base, alice_cm, bob_cm, eve_cm = dr_env
    alice_pub = alice_cm.get_public_key_b64()
    bob_pub = bob_cm.get_public_key_b64()

    bob_store = RatchetStore("bob")
    pub_bundle = bob_store.prepare_publish_bundle(bob_cm.private_key, needed_opks=3)
    claimed_opk = pub_bundle["one_time_keys"][0]
    claimed_snapshot = {
        "device_id": "bob-dev",
        "identity_key": bob_pub,
        "signed_prekey": pub_bundle["signed_prekey"],
        "signature": pub_bundle["signature"],
        "version": pub_bundle["version"],
        "one_time_key": claimed_opk,
    }

    # Forged identity or forged SPK signature MUST fail closed before X3DH!
    alice_store = RatchetStore("alice")
    with pytest.raises(RatchetError):
        alice_store.init_initiator_session_from_bundle(
            our_signing_key=alice_cm.private_key,
            peer_device_id="bob-dev",
            peer_verified_ik_b64=eve_cm.get_public_key_b64(),
            claimed_bundle=claimed_snapshot,
        )

    alice_store.init_initiator_session_from_bundle(
        our_signing_key=alice_cm.private_key,
        peer_device_id="bob-dev",
        peer_verified_ik_b64=bob_pub,
        claimed_bundle=claimed_snapshot,
    )
    assert alice_store.has_active_session("bob-dev", bob_pub)

    # Alice sends 3 offline messages (m0, m1, m2) BEFORE Bob ever comes online!
    w0 = alice_store.encrypt_for_peer(
        our_ik_b64=alice_pub,
        our_device_id="alice-dev",
        peer_device_id="bob-dev",
        peer_verified_ik_b64=bob_pub,
        plaintext="Сообщение #0",
    )
    w1 = alice_store.encrypt_for_peer(
        our_ik_b64=alice_pub,
        our_device_id="alice-dev",
        peer_device_id="bob-dev",
        peer_verified_ik_b64=bob_pub,
        plaintext="Сообщение #1",
    )
    w2 = alice_store.encrypt_for_peer(
        our_ik_b64=alice_pub,
        our_device_id="alice-dev",
        peer_device_id="bob-dev",
        peer_verified_ik_b64=bob_pub,
        plaintext="Сообщение #2",
    )
    assert all(is_double_ratchet_blob(w) for w in (w0, w1, w2))

    # Deliver OUT OF ORDER to Bob: w2 -> w0 -> w1!
    pt2 = bob_store.decrypt_from_peer(
        our_signing_key=bob_cm.private_key,
        our_ik_b64=bob_pub,
        our_device_id="bob-dev",
        peer_device_id="alice-dev",
        peer_verified_ik_b64=alice_pub,
        wire_blob=w2,
    )
    pt0 = bob_store.decrypt_from_peer(
        our_signing_key=bob_cm.private_key,
        our_ik_b64=bob_pub,
        our_device_id="bob-dev",
        peer_device_id="alice-dev",
        peer_verified_ik_b64=alice_pub,
        wire_blob=w0,
    )
    pt1 = bob_store.decrypt_from_peer(
        our_signing_key=bob_cm.private_key,
        our_ik_b64=bob_pub,
        our_device_id="bob-dev",
        peer_device_id="alice-dev",
        peer_verified_ik_b64=alice_pub,
        wire_blob=w1,
    )
    assert (pt0, pt1, pt2) == ("Сообщение #0", "Сообщение #1", "Сообщение #2")

    # FORWARD SECRECY PROOF:
    # Consumed message keys are immediately destroyed; replaying w0, w1, or w2 MUST fail closed!
    for old_wire in (w0, w1, w2):
        with pytest.raises(RatchetError):
            bob_store.decrypt_from_peer(
                our_signing_key=bob_cm.private_key,
                our_ik_b64=bob_pub,
                our_device_id="bob-dev",
                peer_device_id="alice-dev",
                peer_verified_ik_b64=alice_pub,
                wire_blob=old_wire,
            )

    # POST-COMPROMISE SECURITY (SELF-HEALING) PROOF:
    # Simulate an attacker cloning Alice's ENTIRE profile directory (ratchet DB + local key) at T1!
    stolen_alice_dir = tmp_path / "stolen_alice_profile"
    shutil.copytree(base / "profiles" / "alice", stolen_alice_dir)

    # Bob replies (injects fresh ephemeral X25519 ratchet key dh_B1 into KDF_RK)
    bob_reply = bob_store.encrypt_for_peer(
        our_ik_b64=bob_pub,
        our_device_id="bob-dev",
        peer_device_id="alice-dev",
        peer_verified_ik_b64=alice_pub,
        plaintext="Ответ Боба (ротация DH)",
    )
    assert (
        alice_store.decrypt_from_peer(
            our_signing_key=alice_cm.private_key,
            our_ik_b64=alice_pub,
            our_device_id="alice-dev",
            peer_device_id="bob-dev",
            peer_verified_ik_b64=bob_pub,
            wire_blob=bob_reply,
        )
        == "Ответ Боба (ротация DH)"
    )

    # Alice replies (injects fresh ephemeral X25519 ratchet key dh_A2 into KDF_RK!)
    alice_healed = alice_store.encrypt_for_peer(
        our_ik_b64=alice_pub,
        our_device_id="alice-dev",
        peer_device_id="bob-dev",
        peer_verified_ik_b64=bob_pub,
        plaintext="Секрет после исцеления DH",
    )
    assert (
        bob_store.decrypt_from_peer(
            our_signing_key=bob_cm.private_key,
            our_ik_b64=bob_pub,
            our_device_id="bob-dev",
            peer_device_id="alice-dev",
            peer_verified_ik_b64=alice_pub,
            wire_blob=alice_healed,
        )
        == "Секрет после исцеления DH"
    )

    # Bob sends a post-healing message to Alice
    bob_post_heal = bob_store.encrypt_for_peer(
        our_ik_b64=bob_pub,
        our_device_id="bob-dev",
        peer_device_id="alice-dev",
        peer_verified_ik_b64=alice_pub,
        plaintext="Недоступно для хакера со слепком T1!",
    )

    # Restore attacker's T1 snapshot into a separate profile "attacker_clone" with Alice's exact keys!
    shutil.rmtree(base / "profiles" / "alice")
    shutil.copytree(stolen_alice_dir, base / "profiles" / "alice")
    attacker_store = RatchetStore("alice")

    # Attacker with full T1 state CANNOT decrypt `bob_post_heal` because Alice's dh_A2 private key
    # was generated AFTER T1!
    with pytest.raises(RatchetError):
        attacker_store.decrypt_from_peer(
            our_signing_key=alice_cm.private_key,
            our_ik_b64=alice_pub,
            our_device_id="alice-dev",
            peer_device_id="bob-dev",
            peer_verified_ik_b64=bob_pub,
            wire_blob=bob_post_heal,
        )


def test_double_ratchet_outbox_policy_and_two_phase_crash_safe_delivery(dr_env):
    _, alice_cm, bob_cm, eve_cm = dr_env
    alice_pub = alice_cm.get_public_key_b64()
    bob_pub = bob_cm.get_public_key_b64()

    bob_store = RatchetStore("bob")
    bundle = bob_store.prepare_publish_bundle(bob_cm.private_key, needed_opks=2)
    RatchetStore("alice").init_initiator_session_from_bundle(
        our_signing_key=alice_cm.private_key,
        peer_device_id="bob-dev",
        peer_verified_ik_b64=bob_pub,
        claimed_bundle={
            "device_id": "bob-dev",
            "identity_key": bob_pub,
            "signed_prekey": bundle["signed_prekey"],
            "signature": bundle["signature"],
            "version": bundle["version"],
            "one_time_key": bundle["one_time_keys"][0],
        },
    )

    alice_state = SimpleNamespace(
        username="alice",
        device_id="alice-dev",
        server_url="https://node.local",
        allies={
            "bob": {
                "devices": [
                    {
                        "device_id": "bob-dev",
                        "public_key": bob_pub,
                        "verified_fingerprint": fingerprint_public_key(bob_pub),
                        "verified_scope": {
                            "username": "alice",
                            "device_id": "alice-dev",
                            "server_url": "https://node.local",
                        },
                    }
                ]
            }
        },
    )

    # 1. Attachment Double Ratchet envelope passes `verify_queued_recipient` with `return_attachment_key=True`
    import uuid
    f_key = alice_cm.generate_file_key()
    fid = str(uuid.uuid4())
    mid = "msg_att_1"
    att_msg = {"type": "image", "file_id": fid, "secret_key": f_key, "caption": "Чертёж", "msg_id": mid}
    env_att, used_dr = encrypt_personal_envelope(
        owner_username="alice",
        owner_device_id="alice-dev",
        crypto_mgr=alice_cm,
        recipient_device_id="bob-dev",
        recipient_pub_b64=bob_pub,
        plaintext=json.dumps(att_msg, ensure_ascii=False),
        msg_kind="image",
        attachment_commit=attachment_commitment(fid, f_key, mid),
    )
    assert used_dr is True
    queued_att = {
        "receiver_device_id": "bob-dev",
        **env_att,
        "_local_history": {
            "ally_username": "bob",
            "text": f"[IMAGE_META]|{fid}|{f_key}|Чертёж",
            "msg_id": mid,
        },
    }
    ctx_ok, extracted_key = verify_queued_recipient(
        alice_state, alice_cm, queued_att, attachment_file_id=fid, return_attachment_key=True
    )
    assert ctx_ok.username == "bob" and extracted_key == f_key

    # Key replacement on Bob's device MUST block queued DR envelope in outbox!
    alice_state.allies["bob"]["devices"][0].update(
        public_key=eve_cm.get_public_key_b64(),
        verified_fingerprint=fingerprint_public_key(eve_cm.get_public_key_b64()),
    )
    with pytest.raises(OutboxRecipientError):
        verify_queued_recipient(alice_state, alice_cm, queued_att, attachment_file_id=fid)

    # 2. Two-phase crash-safe incoming delivery + conflicting server ID rejection on Bob
    bob_state = SimpleNamespace(
        username="bob",
        device_id="bob-dev",
        server_url="https://node.local",
        allies={
            "alice": {
                "devices": [
                    {
                        "device_id": "alice-dev",
                        "public_key": alice_pub,
                        "verified_fingerprint": fingerprint_public_key(alice_pub),
                        "verified_scope": {
                            "username": "bob",
                            "device_id": "bob-dev",
                            "server_url": "https://node.local",
                        },
                    }
                ]
            }
        },
    )
    wire_env = {
        "id": "srv-dr-100",
        "sender_device_id": "alice-dev",
        **env_att,
    }

    # Phase 1: Bob decrypts before history persistence -> if crash happens before mark_delivery_persisted,
    # retry STILL returns the decrypted plaintext so history is never lost!
    _, pt_first = verify_incoming(bob_state, bob_cm, wire_env)
    _, pt_retry_before_persist = verify_incoming(bob_state, bob_cm, wire_env)
    assert json.loads(pt_first)["caption"] == "Чертёж"
    assert pt_retry_before_persist == pt_first

    # Phase 2: Once history is saved, `mark_delivery_persisted` scrubs staged plaintext;
    # subsequent server redelivery returns idempotent `dr_already_processed` without keeping plaintext!
    RatchetStore("bob").mark_delivery_persisted("srv-dr-100")
    _, pt_after_persist = verify_incoming(bob_state, bob_cm, wire_env)
    assert json.loads(pt_after_persist) == {"type": "dr_already_processed"}
    assert b"\xd0\xa7\xd0\xb5\xd1\x80\xd1\x82\xd1\x91\xd0\xb6" not in RatchetStore("bob").db_path.read_bytes()

    # Conflicting ciphertext under the same server delivery ID MUST be rejected fail-closed!
    env2, _ = encrypt_personal_envelope(
        owner_username="alice",
        owner_device_id="alice-dev",
        crypto_mgr=alice_cm,
        recipient_device_id="bob-dev",
        recipient_pub_b64=bob_pub,
        plaintext=json.dumps({"type": "text", "text": "Другое", "msg_id": "m2"}),
        msg_kind="text",
    )
    conflicting_wire = {"id": "srv-dr-100", "sender_device_id": "alice-dev", **env2}
    with pytest.raises(IncomingIdentityError):
        verify_incoming(bob_state, bob_cm, conflicting_wire)
