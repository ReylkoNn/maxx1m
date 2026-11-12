"""End-to-end backend regression tests for Protected Group Protocol v2."""

import base64
import json
import uuid

from nacl.encoding import Base64Encoder
from nacl.public import Box
from nacl.signing import SigningKey, VerifyKey
from fastapi.testclient import TestClient

from app import models
from app.config import settings
from app.database import AsyncSessionLocal
from app.main import app
from app.security import create_access_token


def _auth(user_id: str, device_id: str) -> dict:
    tok = create_access_token({"sub": user_id, "device_id": device_id})
    return {"Authorization": f"Bearer {tok}"}


def _seal_sender_key(sk_priv: SigningKey, recipient_pub_b64: str, payload_obj: dict) -> tuple[str, str]:
    rvk = VerifyKey(recipient_pub_b64.encode("ascii"), encoder=Base64Encoder)
    box = Box(sk_priv.to_curve25519_private_key(), rvk.to_curve25519_public_key())
    cipher = box.encrypt(json.dumps(payload_obj, separators=(",", ":")).encode("utf-8"))
    sig = sk_priv.sign(cipher).signature
    return (
        base64.b64encode(cipher).decode("ascii"),
        base64.b64encode(sig).decode("ascii"),
    )


def _sign_group_v2_msg(
    sk_priv: SigningKey,
    group_id: str,
    sender_device_id: str,
    sender_key_id: str,
    epoch: int,
    chain_index: int,
    encrypted_blob: str,
) -> str:
    canon = (
        b"max1m-group-msg-sig-v2\x00"
        + json.dumps(
            {
                "blob": encrypted_blob,
                "chain_index": chain_index,
                "epoch": epoch,
                "group_id": group_id,
                "sender_device_id": sender_device_id,
                "sender_key_id": sender_key_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return base64.b64encode(sk_priv.sign(canon).signature).decode("ascii")


def test_groups_v2_create_distribute_send_invite_leave_epoch_and_forged_sig_rejection(monkeypatch):
    # Ensure insecure legacy endpoints remain disabled (503) while v2 works securely!
    monkeypatch.setattr(settings, "ALLOW_INSECURE_LEGACY_GROUPS", False)
    monkeypatch.setattr(settings, "MAX_PENDING_PER_DEVICE", 3)

    alice_sk = SigningKey.generate()
    bob_sk = SigningKey.generate()
    charlie_sk = SigningKey.generate()

    alice_pub = alice_sk.verify_key.encode(encoder=Base64Encoder).decode("ascii")
    bob_pub = bob_sk.verify_key.encode(encoder=Base64Encoder).decode("ascii")
    charlie_pub = charlie_sk.verify_key.encode(encoder=Base64Encoder).decode("ascii")

    with TestClient(app) as client:
        async def seed():
            sfx = uuid.uuid4().hex[:10]
            async with AsyncSessionLocal() as db:
                out = []
                for label, pub in (("alice", alice_pub), ("bob", bob_pub), ("charlie", charlie_pub)):
                    u = models.User(username=f"{label}_{sfx}", password_hash="unused")
                    db.add(u)
                    await db.flush()
                    d = models.Device(
                        user_id=u.id,
                        device_name=f"{label}-dev",
                        public_key=pub,
                        fingerprint=f"fp-{label}-{sfx}",
                    )
                    db.add(d)
                    await db.flush()
                    out.append((u.id, d.id))
                await db.commit()
                return out

        (alice_uid, alice_did), (bob_uid, bob_did), (charlie_uid, charlie_did) = client.portal.call(seed)
        h_alice = _auth(alice_uid, alice_did)
        h_bob = _auth(bob_uid, bob_did)
        h_charlie = _auth(charlie_uid, charlie_did)

        # 1. Legacy /groups/create stays blocked (503), while /groups/v2/create verifies Ed25519 signature.
        enc_ab, sig_ab = _seal_sender_key(alice_sk, bob_pub, {"v": 2, "epoch": 1})
        assert client.post(
            "/groups/create",
            headers=h_alice,
            json={
                "name": "LegacyBlocked",
                "member_device_ids": [bob_did],
                "sender_keys": [
                    {
                        "recipient_device_id": bob_did,
                        "encrypted_sender_key": enc_ab,
                        "sender_key_signature": sig_ab,
                    }
                ],
            },
        ).status_code == 503

        # Forged signature (signed by Bob instead of Alice) on /groups/v2/create -> 400!
        _, bad_sig = _seal_sender_key(bob_sk, bob_pub, {"v": 2, "epoch": 1})
        forged_create = client.post(
            "/groups/v2/create",
            headers=h_alice,
            json={
                "name": "Forged",
                "member_device_ids": [bob_did],
                "sender_keys": [
                    {
                        "sender_device_id": alice_did,
                        "recipient_device_id": bob_did,
                        "encrypted_sender_key": enc_ab,
                        "sender_key_signature": bad_sig,
                    }
                ],
            },
        )
        assert forged_create.status_code == 400

        # Valid /groups/v2/create -> 200 at epoch 1
        created = client.post(
            "/groups/v2/create",
            headers=h_alice,
            json={
                "name": "Core Team",
                "member_device_ids": [bob_did],
                "sender_keys": [
                    {
                        "sender_device_id": alice_did,
                        "recipient_device_id": bob_did,
                        "encrypted_sender_key": enc_ab,
                        "sender_key_signature": sig_ab,
                    }
                ],
            },
        )
        assert created.status_code == 200, created.text
        group_id = created.json()["id"]
        assert created.json()["epoch"] == 1

        # 2. Bob publishes his own SenderKey via /groups/v2/{group_id}/distribute-key
        enc_ba, sig_ba = _seal_sender_key(bob_sk, alice_pub, {"v": 2, "group_id": group_id, "epoch": 1})
        dist = client.post(
            f"/groups/v2/{group_id}/distribute-key",
            headers=h_bob,
            json={
                "epoch": 1,
                "sender_keys": [
                    {
                        "sender_device_id": bob_did,
                        "recipient_device_id": alice_did,
                        "encrypted_sender_key": enc_ba,
                        "sender_key_signature": sig_ba,
                    }
                ],
            },
        )
        assert dist.status_code == 200
        alice_bundles = client.get(f"/groups/{group_id}/sender_keys", headers=h_alice).json()
        assert len(alice_bundles) == 1 and alice_bundles[0]["sender_device_id"] == bob_did

        # 3. /groups/v2/send rejects forged signature & wrong epoch, accepts authentic message,
        #    and enforces MAX_PENDING_DELIVERIES_PER_RECIPIENT (3).
        blob_b64 = base64.b64encode(b"ciphertext-0").decode("ascii")
        good_msg_sig = _sign_group_v2_msg(alice_sk, group_id, alice_did, "keyid_0001", 1, 0, blob_b64)
        bad_msg_sig = _sign_group_v2_msg(bob_sk, group_id, alice_did, "keyid_0001", 1, 0, blob_b64)

        assert client.post(
            "/groups/v2/send",
            headers=h_alice,
            json={
                "group_id": group_id,
                "encrypted_blob": blob_b64,
                "signature": bad_msg_sig,
                "sender_key_id": "keyid_0001",
                "epoch": 1,
                "chain_index": 0,
            },
        ).status_code == 400

        assert client.post(
            "/groups/v2/send",
            headers=h_alice,
            json={
                "group_id": group_id,
                "encrypted_blob": blob_b64,
                "signature": good_msg_sig,
                "sender_key_id": "keyid_0001",
                "epoch": 2,
                "chain_index": 0,
            },
        ).status_code == 409

        sent_ids = []
        for idx in range(3):
            sig_i = _sign_group_v2_msg(alice_sk, group_id, alice_did, "keyid_0001", 1, idx, blob_b64)
            r = client.post(
                "/groups/v2/send",
                headers=h_alice,
                json={
                    "group_id": group_id,
                    "encrypted_blob": blob_b64,
                    "signature": sig_i,
                    "sender_key_id": "keyid_0001",
                    "epoch": 1,
                    "chain_index": idx,
                },
            )
            assert r.status_code == 200, r.text
            sent_ids.append(r.json()["id"])

        # 4th unacknowledged message hits MAX_PENDING_DELIVERIES_PER_RECIPIENT=3 -> 429!
        sig_3 = _sign_group_v2_msg(alice_sk, group_id, alice_did, "keyid_0001", 1, 3, blob_b64)
        assert client.post(
            "/groups/v2/send",
            headers=h_alice,
            json={
                "group_id": group_id,
                "encrypted_blob": blob_b64,
                "signature": sig_3,
                "sender_key_id": "keyid_0001",
                "epoch": 1,
                "chain_index": 3,
            },
        ).status_code == 429

        # Bob syncs safely and acknowledges -> queue drains cleanly!
        synced = client.get("/groups/sync-safe", headers=h_bob).json()
        assert [m["id"] for m in synced] == sent_ids
        assert client.post("/groups/ack", headers=h_bob, json={"message_ids": sent_ids}).status_code == 200
        assert client.get("/groups/sync-safe", headers=h_bob).json() == []

        # 4. Alice invites Charlie via /groups/v2/invite -> bumps epoch 1 -> 2!
        enc_ab2, sig_ab2 = _seal_sender_key(alice_sk, bob_pub, {"v": 2, "epoch": 2})
        enc_ac2, sig_ac2 = _seal_sender_key(alice_sk, charlie_pub, {"v": 2, "epoch": 2})
        inv = client.post(
            "/groups/v2/invite",
            headers=h_alice,
            json={
                "group_id": group_id,
                "new_member_device_id": charlie_did,
                "sender_keys": [
                    {
                        "sender_device_id": alice_did,
                        "recipient_device_id": bob_did,
                        "encrypted_sender_key": enc_ab2,
                        "sender_key_signature": sig_ab2,
                    },
                    {
                        "sender_device_id": alice_did,
                        "recipient_device_id": charlie_did,
                        "encrypted_sender_key": enc_ac2,
                        "sender_key_signature": sig_ac2,
                    },
                ],
            },
        )
        assert inv.status_code == 200, inv.text
        assert inv.json()["epoch"] == 2

        # Sending with stale epoch=1 now fails with 409!
        assert client.post(
            "/groups/v2/send",
            headers=h_alice,
            json={
                "group_id": group_id,
                "encrypted_blob": blob_b64,
                "signature": good_msg_sig,
                "sender_key_id": "keyid_0001",
                "epoch": 1,
                "chain_index": 0,
            },
        ).status_code == 409

        # 5. Charlie leaves -> bumps epoch 2 -> 3 and revokes Charlie's access!
        left = client.post(f"/groups/{group_id}/leave", headers=h_charlie)
        assert left.status_code == 200 and left.json()["epoch"] == 3
        assert client.get(f"/groups/{group_id}/sender_keys", headers=h_charlie).status_code == 403

        # Alice rotates to epoch 3 for remaining member Bob and sends epoch-3 message: Charlie gets nothing!
        enc_ab3, sig_ab3 = _seal_sender_key(alice_sk, bob_pub, {"v": 2, "epoch": 3})
        assert client.post(
            f"/groups/v2/{group_id}/distribute-key",
            headers=h_alice,
            json={
                "epoch": 3,
                "sender_keys": [
                    {
                        "sender_device_id": alice_did,
                        "recipient_device_id": bob_did,
                        "encrypted_sender_key": enc_ab3,
                        "sender_key_signature": sig_ab3,
                    }
                ],
            },
        ).status_code == 200

        sig_ep3 = _sign_group_v2_msg(alice_sk, group_id, alice_did, "keyid_ep03", 3, 0, blob_b64)
        assert client.post(
            "/groups/v2/send",
            headers=h_alice,
            json={
                "group_id": group_id,
                "encrypted_blob": blob_b64,
                "signature": sig_ep3,
                "sender_key_id": "keyid_ep03",
                "epoch": 3,
                "chain_index": 0,
            },
        ).status_code == 200
        assert len(client.get("/groups/sync-safe", headers=h_bob).json()) == 1
        assert client.get("/groups/sync-safe", headers=h_charlie).json() == []
