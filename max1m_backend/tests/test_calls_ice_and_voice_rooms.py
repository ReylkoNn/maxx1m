"""
Tests for Package IV (Backend):
1. `GET /calls/ice-config` ephemeral coturn HMAC-SHA1 credentials including
   `turns:<host>:443?transport=tcp` for VPN-free WebRTC calls in RU.
2. RAM-only Discord-grade Group Voice & Screen-Share Rooms (2–8 participants,
   membership enforcement, E2EE WebRTC signaling relay, and automatic eviction
   on WebSocket disconnect).
"""

import asyncio
import base64
import hashlib
import hmac
import uuid

from fastapi.testclient import TestClient

from app import models
from app.config import settings
from app.database import AsyncSessionLocal
from app.main import app
from app.security import create_access_token


def _seed_user_and_device(client: TestClient, username: str, public_key: str) -> tuple[str, str]:
    async def _create():
        async with AsyncSessionLocal() as db:
            user = models.User(
                id=str(uuid.uuid4()),
                username=username,
                password_hash="argon2id$test",
            )
            dev_id = str(uuid.uuid4())
            dev = models.Device(
                id=dev_id,
                user_id=user.id,
                device_name=f"{username}-ws",
                public_key=public_key,
                fingerprint=f"fp-{uuid.uuid4().hex[:16]}",
            )
            db.add(user)
            db.add(dev)
            await db.commit()
            token = create_access_token({"sub": str(user.id), "device_id": dev_id, "sv": 0})
            return dev_id, token

    return client.portal.call(_create)


def _seed_group(client: TestClient, group_id: str, creator_dev: str, member_devs: list[str]) -> None:
    async def _create():
        async with AsyncSessionLocal() as db:
            grp = models.Group(
                id=group_id,
                name="[E2EE]",
                created_by_device_id=creator_dev,
            )
            db.add(grp)
            for dev_id in member_devs:
                db.add(
                    models.GroupMember(
                        id=str(uuid.uuid4()),
                        group_id=group_id,
                        device_id=dev_id,
                        role="admin" if dev_id == creator_dev else "member",
                    )
                )
            await db.commit()

    client.portal.call(_create)


def test_ice_config_generates_ephemeral_coturn_hmac_sha1_with_turns_443(monkeypatch):
    secret = "super-secret-coturn-shared-hmac-key-2026"
    monkeypatch.setattr(settings, "CALL_STUN_URLS", "stun:turn.company.ru:3478")
    monkeypatch.setattr(
        settings,
        "CALL_TURN_URLS",
        "turn:turn.company.ru:3478?transport=udp,turn:turn.company.ru:3478?transport=tcp,turns:turn.company.ru:443?transport=tcp",
    )
    monkeypatch.setattr(settings, "CALL_TURN_SHARED_SECRET", secret)
    monkeypatch.setattr(settings, "CALL_TURN_CREDENTIAL_TTL_SECONDS", 1800)
    monkeypatch.setattr(settings, "CALL_FORCE_RELAY_RECOMMENDED", True)

    with TestClient(app) as client:
        unauth = client.get("/calls/ice-config")
        assert unauth.status_code == 401

        alice_dev, alice_tok = _seed_user_and_device(
            client,
            f"ice_alice_{uuid.uuid4().hex[:8]}",
            base64.b64encode(b"A" * 32).decode("ascii"),
        )
        r = client.get("/calls/ice-config", headers={"Authorization": f"Bearer {alice_tok}"})
        assert r.status_code == 200, r.text
        data = r.json()

        assert data["turn_configured"] is True
        assert data["has_turns_443"] is True
        assert data["ttl_seconds"] == 1800
        assert data["relay_only_recommended"] is True
        assert len(data["ice_servers"]) == 2
        assert data["ice_servers"][0] == {"urls": ["stun:turn.company.ru:3478"]}

        turn_entry = data["ice_servers"][1]
        assert "turns:turn.company.ru:443?transport=tcp" in turn_entry["urls"]
        turn_user = turn_entry["username"]
        exp_str, bound_dev = turn_user.split(":", 1)
        assert bound_dev == alice_dev
        assert int(exp_str) == data["expires_at"]

        expected_cred = base64.b64encode(
            hmac.new(secret.encode("utf-8"), turn_user.encode("utf-8"), hashlib.sha1).digest()
        ).decode("ascii")
        assert turn_entry["credential"] == expected_cred


def test_group_voice_room_presence_cap_e2ee_signal_and_ws_disconnect_eviction(monkeypatch):
    monkeypatch.setattr(settings, "MAX_GROUP_VOICE_PEERS", 2)

    with TestClient(app) as client:
        alice_dev, alice_tok = _seed_user_and_device(
            client,
            f"vr_alice_{uuid.uuid4().hex[:8]}",
            base64.b64encode(b"1" * 32).decode("ascii"),
        )
        bob_dev, bob_tok = _seed_user_and_device(
            client,
            f"vr_bob_{uuid.uuid4().hex[:8]}",
            base64.b64encode(b"2" * 32).decode("ascii"),
        )
        charlie_dev, charlie_tok = _seed_user_and_device(
            client,
            f"vr_charlie_{uuid.uuid4().hex[:8]}",
            base64.b64encode(b"3" * 32).decode("ascii"),
        )
        eve_dev, eve_tok = _seed_user_and_device(
            client,
            f"vr_eve_{uuid.uuid4().hex[:8]}",
            base64.b64encode(b"9" * 32).decode("ascii"),
        )

        gid = str(uuid.uuid4())
        _seed_group(client, gid, alice_dev, [alice_dev, bob_dev, charlie_dev])

        # Non-member Eve is rejected everywhere (fail-closed)
        assert client.get(
            f"/calls/groups/{gid}/voice/state",
            headers={"Authorization": f"Bearer {eve_tok}"},
        ).status_code == 403
        assert client.post(
            f"/calls/groups/{gid}/voice/join",
            headers={"Authorization": f"Bearer {eve_tok}"},
        ).status_code == 403

        # Connect Alice and Bob WebSockets to observe live presence & E2EE signals
        with client.websocket_connect(
            f"/messages/ws/{alice_dev}",
            headers={"Authorization": f"Bearer {alice_tok}"},
        ) as ws_alice, client.websocket_connect(
            f"/messages/ws/{bob_dev}",
            headers={"Authorization": f"Bearer {bob_tok}"},
        ) as ws_bob:
            # Alice joins voice room
            r_join_a = client.post(
                f"/calls/groups/{gid}/voice/join",
                headers={"Authorization": f"Bearer {alice_tok}"},
                json={"is_muted": False, "is_deafened": False, "is_sharing_screen": False},
            )
            assert r_join_a.status_code == 200
            ev_a = ws_alice.receive_json()
            ev_b = ws_bob.receive_json()
            assert ev_a["type"] == "group_voice_state" and len(ev_a["participants"]) == 1
            assert ev_b["type"] == "group_voice_state" and ev_b["participants"][0]["device_id"] == alice_dev

            # Signaling to Bob BEFORE Bob joins the voice room must fail closed (409)
            r_premature = client.post(
                f"/calls/groups/{gid}/voice/signal",
                headers={"Authorization": f"Bearer {alice_tok}"},
                json={
                    "target_device_id": bob_dev,
                    "channel": "voice",
                    "encrypted_blob": "TTFEUjAx_dummy_sdp",
                    "signature": "sig_b64",
                },
            )
            assert r_premature.status_code == 409

            # Bob joins voice room (room now has 2/2 peers)
            r_join_b = client.post(
                f"/calls/groups/{gid}/voice/join",
                headers={"Authorization": f"Bearer {bob_tok}"},
                json={"is_muted": False, "is_deafened": False, "is_sharing_screen": True},
            )
            assert r_join_b.status_code == 200
            assert ws_alice.receive_json()["participants"][1]["is_sharing_screen"] is True
            assert len(ws_bob.receive_json()["participants"]) == 2

            # Charlie tries to join when room is at MAX_GROUP_VOICE_PEERS=2 -> 409 Conflict
            r_full = client.post(
                f"/calls/groups/{gid}/voice/join",
                headers={"Authorization": f"Bearer {charlie_tok}"},
            )
            assert r_full.status_code == 409

            # Alice relays E2EE WebRTC offer to Bob inside the voice room
            r_sig = client.post(
                f"/calls/groups/{gid}/voice/signal",
                headers={"Authorization": f"Bearer {alice_tok}"},
                json={
                    "target_device_id": bob_dev,
                    "channel": "screen",
                    "encrypted_blob": "ENC_SDP_OFFER_BLOB",
                    "signature": "ED25519_SIG_BLOB",
                },
            )
            assert r_sig.status_code == 200 and r_sig.json()["delivered"] is True
            relayed = ws_bob.receive_json()
            assert relayed["type"] == "group_voice_signal"
            assert relayed["group_id"] == gid
            assert relayed["sender_device_id"] == alice_dev
            assert relayed["channel"] == "screen"
            assert relayed["encrypted_blob"] == "ENC_SDP_OFFER_BLOB"
            assert relayed["signature"] == "ED25519_SIG_BLOB"

        # Once Bob's WebSocket closes (above context exit), keep Alice's WS open in a fresh check:
        # verify Bob was automatically evicted from RAM voice room!
        st_after = client.get(
            f"/calls/groups/{gid}/voice/state",
            headers={"Authorization": f"Bearer {charlie_tok}"},
        )
        assert st_after.status_code == 200
        assert st_after.json()["participants"] == []
