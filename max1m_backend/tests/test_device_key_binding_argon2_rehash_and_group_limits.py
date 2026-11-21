"""Regression tests for Package #8 backend features:
- Ed25519 public-key & SHA-256 fingerprint binding (anti-fingerprint-squatting by default + strict mode)
- Argon2id settings wiring, transparent password hash upgrade on login, and JWT algorithm whitelist
- Group endpoint group_id validation and /groups/sync-safe cursor/limit bounds
"""
import base64
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jose import JWTError
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import models, security
from app.config import settings, validate_secret_key
from app.database import AsyncSessionLocal
from app.main import app
from app.rate_limit import limiter


@pytest.fixture(autouse=True)
def _reset_limiter():
    limiter.reset()
    yield
    limiter.reset()


def _seed_invite(client: TestClient) -> str:
    code = f"INV-{uuid.uuid4().hex[:12].upper()}"

    async def _ins():
        async with AsyncSessionLocal() as db:
            db.add(models.InviteCode(code=code))
            await db.commit()

    client.portal.call(_ins)
    return code


def _gen_ed25519_pair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    fp = security.fingerprint_ed25519_public_key(pub_b64)
    return pub_b64, fp


def test_fingerprint_squatting_blocked_by_default_and_strict_mode_enforced(monkeypatch):
    victim_pub, victim_fp = _gen_ed25519_pair()
    attacker_pub, attacker_fp = _gen_ed25519_pair()
    assert victim_fp != attacker_fp

    with TestClient(app) as client:
        # 1. Default mode (REQUIRE_VERIFIED_DEVICE_KEYS=False):
        # Attacker tries to squat victim's real colon-formatted SHA-256 fingerprint under attacker_pub
        monkeypatch.setattr(settings, "REQUIRE_VERIFIED_DEVICE_KEYS", False)
        atk_invite = _seed_invite(client)
        squat_reg = client.post(
            "/auth/register",
            json={
                "username": f"squat_{uuid.uuid4().hex[:8]}",
                "password": "AttackerPass!123",
                "invite_code": atk_invite,
                "device_name": "FakeDevice",
                "public_key": attacker_pub,
                "fingerprint": victim_fp,
            },
        )
        assert squat_reg.status_code == 400

        # Invite was NOT consumed, and victim can register their genuine key + fingerprint!
        vic_invite = _seed_invite(client)
        vic_user = f"victim_{uuid.uuid4().hex[:8]}"
        ok_reg = client.post(
            "/auth/register",
            json={
                "username": vic_user,
                "password": "VictimPass!123",
                "invite_code": vic_invite,
                "device_name": "VictimPC",
                "public_key": victim_pub,
                "fingerprint": victim_fp,
            },
        )
        assert ok_reg.status_code == 201, ok_reg.text

        # Attacker also cannot squat a colon fingerprint via secondary-device /auth/login
        atk_user = f"atklog_{uuid.uuid4().hex[:8]}"
        atk_reg_ok = client.post(
            "/auth/register",
            json={
                "username": atk_user,
                "password": "AttackerPass!123",
                "invite_code": atk_invite,
                "device_name": "AtkPC",
                "public_key": attacker_pub,
                "fingerprint": attacker_fp,
            },
        )
        assert atk_reg_ok.status_code == 201, atk_reg_ok.text
        _, target_fp2 = _gen_ed25519_pair()
        other_pub2, _ = _gen_ed25519_pair()
        squat_login = client.post(
            "/auth/login",
            json={
                "username": atk_user,
                "password": "AttackerPass!123",
                "device_name": "Squatter2",
                "public_key": other_pub2,
                "fingerprint": target_fp2,
            },
        )
        assert squat_login.status_code == 400

        # 2. Strict mode (REQUIRE_VERIFIED_DEVICE_KEYS=True): rejects synthetic non-Ed25519 keys/fingerprints
        limiter.reset()
        monkeypatch.setattr(settings, "REQUIRE_VERIFIED_DEVICE_KEYS", True)
        strict_invite = _seed_invite(client)
        bad_strict = client.post(
            "/auth/register",
            json={
                "username": f"strict_{uuid.uuid4().hex[:8]}",
                "password": "StrictPass!123",
                "invite_code": strict_invite,
                "device_name": "SyntheticDev",
                "public_key": "not-an-ed25519-key",
                "fingerprint": f"fp-{uuid.uuid4().hex}",
            },
        )
        assert bad_strict.status_code == 400

        good_pub, good_fp = _gen_ed25519_pair()
        good_strict = client.post(
            "/auth/register",
            json={
                "username": f"strict_{uuid.uuid4().hex[:8]}",
                "password": "StrictPass!123",
                "invite_code": strict_invite,
                "device_name": "VerifiedDev",
                "public_key": good_pub,
                "fingerprint": good_fp,
            },
        )
        assert good_strict.status_code == 201, good_strict.text


def test_argon2_settings_transparent_rehash_and_jwt_algorithm_whitelist(monkeypatch):
    with TestClient(app) as client:
        monkeypatch.setattr(settings, "ARGON2_TIME_COST", 2)
        monkeypatch.setattr(settings, "ARGON2_MEMORY_COST", 19456)
        monkeypatch.setattr(settings, "ARGON2_PARALLELISM", 1)

        invite = _seed_invite(client)
        username = f"rehash_{uuid.uuid4().hex[:8]}"
        password = "RehashTarget!99"
        pub, fp = _gen_ed25519_pair()
        reg = client.post(
            "/auth/register",
            json={
                "username": username,
                "password": password,
                "invite_code": invite,
                "device_name": "Laptop",
                "public_key": pub,
                "fingerprint": fp,
            },
        )
        assert reg.status_code == 201, reg.text
        user_id = reg.json()["user_id"]
        device_id = reg.json()["device_id"]

        async def _get_hash() -> str:
            async with AsyncSessionLocal() as db:
                row = await db.get(models.User, user_id)
                return row.password_hash

        initial_hash = client.portal.call(_get_hash)
        assert "m=19456,t=2,p=1" in initial_hash

        # Increase Argon2 cost in settings -> next login transparently upgrades stored hash
        monkeypatch.setattr(settings, "ARGON2_TIME_COST", 3)
        monkeypatch.setattr(settings, "ARGON2_MEMORY_COST", 32768)
        monkeypatch.setattr(settings, "ARGON2_PARALLELISM", 2)
        assert security.check_needs_rehash(initial_hash) is True

        login_resp = client.post(
            "/auth/login",
            json={"username": username, "password": password, "device_id": device_id},
        )
        assert login_resp.status_code == 200, login_resp.text
        token = login_resp.json()["access_token"]

        upgraded_hash = client.portal.call(_get_hash)
        assert upgraded_hash != initial_hash
        assert "m=32768,t=3,p=2" in upgraded_hash
        assert security.check_needs_rehash(upgraded_hash) is False

        # JWT algorithm whitelist blocks "none" / "RS256" misconfiguration
        monkeypatch.setattr(settings, "ALGORITHM", "none")
        with pytest.raises(ValueError):
            validate_secret_key()
        with pytest.raises(ValueError):
            security.create_access_token({"sub": user_id, "device_id": device_id})
        with pytest.raises(JWTError):
            security.decode_access_token(token)
        assert (
            client.get("/auth/devices", headers={"Authorization": f"Bearer {token}"}).status_code
            == 401
        )

        # Unsafe Argon2 floor rejected by validate_secret_key
        monkeypatch.setattr(settings, "ALGORITHM", "HS256")
        monkeypatch.setattr(settings, "ARGON2_MEMORY_COST", 1024)
        with pytest.raises(ValueError):
            validate_secret_key()


def test_group_id_validation_and_sync_safe_limit_and_cursor_bounds():
    with TestClient(app) as client:
        pub, fp = _gen_ed25519_pair()
        username = f"grp8_{uuid.uuid4().hex[:8]}"
        pw = "GroupPass!123"
        reg = client.post(
            "/auth/register",
            json={
                "username": username,
                "password": pw,
                "invite_code": _seed_invite(client),
                "device_name": "GroupDev",
                "public_key": pub,
                "fingerprint": fp,
            },
        )
        dev_id = reg.json()["device_id"]
        token = client.post(
            "/auth/login",
            json={"username": username, "password": pw, "device_id": dev_id},
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Malformed group_id rejected with 400 on members & sender_keys
        bad_id = "bad!group$id"
        assert client.get(f"/groups/{bad_id}/members", headers=headers).status_code == 400
        assert client.get(f"/groups/{bad_id}/sender_keys", headers=headers).status_code == 400

        # Malformed cursor rejected with 400 on /groups/sync-safe
        assert client.get("/groups/sync-safe", params={"after": "bad!cursor"}, headers=headers).status_code == 400
        assert client.get("/groups/sync-safe", params={"limit": 101}, headers=headers).status_code == 422

        # Seed 3 pending group deliveries and verify limit=2 pagination
        async def _seed_group_deliveries():
            async with AsyncSessionLocal() as db:
                other_dev = models.Device(
                    user_id=(await db.execute(select(models.User.id).where(models.User.username == username))).scalar_one(),
                    device_name="PeerGroupDev",
                    public_key="peer-pk",
                    fingerprint=f"fp-{uuid.uuid4().hex}",
                )
                db.add(other_dev)
                await db.flush()
                grp = models.Group(name="BoundedGroup", created_by_device_id=other_dev.id)
                db.add(grp)
                await db.flush()
                db.add_all(
                    [
                        models.GroupMember(group_id=grp.id, device_id=other_dev.id, role="owner"),
                        models.GroupMember(group_id=grp.id, device_id=dev_id, role="member"),
                    ]
                )
                await db.flush()
                for idx in range(3):
                    gm = models.GroupMessage(
                        id=f"gm-{uuid.uuid4().hex[:12]}-{idx}",
                        group_id=grp.id,
                        sender_device_id=other_dev.id,
                        encrypted_blob=f"blob-{idx}",
                        signature=f"sig-{idx}",
                        sender_key_id="sk1",
                        chain_index=idx,
                    )
                    db.add(gm)
                    await db.flush()
                    db.add(models.GroupMessageDelivery(message_id=gm.id, device_id=dev_id, is_delivered=False))
                await db.commit()

        client.portal.call(_seed_group_deliveries)
        page1 = client.get("/groups/sync-safe", params={"limit": 2}, headers=headers)
        assert page1.status_code == 200
        items1 = page1.json()
        assert len(items1) == 2

        page2 = client.get("/groups/sync-safe", params={"after": items1[-1]["id"], "limit": 2}, headers=headers)
        assert page2.status_code == 200
        items2 = page2.json()
        assert len(items2) == 1
