import base64
import concurrent.futures
import os
import uuid
import warnings

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import models
from app.config import Settings, settings, validate_secret_key
from app.database import AsyncSessionLocal
from app.main import app
from app.rate_limit import limiter


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    limiter.reset()
    yield
    limiter.reset()


def _seed_invite(client: TestClient, code: str):
    async def _insert():
        async with AsyncSessionLocal() as db:
            db.add(models.InviteCode(code=code, is_used=False))
            await db.commit()

    client.portal.call(_insert)


def _register_and_login(client: TestClient, username: str, password: str = "StrongPass123!"):
    code = f"INV-{uuid.uuid4().hex[:12]}"
    _seed_invite(client, code)
    pub1 = base64.b64encode(os.urandom(32)).decode("ascii")
    fp1 = f"fp-{uuid.uuid4().hex}"
    reg = client.post(
        "/auth/register",
        json={
            "username": username,
            "password": password,
            "invite_code": code,
            "device_name": "Primary Laptop",
            "public_key": pub1,
            "fingerprint": fp1,
        },
    )
    assert reg.status_code == 201, reg.text
    dev1_id = reg.json()["device_id"]
    login1 = client.post(
        "/auth/login",
        json={"username": username, "password": password, "device_id": dev1_id},
    )
    assert login1.status_code == 200, login1.text
    return dev1_id, login1.json()["access_token"]


def _login_new_device(client: TestClient, username: str, name: str, password: str = "StrongPass123!"):
    pub = base64.b64encode(os.urandom(32)).decode("ascii")
    fp = f"fp-{uuid.uuid4().hex}"
    resp = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
            "device_name": name,
            "public_key": pub,
            "fingerprint": fp,
        },
    )
    return resp


def test_list_own_devices_and_revoke_closes_ws_and_hides_from_lookup():
    with TestClient(app) as client:
        username = f"devmgr_{uuid.uuid4().hex[:10]}"
        dev1_id, tok1 = _register_and_login(client, username)
        r2 = _login_new_device(client, username, "Second Phone")
        assert r2.status_code == 200, r2.text
        dev2_id, tok2 = r2.json()["device_id"], r2.json()["access_token"]

        r3 = _login_new_device(client, username, "Workstation")
        assert r3.status_code == 200, r3.text
        dev3_id, tok3 = r3.json()["device_id"], r3.json()["access_token"]

        listed = client.get("/auth/devices", headers={"Authorization": f"Bearer {tok1}"})
        assert listed.status_code == 200, listed.text
        items = listed.json()
        assert [d["id"] for d in items] == [dev1_id, dev2_id, dev3_id]
        assert [d["is_current"] for d in items] == [True, False, False]
        assert all(d["is_revoked"] is False for d in items)

        # Open a live WebSocket for dev2 and verify revoke closes it immediately.
        with client.websocket_connect(
            f"/messages/ws/{dev2_id}", headers={"Authorization": f"Bearer {tok2}"}
        ) as ws2:
            revoke = client.post(
                f"/auth/devices/{dev2_id}/revoke",
                headers={"Authorization": f"Bearer {tok1}"},
            )
            assert revoke.status_code == 200, revoke.text
            assert revoke.json() == {
                "status": "ok",
                "device_id": dev2_id,
                "is_revoked": True,
                "already_revoked": False,
            }
            with pytest.raises(WebSocketDisconnect) as exc_info:
                ws2.receive_text()
            assert exc_info.value.code == 1008

        # Idempotent second revoke.
        revoke_again = client.post(
            f"/auth/devices/{dev2_id}/revoke",
            headers={"Authorization": f"Bearer {tok1}"},
        )
        assert revoke_again.status_code == 200
        assert revoke_again.json()["already_revoked"] is True

        # Revoked device loses HTTP access and re-login access immediately.
        assert client.get("/auth/devices", headers={"Authorization": f"Bearer {tok2}"}).status_code == 401
        assert client.get("/messages/sync", headers={"Authorization": f"Bearer {tok2}"}).status_code == 401
        relogin = client.post(
            "/auth/login",
            json={"username": username, "password": "StrongPass123!", "device_id": dev2_id},
        )
        assert relogin.status_code == 403

        # Contact lookup returns only active devices (dev1 and dev3).
        lookup = client.get(
            f"/auth/find/{username}",
            headers={"Authorization": f"Bearer {tok3}"},
        )
        assert lookup.status_code == 200, lookup.text
        found_ids = [d["device_id"] for d in lookup.json()["devices"]]
        assert found_ids == [dev1_id, dev3_id]


def test_cannot_revoke_current_device_or_foreign_device():
    with TestClient(app) as client:
        u1 = f"owner_{uuid.uuid4().hex[:10]}"
        u2 = f"other_{uuid.uuid4().hex[:10]}"
        dev1_id, tok1 = _register_and_login(client, u1)
        dev2_id, _ = _register_and_login(client, u2)

        self_revoke = client.post(
            f"/auth/devices/{dev1_id}/revoke",
            headers={"Authorization": f"Bearer {tok1}"},
        )
        assert self_revoke.status_code == 400

        foreign_revoke = client.post(
            f"/auth/devices/{dev2_id}/revoke",
            headers={"Authorization": f"Bearer {tok1}"},
        )
        missing_revoke = client.post(
            f"/auth/devices/{uuid.uuid4()}/revoke",
            headers={"Authorization": f"Bearer {tok1}"},
        )
        assert foreign_revoke.status_code == 404
        assert missing_revoke.status_code == 404
        assert foreign_revoke.json() == missing_revoke.json()


def test_concurrent_mutual_revocation_serializes_without_full_lockout():
    with TestClient(app) as client:
        username = f"race_{uuid.uuid4().hex[:10]}"
        dev_a, tok_a = _register_and_login(client, username)
        r_b = _login_new_device(client, username, "Peer B")
        assert r_b.status_code == 200
        dev_b, tok_b = r_b.json()["device_id"], r_b.json()["access_token"]

        def _call(token, target):
            return client.post(
                f"/auth/devices/{target}/revoke",
                headers={"Authorization": f"Bearer {token}"},
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fa = pool.submit(_call, tok_a, dev_b)
            fb = pool.submit(_call, tok_b, dev_a)
            codes = sorted([fa.result().status_code, fb.result().status_code])

        # Exactly one wins (200) and the revoked loser is rejected (401).
        assert codes == [200, 401]


def test_login_enforces_active_device_quota_until_old_device_revoked(monkeypatch):
    monkeypatch.setattr(settings, "MAX_ACTIVE_DEVICES_PER_USER", 2)
    with TestClient(app) as client:
        username = f"quota_{uuid.uuid4().hex[:10]}"
        dev1_id, tok1 = _register_and_login(client, username)
        r2 = _login_new_device(client, username, "Device 2")
        assert r2.status_code == 200
        dev2_id = r2.json()["device_id"]

        r3_blocked = _login_new_device(client, username, "Device 3")
        assert r3_blocked.status_code == 409

        rev = client.post(
            f"/auth/devices/{dev2_id}/revoke",
            headers={"Authorization": f"Bearer {tok1}"},
        )
        assert rev.status_code == 200

        r3_allowed = _login_new_device(client, username, "Device 3")
        assert r3_allowed.status_code == 200


def test_settings_config_no_deprecation_and_secret_key_length_validation(monkeypatch):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cfg = Settings(SECRET_KEY="x" * 32, _env_file=None)
        assert cfg.MAX_ACTIVE_DEVICES_PER_USER == 32
    pydantic_warnings = [w for w in caught if "PydanticDeprecatedSince20" in type(w.message).__name__]
    assert pydantic_warnings == []

    for bad in ("", "CHANGE_ME", "short-key-under-32-chars", "a" * 31):
        monkeypatch.setattr(settings, "SECRET_KEY", bad)
        with pytest.raises(ValueError):
            validate_secret_key()

    monkeypatch.setattr(settings, "SECRET_KEY", "s" * 32)
    validate_secret_key()


def test_prekey_per_peer_claim_cap_protects_pool_for_other_contacts(monkeypatch):
    from app.api import prekeys

    monkeypatch.setattr(settings, "ENABLE_EXPERIMENTAL_PREKEYS", True)
    monkeypatch.setattr(prekeys, "MAX_CLAIMS_PER_PEER_DEVICE", 2)
    monkeypatch.setattr(prekeys, "MAX_CLAIMS_PER_PEER_USER", 3)

    with TestClient(app) as client:
        u_target = f"pk_t_{uuid.uuid4().hex[:8]}"
        u_attacker = f"pk_a_{uuid.uuid4().hex[:8]}"
        u_legit = f"pk_l_{uuid.uuid4().hex[:8]}"
        target_dev, tok_target = _register_and_login(client, u_target)
        _, tok_att1 = _register_and_login(client, u_attacker)
        att2 = _login_new_device(client, u_attacker, "Attacker Dev 2")
        assert att2.status_code == 200
        tok_att2 = att2.json()["access_token"]
        _, tok_legit = _register_and_login(client, u_legit)

        opks = [
            {"key_id": str(uuid.uuid4()), "public_key": base64.b64encode(os.urandom(32)).decode()}
            for _ in range(6)
        ]
        pub = client.put(
            "/experimental/prekeys/bundle",
            headers={"Authorization": f"Bearer {tok_target}"},
            json={
                "version": 1,
                "signed_prekey": base64.b64encode(os.urandom(32)).decode(),
                "signature": base64.b64encode(os.urandom(64)).decode(),
                "one_time_keys": opks,
            },
        )
        assert pub.status_code == 200

        url = f"/experimental/prekeys/{target_dev}/claim"
        first_req = {"request_id": str(uuid.uuid4())}
        assert client.post(url, headers={"Authorization": f"Bearer {tok_att1}"}, json=first_req).status_code == 200
        assert client.post(url, headers={"Authorization": f"Bearer {tok_att1}"}, json={"request_id": str(uuid.uuid4())}).status_code == 200
        # 3rd new claim from same device hits MAX_CLAIMS_PER_PEER_DEVICE (429),
        # while idempotent retry of first_req still succeeds (200).
        assert client.post(url, headers={"Authorization": f"Bearer {tok_att1}"}, json={"request_id": str(uuid.uuid4())}).status_code == 429
        assert client.post(url, headers={"Authorization": f"Bearer {tok_att1}"}, json=first_req).status_code == 200

        # Second device of same attacker user gets 1 more key, then hits MAX_CLAIMS_PER_PEER_USER (3).
        assert client.post(url, headers={"Authorization": f"Bearer {tok_att2}"}, json={"request_id": str(uuid.uuid4())}).status_code == 200
        assert client.post(url, headers={"Authorization": f"Bearer {tok_att2}"}, json={"request_id": str(uuid.uuid4())}).status_code == 429

        # Legitimate independent contact still claims an OPK cleanly!
        legit_resp = client.post(url, headers={"Authorization": f"Bearer {tok_legit}"}, json={"request_id": str(uuid.uuid4())})
        assert legit_resp.status_code == 200
