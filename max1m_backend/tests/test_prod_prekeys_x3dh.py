import asyncio
import base64
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from app import models
from app.api.prekeys import X3DH_CURVE25519_PREFIX
from app.config import settings
from app.database import AsyncSessionLocal
from app.main import app
from app.security import create_access_token


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, base64.b64encode(pub_raw).decode("ascii")


def _gen_x25519_pub_b64() -> tuple[bytes, str]:
    priv = X25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pub_raw, base64.b64encode(pub_raw).decode("ascii")


def _seed_user_device(username: str, ed_pub_b64: str) -> tuple[str, str]:
    async def _run():
        async with AsyncSessionLocal() as db:
            user = models.User(username=username, password_hash="unused")
            db.add(user)
            await db.flush()
            dev = models.Device(
                user_id=user.id,
                device_name=f"{username}-pc",
                public_key=ed_pub_b64,
                fingerprint=uuid.uuid4().hex,
            )
            db.add(dev)
            await db.commit()
            tok = create_access_token({"sub": str(user.id), "device_id": dev.id, "session_version": 0})
            return dev.id, tok

    return asyncio.run(_run())


def test_prod_prekeys_enforces_mandatory_ed25519_signature_and_supports_3dh_fallback():
    # Ensure experimental flag remains False while production /prekeys is active!
    assert settings.ENABLE_EXPERIMENTAL_PREKEYS is False
    assert settings.ENABLE_PREKEYS is True

    alice_ed, alice_pub = _gen_ed25519()
    bob_ed, bob_pub = _gen_ed25519()
    mallory_ed, _ = _gen_ed25519()

    with TestClient(app) as client:
        u_a = f"pka_{uuid.uuid4().hex[:8]}"
        u_b = f"pkb_{uuid.uuid4().hex[:8]}"
        alice_dev, alice_tok = _seed_user_device(u_a, alice_pub)
        bob_dev, bob_tok = _seed_user_device(u_b, bob_pub)

        h_alice = {"Authorization": f"Bearer {alice_tok}"}
        h_bob = {"Authorization": f"Bearer {bob_tok}"}

        # 1. Initial status shows no bundle
        st0 = client.get("/prekeys/status", headers=h_bob)
        assert st0.status_code == 200
        assert st0.json() == {"has_bundle": False, "version": 0, "available_one_time_keys": 0}

        # 2. Forged signature MUST be rejected with 400 even if verify_signature=False is sent!
        spk_raw, spk_b64 = _gen_x25519_pub_b64()
        bad_sig = base64.b64encode(mallory_ed.sign(X3DH_CURVE25519_PREFIX + spk_raw)).decode("ascii")
        r_bad = client.put(
            "/prekeys/bundle",
            headers=h_bob,
            json={
                "version": 1,
                "signed_prekey": spk_b64,
                "signature": bad_sig,
                "one_time_keys": [],
                "verify_signature": False,
            },
        )
        assert r_bad.status_code == 400

        # 3. Valid Ed25519 signature over curve_25519:<spk> succeeds with 1 OPK
        good_sig = base64.b64encode(bob_ed.sign(X3DH_CURVE25519_PREFIX + spk_raw)).decode("ascii")
        _, opk1_pub = _gen_x25519_pub_b64()
        opk1_id = str(uuid.uuid4())
        r_ok = client.put(
            "/prekeys/bundle",
            headers=h_bob,
            json={
                "version": 1,
                "signed_prekey": spk_b64,
                "signature": good_sig,
                "one_time_keys": [{"key_id": opk1_id, "public_key": opk1_pub}],
            },
        )
        assert r_ok.status_code == 200
        assert r_ok.json() == {"available": 1, "version": 1}

        st1 = client.get("/prekeys/status", headers=h_bob).json()
        assert st1 == {"has_bundle": True, "version": 1, "available_one_time_keys": 1}

        # 4. Alice claims Bob's bundle -> receives OPK #1 (and idempotent retry returns identical snapshot)
        req1 = str(uuid.uuid4())
        c1 = client.post(f"/prekeys/{bob_dev}/claim", headers=h_alice, json={"request_id": req1})
        assert c1.status_code == 200
        body1 = c1.json()
        assert body1["identity_key"] == bob_pub
        assert body1["signed_prekey"] == spk_b64
        assert body1["one_time_key"] == {"key_id": opk1_id, "public_key": opk1_pub}

        c1_retry = client.post(f"/prekeys/{bob_dev}/claim", headers=h_alice, json={"request_id": req1})
        assert c1_retry.status_code == 200
        assert c1_retry.json() == body1

        # 5. Next fresh claim when Bob's OPKs are exhausted gracefully falls back to 3-DH (one_time_key=None)
        c2 = client.post(
            f"/prekeys/{bob_dev}/claim",
            headers=h_alice,
            json={"request_id": str(uuid.uuid4())},
        )
        assert c2.status_code == 200
        body2 = c2.json()
        assert body2["identity_key"] == bob_pub
        assert body2["signed_prekey"] == spk_b64
        assert body2["one_time_key"] is None
