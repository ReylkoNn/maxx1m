"""Opt-in research transport for public X3DH prekeys, NOT a messaging protocol.

Clients must verify identities and signed prekeys independently. This endpoint is
not used by the desktop application, and is disabled by default.
"""
import base64
import binascii
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, UUID4, field_validator, model_validator
from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from .. import models
from ..api.messages import get_current_device_id
from ..config import settings
from ..database import get_db
from ..rate_limit import limiter

router = APIRouter(prefix="/experimental/prekeys", tags=["Experimental prekey transport"])
MAX_AVAILABLE = 200
MAX_TOTAL = 10000  # Includes claimed records, retained to prevent OPK reuse.
MAX_CLAIMS_PER_PEER_DEVICE = 16
MAX_CLAIMS_PER_PEER_USER = 32
_SAFE_PREKEY_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _enabled():
    if not settings.ENABLE_EXPERIMENTAL_PREKEYS:
        raise HTTPException(503, "Experimental prekey transport is disabled")


def _public_b64(value, size):
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
            raise ValueError()
    except (binascii.Error, ValueError, TypeError):
        raise ValueError("Invalid public key encoding")
    return value


X3DH_CURVE25519_PREFIX = b"curve_25519:"


def verify_signed_prekey_signature(
    identity_public_key_b64: str,
    signed_prekey_b64: str,
    signature_b64: str,
) -> bool:
    """Verify Ed25519 signature over signed_prekey (X3DH domain-prefixed or raw)."""
    try:
        id_raw = base64.b64decode(identity_public_key_b64, validate=True)
        spk_raw = base64.b64decode(signed_prekey_b64, validate=True)
        sig_raw = base64.b64decode(signature_b64, validate=True)
        if (
            len(id_raw) != 32
            or len(spk_raw) != 32
            or len(sig_raw) != 64
            or base64.b64encode(id_raw).decode("ascii") != identity_public_key_b64
            or base64.b64encode(spk_raw).decode("ascii") != signed_prekey_b64
            or base64.b64encode(sig_raw).decode("ascii") != signature_b64
        ):
            return False
        pub = Ed25519PublicKey.from_public_bytes(id_raw)
    except (binascii.Error, ValueError, TypeError):
        return False

    for candidate in (X3DH_CURVE25519_PREFIX + spk_raw, spk_raw):
        try:
            pub.verify(sig_raw, candidate)
            return True
        except InvalidSignature:
            continue
    return False


class PublicPreKey(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: UUID4
    public_key: str = Field(min_length=44, max_length=44)

    @field_validator("public_key")
    @classmethod
    def validate_key(cls, value): return _public_b64(value, 32)


class PublishBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(ge=1, le=2**31 - 1, strict=True)
    signed_prekey: str = Field(min_length=44, max_length=44)
    signature: str = Field(min_length=88, max_length=88)
    one_time_keys: list[PublicPreKey] = Field(max_length=100)
    verify_signature: bool = False

    @field_validator("signed_prekey")
    @classmethod
    def validate_signed(cls, value): return _public_b64(value, 32)

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value): return _public_b64(value, 64)

    @model_validator(mode="after")
    def unique_batch(self):
        ids = [entry.key_id for entry in self.one_time_keys]
        keys = [entry.public_key for entry in self.one_time_keys]
        if len(set(ids)) != len(ids) or len(set(keys)) != len(keys):
            raise ValueError("Duplicate prekey")
        return self


class ClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID4


async def _write_lock(db, device_id):
    # SQLite serializes writers, including concurrent processes. Force the lock
    # before reading bundle/counters or a consumed key could be issued twice.
    result = await db.execute(update(models.Device).where(
        models.Device.id == device_id, models.Device.is_revoked == False,
        models.Device.user_id.in_(select(models.User.id).where(models.User.is_active == True)),
    ).values(last_seen=models.Device.last_seen))
    if result.rowcount != 1:
        raise HTTPException(403, "Device unavailable")


@router.put("/bundle")
@limiter.limit("60/minute")
async def publish_bundle(request: Request, bundle: PublishBundle,
                         device_id: str = Depends(get_current_device_id), db: AsyncSession = Depends(get_db)):
    _enabled()
    await _write_lock(db, device_id)
    try:
        if bundle.verify_signature or settings.REQUIRE_SIGNED_PREKEY_VERIFICATION:
            owner_device = await db.get(models.Device, device_id)
            if owner_device is None or not verify_signed_prekey_signature(
                owner_device.public_key, bundle.signed_prekey, bundle.signature
            ):
                raise HTTPException(400, "Invalid signed prekey signature")
        current = await db.get(models.ExperimentalPreKeyBundle, device_id)
        if current:
            if (bundle.version < current.version or
                (bundle.version == current.version and (bundle.signed_prekey != current.signed_prekey or bundle.signature != current.signature))):
                raise HTTPException(409, "Stale or conflicting signed prekey version")
            current.version, current.signed_prekey, current.signature = bundle.version, bundle.signed_prekey, bundle.signature
        else:
            db.add(models.ExperimentalPreKeyBundle(device_id=device_id, version=bundle.version,
                                                    signed_prekey=bundle.signed_prekey, signature=bundle.signature))

        existing = (await db.execute(select(models.ExperimentalOneTimePreKey).where(
            models.ExperimentalOneTimePreKey.device_id == device_id,
            (models.ExperimentalOneTimePreKey.key_id.in_([str(key.key_id) for key in bundle.one_time_keys]) |
             models.ExperimentalOneTimePreKey.public_key.in_([key.public_key for key in bundle.one_time_keys]))
        ))).scalars().all()
        by_id = {key.key_id: key for key in existing}
        by_public = {key.public_key: key for key in existing}
        additions = []
        for key in bundle.one_time_keys:
            old_id, old_key = by_id.get(str(key.key_id)), by_public.get(key.public_key)
            if old_id or old_key:
                if old_id is None or old_key is None or old_id.id != old_key.id:
                    raise HTTPException(409, "Prekey conflict")
            else:
                additions.append(models.ExperimentalOneTimePreKey(device_id=device_id, key_id=str(key.key_id), public_key=key.public_key))
        total, available = (await db.execute(select(
            func.count(models.ExperimentalOneTimePreKey.id),
            func.count(models.ExperimentalOneTimePreKey.id).filter(models.ExperimentalOneTimePreKey.claimed_by.is_(None)),
        ).where(models.ExperimentalOneTimePreKey.device_id == device_id))).one()
        if total + len(additions) > MAX_TOTAL or available + len(additions) > MAX_AVAILABLE:
            raise HTTPException(409, "Prekey capacity reached")
        db.add_all(additions)
        await db.commit()
        return {"available": available + len(additions)}
    except BaseException:
        await db.rollback()
        raise


@router.post("/{target_device_id}/claim")
@limiter.limit("60/minute")
async def claim_bundle(request: Request, target_device_id: str, body: ClaimRequest,
                       device_id: str = Depends(get_current_device_id), db: AsyncSession = Depends(get_db)):
    _enabled()
    if not _SAFE_PREKEY_DEVICE_ID_RE.fullmatch(target_device_id) or target_device_id == device_id:
        raise HTTPException(400, "Invalid target device")
    await _write_lock(db, device_id)
    try:
        target = (await db.execute(select(models.Device).join(models.User).where(
            models.Device.id == target_device_id, models.Device.is_revoked == False,
            models.User.is_active == True))).scalars().first()
        if not target:
            raise HTTPException(404, "Target unavailable")
        previous = (await db.execute(select(models.ExperimentalOneTimePreKey).where(
            models.ExperimentalOneTimePreKey.claimed_by == device_id,
            models.ExperimentalOneTimePreKey.request_id == str(body.request_id)))).scalars().first()
        if previous and previous.device_id != target_device_id:
            raise HTTPException(409, "Request ID already used")
        if previous is None:
            caller_device = await db.get(models.Device, device_id)
            if caller_device is None:
                raise HTTPException(403, "Device unavailable")
            peer_device_claims = (await db.execute(select(func.count(models.ExperimentalOneTimePreKey.id)).where(
                models.ExperimentalOneTimePreKey.device_id == target_device_id,
                models.ExperimentalOneTimePreKey.claimed_by == device_id,
            ))).scalar_one()
            if peer_device_claims >= MAX_CLAIMS_PER_PEER_DEVICE:
                raise HTTPException(429, "Prekey claim limit reached for this peer")
            peer_user_claims = (await db.execute(
                select(func.count(models.ExperimentalOneTimePreKey.id))
                .join(models.Device, models.Device.id == models.ExperimentalOneTimePreKey.claimed_by)
                .where(
                    models.ExperimentalOneTimePreKey.device_id == target_device_id,
                    models.Device.user_id == caller_device.user_id,
                )
            )).scalar_one()
            if peer_user_claims >= MAX_CLAIMS_PER_PEER_USER:
                raise HTTPException(429, "Prekey claim limit reached for this peer")
            bundle = await db.get(models.ExperimentalPreKeyBundle, target_device_id)
            if bundle is None:
                raise HTTPException(404, "Prekey bundle unavailable")
            previous = (await db.execute(select(models.ExperimentalOneTimePreKey).where(
                models.ExperimentalOneTimePreKey.device_id == target_device_id,
                models.ExperimentalOneTimePreKey.claimed_by.is_(None)
            ).order_by(models.ExperimentalOneTimePreKey.id).limit(1))).scalars().first()
            if previous is None:
                raise HTTPException(409, "No one-time prekeys available")
            previous.claimed_by, previous.request_id = device_id, str(body.request_id)
            previous.claimed_identity_key = target.public_key
            previous.claimed_signed_prekey, previous.claimed_signature = bundle.signed_prekey, bundle.signature
            previous.claimed_version = bundle.version
            await db.commit()
        return {"device_id": target_device_id, "identity_key": previous.claimed_identity_key,
                "signed_prekey": previous.claimed_signed_prekey, "signature": previous.claimed_signature,
                "version": previous.claimed_version,
                "one_time_key": {"key_id": previous.key_id, "public_key": previous.public_key}}
    except BaseException:
        await db.rollback()
        raise


prod_router = APIRouter(prefix="/prekeys", tags=["X3DH PreKeys"])


def _prod_enabled():
    if not settings.ENABLE_PREKEYS:
        raise HTTPException(503, "Prekey transport is disabled")


@prod_router.get("/status")
@limiter.limit("60/minute")
async def get_prekey_status(
    request: Request,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    _prod_enabled()
    bundle = await db.get(models.ExperimentalPreKeyBundle, device_id)
    available = (
        await db.execute(
            select(func.count(models.ExperimentalOneTimePreKey.id)).where(
                models.ExperimentalOneTimePreKey.device_id == device_id,
                models.ExperimentalOneTimePreKey.claimed_by.is_(None),
            )
        )
    ).scalar_one()
    return {
        "has_bundle": bundle is not None,
        "version": int(bundle.version) if bundle is not None else 0,
        "available_one_time_keys": int(available),
    }


@prod_router.put("/bundle")
@limiter.limit("60/minute")
async def publish_prod_bundle(
    request: Request,
    bundle: PublishBundle,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    _prod_enabled()
    await _write_lock(db, device_id)
    try:
        owner_device = await db.get(models.Device, device_id)
        if owner_device is None or not verify_signed_prekey_signature(
            owner_device.public_key, bundle.signed_prekey, bundle.signature
        ):
            raise HTTPException(400, "Invalid signed prekey signature")

        current = await db.get(models.ExperimentalPreKeyBundle, device_id)
        if current:
            if bundle.version < current.version or (
                bundle.version == current.version
                and (bundle.signed_prekey != current.signed_prekey or bundle.signature != current.signature)
            ):
                raise HTTPException(409, "Stale or conflicting signed prekey version")
            current.version, current.signed_prekey, current.signature = (
                bundle.version,
                bundle.signed_prekey,
                bundle.signature,
            )
        else:
            db.add(
                models.ExperimentalPreKeyBundle(
                    device_id=device_id,
                    version=bundle.version,
                    signed_prekey=bundle.signed_prekey,
                    signature=bundle.signature,
                )
            )

        existing = (
            await db.execute(
                select(models.ExperimentalOneTimePreKey).where(
                    models.ExperimentalOneTimePreKey.device_id == device_id,
                    (
                        models.ExperimentalOneTimePreKey.key_id.in_([str(key.key_id) for key in bundle.one_time_keys])
                        | models.ExperimentalOneTimePreKey.public_key.in_([key.public_key for key in bundle.one_time_keys])
                    ),
                )
            )
        ).scalars().all()
        by_id = {key.key_id: key for key in existing}
        by_public = {key.public_key: key for key in existing}
        additions = []
        for key in bundle.one_time_keys:
            old_id, old_key = by_id.get(str(key.key_id)), by_public.get(key.public_key)
            if old_id or old_key:
                if old_id is None or old_key is None or old_id.id != old_key.id:
                    raise HTTPException(409, "Prekey conflict")
            else:
                additions.append(
                    models.ExperimentalOneTimePreKey(
                        device_id=device_id, key_id=str(key.key_id), public_key=key.public_key
                    )
                )
        total, available = (
            await db.execute(
                select(
                    func.count(models.ExperimentalOneTimePreKey.id),
                    func.count(models.ExperimentalOneTimePreKey.id).filter(
                        models.ExperimentalOneTimePreKey.claimed_by.is_(None)
                    ),
                ).where(models.ExperimentalOneTimePreKey.device_id == device_id)
            )
        ).one()
        if total + len(additions) > MAX_TOTAL or available + len(additions) > MAX_AVAILABLE:
            raise HTTPException(409, "Prekey capacity reached")
        db.add_all(additions)
        await db.commit()
        return {"available": available + len(additions), "version": bundle.version}
    except BaseException:
        await db.rollback()
        raise


@prod_router.post("/{target_device_id}/claim")
@limiter.limit("60/minute")
async def claim_prod_bundle(
    request: Request,
    target_device_id: str,
    body: ClaimRequest,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    _prod_enabled()
    if not _SAFE_PREKEY_DEVICE_ID_RE.fullmatch(target_device_id) or target_device_id == device_id:
        raise HTTPException(400, "Invalid target device")
    await _write_lock(db, device_id)
    try:
        target = (
            await db.execute(
                select(models.Device)
                .join(models.User)
                .where(
                    models.Device.id == target_device_id,
                    models.Device.is_revoked == False,
                    models.User.is_active == True,
                )
            )
        ).scalars().first()
        if not target:
            raise HTTPException(404, "Target unavailable")

        previous = (
            await db.execute(
                select(models.ExperimentalOneTimePreKey).where(
                    models.ExperimentalOneTimePreKey.claimed_by == device_id,
                    models.ExperimentalOneTimePreKey.request_id == str(body.request_id),
                )
            )
        ).scalars().first()
        if previous and previous.device_id != target_device_id:
            raise HTTPException(409, "Request ID already used")

        if previous is not None:
            return {
                "device_id": target_device_id,
                "identity_key": previous.claimed_identity_key,
                "signed_prekey": previous.claimed_signed_prekey,
                "signature": previous.claimed_signature,
                "version": previous.claimed_version,
                "one_time_key": {"key_id": previous.key_id, "public_key": previous.public_key},
            }

        caller_device = await db.get(models.Device, device_id)
        if caller_device is None:
            raise HTTPException(403, "Device unavailable")

        bundle = await db.get(models.ExperimentalPreKeyBundle, target_device_id)
        if bundle is None:
            raise HTTPException(404, "Prekey bundle unavailable")
        if not verify_signed_prekey_signature(target.public_key, bundle.signed_prekey, bundle.signature):
            raise HTTPException(409, "Stored signed prekey failed signature verification")

        peer_device_claims = (
            await db.execute(
                select(func.count(models.ExperimentalOneTimePreKey.id)).where(
                    models.ExperimentalOneTimePreKey.device_id == target_device_id,
                    models.ExperimentalOneTimePreKey.claimed_by == device_id,
                )
            )
        ).scalar_one()
        if peer_device_claims >= MAX_CLAIMS_PER_PEER_DEVICE:
            raise HTTPException(429, "Prekey claim limit reached for this peer")
        peer_user_claims = (
            await db.execute(
                select(func.count(models.ExperimentalOneTimePreKey.id))
                .join(models.Device, models.Device.id == models.ExperimentalOneTimePreKey.claimed_by)
                .where(
                    models.ExperimentalOneTimePreKey.device_id == target_device_id,
                    models.Device.user_id == caller_device.user_id,
                )
            )
        ).scalar_one()
        if peer_user_claims >= MAX_CLAIMS_PER_PEER_USER:
            raise HTTPException(429, "Prekey claim limit reached for this peer")

        opk = (
            await db.execute(
                select(models.ExperimentalOneTimePreKey)
                .where(
                    models.ExperimentalOneTimePreKey.device_id == target_device_id,
                    models.ExperimentalOneTimePreKey.claimed_by.is_(None),
                )
                .order_by(models.ExperimentalOneTimePreKey.id)
                .limit(1)
            )
        ).scalars().first()
        if opk is not None:
            opk.claimed_by, opk.request_id = device_id, str(body.request_id)
            opk.claimed_identity_key = target.public_key
            opk.claimed_signed_prekey, opk.claimed_signature = bundle.signed_prekey, bundle.signature
            opk.claimed_version = bundle.version
            await db.commit()
            return {
                "device_id": target_device_id,
                "identity_key": target.public_key,
                "signed_prekey": bundle.signed_prekey,
                "signature": bundle.signature,
                "version": bundle.version,
                "one_time_key": {"key_id": opk.key_id, "public_key": opk.public_key},
            }

        # Graceful 3-DH fallback when all OPKs of an offline peer are temporarily exhausted
        await db.commit()
        return {
            "device_id": target_device_id,
            "identity_key": target.public_key,
            "signed_prekey": bundle.signed_prekey,
            "signature": bundle.signature,
            "version": bundle.version,
            "one_time_key": None,
        }
    except BaseException:
        await db.rollback()
        raise
