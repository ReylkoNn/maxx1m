import re
from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, or_, func, text
from sqlalchemy.exc import IntegrityError
from datetime import timedelta, datetime, timezone

from .. import schemas, models, security
from ..database import get_db
from ..config import settings
from ..rate_limit import limiter
from ..password_jobs import run_password_job
from ..api.messages import get_current_device_id, manager

router = APIRouter(prefix="/auth", tags=["Authentication"])
_USERNAME_LOOKUP_RE = re.compile(r"^[A-Za-z0-9_]{3,50}$")


@router.post("/register", response_model=schemas.RegisterResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_REGISTER)
async def register(
        request: Request,
        user_in: schemas.RegisterRequest,
        db: AsyncSession = Depends(get_db)
):
    """
    Регистрация нового устройства.

    Rate limit: 3 запроса в час — инвайт-коды должны быть дорогими,
    чтобы спам-регистрации были невозможны.
    """
    if not security.validate_device_key_and_fingerprint(
        user_in.public_key,
        user_in.fingerprint,
        strict=bool(settings.REQUIRE_VERIFIED_DEVICE_KEYS),
    ):
        raise HTTPException(
            status_code=400,
            detail="Публичный ключ Ed25519 или отпечаток устройства некорректен либо не соответствует ключу.",
        )

    # Reject obviously invalid invitations cheaply. The later atomic UPDATE is
    # authoritative because another registration can claim the code meanwhile.
    now = datetime.now(timezone.utc)
    invite = (await db.execute(select(models.InviteCode).where(
        models.InviteCode.code == user_in.invite_code,
        models.InviteCode.is_used == False,
        or_(models.InviteCode.expires_at.is_(None), models.InviteCode.expires_at > now),
    ))).scalars().first()
    if not invite:
        raise HTTPException(status_code=400, detail="Инвайт-код недействителен, использован или истёк.")

    # Hash outside the SQLite write lock and off the event loop.
    stmt = select(models.User).where(models.User.username == user_in.username)
    if (await db.execute(stmt)).scalars().first():
        raise HTTPException(status_code=400, detail="Имя пользователя уже занято.")

    hashed_password = await run_password_job(security.hash_password, user_in.password)
    await db.rollback()
    try:
        await db.execute(text("BEGIN IMMEDIATE"))
        now = datetime.now(timezone.utc)
        claim = await db.execute(
            update(models.InviteCode)
            .where(
                models.InviteCode.code == user_in.invite_code,
                models.InviteCode.is_used == False,
                or_(models.InviteCode.expires_at.is_(None), models.InviteCode.expires_at > now),
            )
            .values(is_used=True)
            .execution_options(synchronize_session=False)
        )
        if claim.rowcount != 1:
            await db.rollback()
            raise HTTPException(status_code=400, detail="Инвайт-код недействителен, использован или истёк.")

        new_user = models.User(username=user_in.username, password_hash=hashed_password)
        db.add(new_user)
        await db.flush()
        new_device = models.Device(
            user_id=new_user.id, device_name=user_in.device_name,
            public_key=user_in.public_key, fingerprint=user_in.fingerprint,
            session_version=0,
        )
        db.add(new_device)
        await db.execute(
            update(models.InviteCode).where(models.InviteCode.code == user_in.invite_code)
            .values(used_by_user_id=new_user.id)
        )
        await db.commit()
        await db.refresh(new_user)
        await db.refresh(new_device)
    except IntegrityError:
        # Includes concurrent duplicate usernames/fingerprints. The invite claim
        # is in the same transaction, so it is not consumed on failure.
        await db.rollback()
        raise HTTPException(status_code=400, detail="Имя пользователя или устройство уже существует.")
    except BaseException:
        await db.rollback()
        raise

    return schemas.RegisterResponse(
        user_id=new_user.id, device_id=new_device.id, message="Registration successful."
    )


@router.post("/login", response_model=schemas.TokenResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login(
        request: Request,
        login_data: schemas.LoginRequest,
        db: AsyncSession = Depends(get_db)
):
    """
    Авторизация.

    Rate limit: 5 запросов в минуту — достаточно для нормального входа,
    но брутфорс Argon2id (64MB RAM) даже без лимита был бы медленным.
    Лимит добавляет защиту от DOS через массовый параллельный брутфорс.
    """
    stmt = select(models.User).where(models.User.username == login_data.username)
    result = await db.execute(stmt)
    user = result.scalars().first()

    # Always perform a comparable password check to reduce username-enumeration
    # timing differences. The dummy value is never accepted as a credential.
    password_hash = user.password_hash if user and user.is_active else security.DUMMY_PASSWORD_HASH
    valid_password = await run_password_job(security.verify_password, login_data.password, password_hash)
    if not user or not user.is_active or not valid_password:
        raise HTTPException(status_code=401, detail="Неверное имя пользователя или пароль.")

    user_id = user.id
    old_password_hash = user.password_hash
    upgraded_password_hash = None
    if security.check_needs_rehash(old_password_hash):
        upgraded_password_hash = await run_password_job(security.hash_password, login_data.password)

    device_id_to_auth = None
    device_public_key = None
    device_session_version = 0

    if login_data.device_id:
        await db.rollback()
        try:
            await db.execute(text("BEGIN IMMEDIATE"))
            active_user = (await db.execute(
                select(models.User).where(
                    models.User.id == user_id,
                    models.User.is_active == True,
                )
            )).scalars().first()
            if not active_user:
                await db.rollback()
                raise HTTPException(status_code=401, detail="Неверное имя пользователя или пароль.")
            if upgraded_password_hash is not None and active_user.password_hash == old_password_hash:
                active_user.password_hash = upgraded_password_hash

            stmt = select(models.Device).where(
                models.Device.id == login_data.device_id, models.Device.user_id == user_id
            )
            result = await db.execute(stmt)
            existing_device = result.scalars().first()

            if not existing_device:
                await db.rollback()
                raise HTTPException(status_code=400, detail="Устройство не найдено.")
            if existing_device.is_revoked:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Доступ с этого устройства отозван.")

            new_ls = security.coarsen_device_last_seen(
                datetime.now(timezone.utc),
                floor_dt=existing_device.created_at,
            )
            if new_ls is not None:
                existing_device.last_seen = new_ls
            device_id_to_auth = existing_device.id
            device_public_key = existing_device.public_key
            device_session_version = int(existing_device.session_version or 0)
            await db.commit()
        except BaseException:
            await db.rollback()
            raise

    elif login_data.public_key and login_data.fingerprint and login_data.device_name:
        if not security.validate_device_key_and_fingerprint(
            login_data.public_key,
            login_data.fingerprint,
            strict=bool(settings.REQUIRE_VERIFIED_DEVICE_KEYS),
        ):
            raise HTTPException(
                status_code=400,
                detail="Публичный ключ Ed25519 или отпечаток устройства некорректен либо не соответствует ключу.",
            )
        await db.rollback()
        try:
            await db.execute(text("BEGIN IMMEDIATE"))
            active_user = (await db.execute(
                select(models.User).where(
                    models.User.id == user_id,
                    models.User.is_active == True,
                )
            )).scalars().first()
            if not active_user:
                await db.rollback()
                raise HTTPException(status_code=401, detail="Неверное имя пользователя или пароль.")
            if upgraded_password_hash is not None and active_user.password_hash == old_password_hash:
                active_user.password_hash = upgraded_password_hash

            stmt = select(models.Device).where(models.Device.fingerprint == login_data.fingerprint)
            if (await db.execute(stmt)).scalars().first():
                await db.rollback()
                raise HTTPException(status_code=400, detail="Такой Fingerprint устройства уже существует.")

            total_devices, active_devices = (await db.execute(
                select(
                    func.count(models.Device.id),
                    func.count(models.Device.id).filter(models.Device.is_revoked == False),
                ).where(models.Device.user_id == user_id)
            )).one()
            if active_devices >= settings.MAX_ACTIVE_DEVICES_PER_USER:
                await db.rollback()
                raise HTTPException(
                    status_code=409,
                    detail="Достигнут лимит активных устройств аккаунта. Отзовите старое устройство.",
                )
            if total_devices >= settings.MAX_TOTAL_DEVICES_PER_USER:
                await db.rollback()
                raise HTTPException(
                    status_code=409,
                    detail="Достигнут общий лимит устройств аккаунта.",
                )

            new_device = models.Device(
                user_id=user_id, device_name=login_data.device_name,
                public_key=login_data.public_key, fingerprint=login_data.fingerprint,
                session_version=0,
            )
            db.add(new_device)
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=400, detail="Такой Fingerprint устройства уже существует.")
        except BaseException:
            await db.rollback()
            raise
        await db.refresh(new_device)
        device_id_to_auth = new_device.id
        device_public_key = new_device.public_key
        device_session_version = int(new_device.session_version or 0)
    else:
        raise HTTPException(status_code=400, detail="Необходимы данные устройства.")

    access_token = security.create_access_token(
        data={"sub": user_id, "device_id": device_id_to_auth, "sv": device_session_version},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return schemas.TokenResponse(access_token=access_token, token_type="bearer", device_id=device_id_to_auth,
                                 device_public_key=device_public_key)


@router.post("/logout", response_model=schemas.LogoutResponse)
@limiter.limit("30/minute")
async def logout(
        request: Request,
        body: schemas.LogoutRequest | None = Body(default=None),
        current_device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db),
):
    """
    Отзывает текущую JWT-сессию устройства (или все активные сессии аккаунта при
    include_other_devices=True) без безвозвратного отзыва самого криптографического
    устройства (is_revoked остаётся False).
    """
    include_others = bool(body.include_other_devices) if body is not None else False
    only_others = bool(body.only_other_devices) if body is not None else False
    if include_others and only_others:
        raise HTTPException(status_code=400, detail="Взаимоисключающие параметры выхода из сессии.")
    invalidated_ids: list[str] = []

    await db.rollback()
    try:
        await db.execute(text("BEGIN IMMEDIATE"))
        caller = (await db.execute(
            select(models.Device)
            .join(models.User, models.User.id == models.Device.user_id)
            .where(
                models.Device.id == current_device_id,
                models.Device.is_revoked == False,
                models.User.is_active == True,
            )
        )).scalars().first()
        if caller is None:
            await db.rollback()
            raise HTTPException(status_code=401, detail="Доступ с этого устройства отозван.")

        if only_others:
            invalidated_ids = list((await db.execute(
                select(models.Device.id).where(
                    models.Device.user_id == caller.user_id,
                    models.Device.id != current_device_id,
                    models.Device.is_revoked == False,
                )
            )).scalars().all())
        elif include_others:
            invalidated_ids = list((await db.execute(
                select(models.Device.id).where(
                    models.Device.user_id == caller.user_id,
                    models.Device.is_revoked == False,
                )
            )).scalars().all())
        else:
            invalidated_ids = [current_device_id]

        if invalidated_ids:
            await db.execute(
                update(models.Device)
                .where(models.Device.id.in_(invalidated_ids))
                .values(session_version=func.coalesce(models.Device.session_version, 0) + 1)
                .execution_options(synchronize_session=False)
            )
        await db.commit()
    except BaseException:
        await db.rollback()
        raise

    for did in invalidated_ids:
        await manager.close_device(did)

    return schemas.LogoutResponse(
        status="ok",
        invalidated_devices_count=len(invalidated_ids),
    )


@router.post("/change-password", response_model=schemas.ChangePasswordResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def change_password(
        request: Request,
        body: schemas.ChangePasswordRequest,
        current_device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db),
):
    """
    Смена пароля текущего аккаунта с опциональным атомарным отзывом всех
    остальных устройств пользователя.
    """
    row = (await db.execute(
        select(models.Device, models.User)
        .join(models.User, models.User.id == models.Device.user_id)
        .where(
            models.Device.id == current_device_id,
            models.Device.is_revoked == False,
            models.User.is_active == True,
        )
    )).first()
    caller_device = row[0] if row else None
    caller_user = row[1] if row else None
    expected_old_hash = caller_user.password_hash if caller_user else security.DUMMY_PASSWORD_HASH

    valid_current = await run_password_job(
        security.verify_password,
        body.current_password,
        expected_old_hash,
    )
    if caller_device is None or caller_user is None or not valid_current:
        raise HTTPException(status_code=401, detail="Неверный текущий пароль.")

    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="Новый пароль должен отличаться от текущего.")

    user_id = caller_user.id
    # Argon2id (64 MiB) выполняется вне транзакции записи SQLite и вне event loop.
    new_password_hash = await run_password_job(security.hash_password, body.new_password)

    revoked_device_ids: list[str] = []
    other_active_ids: list[str] = []
    await db.rollback()
    try:
        await db.execute(text("BEGIN IMMEDIATE"))
        still_active_caller = (await db.execute(
            select(models.Device.id)
            .join(models.User, models.User.id == models.Device.user_id)
            .where(
                models.Device.id == current_device_id,
                models.Device.user_id == user_id,
                models.Device.is_revoked == False,
                models.User.is_active == True,
            )
        )).scalar_one_or_none()
        if still_active_caller is None:
            await db.rollback()
            raise HTTPException(status_code=401, detail="Доступ с этого устройства отозван.")

        upd = await db.execute(
            update(models.User)
            .where(
                models.User.id == user_id,
                models.User.is_active == True,
                models.User.password_hash == expected_old_hash,
            )
            .values(password_hash=new_password_hash)
            .execution_options(synchronize_session=False)
        )
        if upd.rowcount != 1:
            await db.rollback()
            raise HTTPException(
                status_code=409,
                detail="Пароль был изменён параллельным запросом. Повторите попытку.",
            )

        other_active_ids = list((await db.execute(
            select(models.Device.id).where(
                models.Device.user_id == user_id,
                models.Device.id != current_device_id,
                models.Device.is_revoked == False,
            )
        )).scalars().all())
        if other_active_ids:
            values_to_update: dict = {
                "session_version": func.coalesce(models.Device.session_version, 0) + 1,
            }
            if body.revoke_other_devices:
                values_to_update["is_revoked"] = True
                revoked_device_ids = list(other_active_ids)
            await db.execute(
                update(models.Device)
                .where(models.Device.id.in_(other_active_ids))
                .values(**values_to_update)
                .execution_options(synchronize_session=False)
            )

        await db.commit()
    except BaseException:
        await db.rollback()
        raise

    for other_id in other_active_ids:
        await manager.close_device(other_id)

    return schemas.ChangePasswordResponse(
        status="ok",
        revoked_devices_count=len(revoked_device_ids),
    )


@router.get("/devices", response_model=list[schemas.OwnDeviceInfo])
@limiter.limit("30/minute")
async def list_own_devices(
        request: Request,
        current_device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db),
):
    """Список всех устройств текущего аккаунта (включая отозванные)."""
    caller = (await db.execute(
        select(models.Device)
        .join(models.User, models.User.id == models.Device.user_id)
        .where(
            models.Device.id == current_device_id,
            models.Device.is_revoked == False,
            models.User.is_active == True,
        )
    )).scalars().first()
    if caller is None:
        raise HTTPException(status_code=401, detail="Доступ с этого устройства отозван.")

    devices = (await db.execute(
        select(models.Device)
        .where(models.Device.user_id == caller.user_id)
        .order_by(models.Device.created_at.asc(), models.Device.id.asc())
        .limit(max(settings.MAX_TOTAL_DEVICES_PER_USER, 256))
    )).scalars().all()

    return [
        schemas.OwnDeviceInfo(
            id=d.id,
            device_name=d.device_name,
            public_key=d.public_key,
            fingerprint=d.fingerprint,
            is_revoked=bool(d.is_revoked),
            is_current=(d.id == current_device_id),
            created_at=d.created_at,
            last_seen=d.last_seen,
        )
        for d in devices
    ]


@router.post("/devices/{target_device_id}/revoke")
@limiter.limit("20/minute")
async def revoke_own_device(
        request: Request,
        target_device_id: str,
        current_device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db),
):
    """Атомарный отзыв другого устройства того же пользователя."""
    if not 1 <= len(target_device_id) <= 64:
        raise HTTPException(status_code=400, detail="Некорректный идентификатор устройства.")
    if target_device_id == current_device_id:
        raise HTTPException(status_code=400, detail="Нельзя отозвать текущее устройство.")

    await db.rollback()
    try:
        await db.execute(text("BEGIN IMMEDIATE"))
        caller = (await db.execute(
            select(models.Device)
            .join(models.User, models.User.id == models.Device.user_id)
            .where(
                models.Device.id == current_device_id,
                models.Device.is_revoked == False,
                models.User.is_active == True,
            )
        )).scalars().first()
        if caller is None:
            await db.rollback()
            raise HTTPException(status_code=401, detail="Доступ с этого устройства отозван.")

        target = (await db.execute(
            select(models.Device).where(
                models.Device.id == target_device_id,
                models.Device.user_id == caller.user_id,
            )
        )).scalars().first()
        if target is None:
            await db.rollback()
            raise HTTPException(status_code=404, detail="Устройство не найдено.")

        already_revoked = bool(target.is_revoked)
        target.is_revoked = True
        await db.commit()
    except BaseException:
        await db.rollback()
        raise

    await manager.close_device(target_device_id)
    return {
        "status": "ok",
        "device_id": target_device_id,
        "is_revoked": True,
        "already_revoked": already_revoked,
    }


@router.get("/find/{target_username}", response_model=schemas.UserLookupResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def find_user(
        request: Request,
        target_username: str,
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db)
):
    """
    Поиск союзника по тегу.

    Rate limit: 5/мин — защищает от массового перебора usernames.
    NOTE(P0-4): ответы унифицированы — по 404 нельзя отличить «нет такого юзера»,
    «юзер деактивирован» или «юзер есть, но устройств нет».
    """
    clean_username = target_username.lstrip("@")
    if not _USERNAME_LOOKUP_RE.fullmatch(clean_username):
        raise HTTPException(status_code=404, detail="Союзник с таким тегом не найден.")

    stmt = select(models.User).where(
        models.User.username == clean_username,
        models.User.is_active == True,
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="Союзник с таким тегом не найден.")

    stmt_dev = (
        select(models.Device)
        .where(
            models.Device.user_id == user.id,
            models.Device.is_revoked == False,
        )
        .order_by(models.Device.created_at.asc(), models.Device.id.asc())
        .limit(max(settings.MAX_ACTIVE_DEVICES_PER_USER, 256))
    )
    res_dev = await db.execute(stmt_dev)
    devices = res_dev.scalars().all()

    if not devices:
        # Unified response: нельзя отличить «нет юзера» от «нет устройств» —
        # это закрывает P0-4 (user enumeration). Одно сообщение для обоих случаев.
        raise HTTPException(status_code=404, detail="Союзник с таким тегом не найден.")

    dev_list = [
        {"device_id": d.id, "device_name": d.device_name, "public_key": d.public_key, "fingerprint": d.fingerprint} for
        d in devices]

    return {"user_id": user.id, "username": user.username, "devices": dev_list}
