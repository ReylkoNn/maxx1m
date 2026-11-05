from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import timedelta, datetime, timezone

from .. import schemas, models, security
from ..database import get_db
from ..config import settings
from ..rate_limit import limiter
from ..api.messages import get_current_device_id

router = APIRouter(prefix="/auth", tags=["Authentication"])


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
    stmt = select(models.InviteCode).where(models.InviteCode.code == user_in.invite_code)
    result = await db.execute(stmt)
    invite = result.scalars().first()

    if not invite:
        raise HTTPException(status_code=400, detail="Неверный инвайт-код.")
    if invite.is_used:
        raise HTTPException(status_code=400, detail="Инвайт-код уже использован.")
    if invite.expires_at:
        expires = invite.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="Инвайт-код истёк.")

    stmt = select(models.User).where(models.User.username == user_in.username)
    result = await db.execute(stmt)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Имя пользователя уже занято.")

    hashed_password = security.hash_password(user_in.password)
    new_user = models.User(username=user_in.username, password_hash=hashed_password)
    db.add(new_user)
    await db.flush()

    new_device = models.Device(
        user_id=new_user.id, device_name=user_in.device_name,
        public_key=user_in.public_key, fingerprint=user_in.fingerprint
    )
    db.add(new_device)

    invite.is_used = True
    invite.used_by_user_id = new_user.id

    await db.commit()
    await db.refresh(new_user)
    await db.refresh(new_device)

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

    if not user or not security.verify_password(login_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Неверное имя пользователя или пароль.")

    device_id_to_auth = None

    if login_data.device_id:
        stmt = select(models.Device).where(
            models.Device.id == login_data.device_id, models.Device.user_id == user.id
        )
        result = await db.execute(stmt)
        existing_device = result.scalars().first()

        if not existing_device:
            raise HTTPException(status_code=400, detail="Устройство не найдено.")
        if existing_device.is_revoked:
            raise HTTPException(status_code=403, detail="Доступ с этого устройства отозван.")

        device_id_to_auth = existing_device.id

    elif login_data.public_key and login_data.fingerprint and login_data.device_name:
        stmt = select(models.Device).where(models.Device.fingerprint == login_data.fingerprint)
        result = await db.execute(stmt)
        if result.scalars().first():
            raise HTTPException(status_code=400, detail="Такой Fingerprint устройства уже существует.")

        new_device = models.Device(
            user_id=user.id, device_name=login_data.device_name,
            public_key=login_data.public_key, fingerprint=login_data.fingerprint
        )
        db.add(new_device)
        await db.commit()
        await db.refresh(new_device)
        device_id_to_auth = new_device.id
    else:
        raise HTTPException(status_code=400, detail="Необходимы данные устройства.")

    access_token = security.create_access_token(
        data={"sub": user.id, "device_id": device_id_to_auth},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return schemas.TokenResponse(access_token=access_token, token_type="bearer", device_id=device_id_to_auth)


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
    NOTE(P0-4): ответы унифицированы — по 404 нельзя отличить «нет такого юзера»
    от «юзер есть, но устройств нет».
    """
    clean_username = target_username.lstrip("@")

    stmt = select(models.User).where(models.User.username == clean_username)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="Союзник с таким тегом не найден.")

    stmt_dev = select(models.Device).where(
        models.Device.user_id == user.id,
        models.Device.is_revoked == False
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
