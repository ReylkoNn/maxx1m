import base64
import json
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, update, delete, text, func
from datetime import datetime, timezone
from sqlalchemy.orm import selectinload

from .. import schemas, models
from ..database import get_db
from ..api.messages import manager, get_current_device_id
from ..rate_limit import limiter
from ..config import settings

router = APIRouter(prefix="/groups", tags=["Groups"])
_SAFE_GROUP_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SAFE_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
MAX_GROUP_DEVICES = 64


def _verify_ed25519_raw(public_key_b64: str, signature_b64: str, payload_bytes: bytes) -> bool:
    try:
        pub_raw = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
        sig_raw = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        if len(pub_raw) != 32 or len(sig_raw) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw, payload_bytes)
        return True
    except Exception:
        return False


def _verify_sender_key_entry_signature(public_key_b64: str, entry: schemas.SenderKeyEntry) -> bool:
    try:
        cipher_raw = base64.b64decode(entry.encrypted_sender_key.encode("ascii"), validate=True)
        if not cipher_raw:
            return False
    except Exception:
        return False
    return _verify_ed25519_raw(public_key_b64, entry.sender_key_signature, cipher_raw)


def _canonical_group_v2_msg_bytes(
    group_id: str,
    sender_device_id: str,
    sender_key_id: str,
    epoch: int,
    chain_index: int,
    encrypted_blob: str,
) -> bytes:
    canonical = json.dumps(
        {
            "blob": encrypted_blob,
            "chain_index": int(chain_index),
            "epoch": int(epoch),
            "group_id": group_id,
            "sender_device_id": sender_device_id,
            "sender_key_id": sender_key_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return b"max1m-group-msg-sig-v2\x00" + canonical


async def _get_active_device_row(db: AsyncSession, device_id: str) -> models.Device:
    row = (
        await db.execute(
            select(models.Device)
            .join(models.User, models.User.id == models.Device.user_id)
            .where(
                models.Device.id == device_id,
                models.Device.is_revoked == False,
                models.User.is_active == True,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=401, detail="Device unavailable")
    return row


def _validate_group_id(group_id: str) -> str:
    if not isinstance(group_id, str) or not _SAFE_GROUP_ID_RE.fullmatch(group_id):
        raise HTTPException(status_code=400, detail="Некорректный идентификатор группы")
    return group_id


async def _assert_active_device_locked(db: AsyncSession, device_id: str) -> None:
    authorized = (await db.execute(
        select(models.Device.id)
        .join(models.User, models.User.id == models.Device.user_id)
        .where(
            models.Device.id == device_id,
            models.Device.is_revoked == False,
            models.User.is_active == True,
        )
    )).scalar_one_or_none()
    if authorized is None:
        raise HTTPException(status_code=401, detail="Device unavailable")


def _require_legacy_groups_enabled():
    if not settings.ALLOW_INSECURE_LEGACY_GROUPS:
        raise HTTPException(status_code=503, detail="Небезопасные групповые операции отключены до внедрения защищённого протокола")


async def _assert_member(group_id: str, device_id: str, db: AsyncSession):
    """Проверяет членство устройства в группе. Бросает 403 если нет."""
    stmt = select(models.GroupMember).where(
        and_(
            models.GroupMember.group_id == group_id,
            models.GroupMember.device_id == device_id
        )
    )
    result = await db.execute(stmt)
    member = result.scalars().first()
    if not member:
        raise HTTPException(status_code=403, detail="Не участник группы")
    return member


async def _get_member_device_ids(group_id: str, db: AsyncSession) -> list[str]:
    """Возвращает список device_id всех участников группы."""
    stmt = select(models.GroupMember.device_id).where(
        models.GroupMember.group_id == group_id
    )
    result = await db.execute(stmt)
    return [r[0] for r in result.all()]


@router.post("/create", response_model=schemas.GroupInfo)
@limiter.limit("10/hour")
async def create_group(
    request: Request,
    data: schemas.GroupCreate,
    creator_device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    _require_legacy_groups_enabled()
    recipients = set(data.member_device_ids)
    if creator_device_id in recipients or len(recipients) != len(data.member_device_ids):
        raise HTTPException(status_code=400, detail="Некорректный список участников")
    key_recipients = [entry.recipient_device_id for entry in data.sender_keys]
    if (set(key_recipients) != recipients or len(key_recipients) != len(recipients)
            or any(entry.sender_device_id not in (None, creator_device_id) for entry in data.sender_keys)):
        raise HTTPException(status_code=400, detail="Некорректный список ключей участников")

    group = models.Group(
        name=data.name,
        created_by_device_id=creator_device_id
    )
    db.add(group)
    await db.flush()

    all_device_ids = list(set([creator_device_id] + data.member_device_ids))

    for device_id in all_device_ids:
        stmt = select(models.Device).where(
            and_(models.Device.id == device_id, models.Device.is_revoked == False)
        )
        result = await db.execute(stmt)
        if not result.scalars().first():
            raise HTTPException(status_code=404, detail=f"Устройство {device_id} не найдено")

    for device_id in all_device_ids:
        role = "owner" if device_id == creator_device_id else "member"
        member = models.GroupMember(group_id=group.id, device_id=device_id, role=role)
        db.add(member)

    for entry in data.sender_keys:
        skd = models.SenderKeyDistribution(
            group_id=group.id,
            sender_device_id=creator_device_id,
            recipient_device_id=entry.recipient_device_id,
            encrypted_sender_key=entry.encrypted_sender_key,
            sender_key_signature=entry.sender_key_signature
        )
        db.add(skd)

    await db.commit()

    # ← Явная загрузка members с device через selectinload
    stmt = (
        select(models.Group)
        .options(
            selectinload(models.Group.members).selectinload(models.GroupMember.device)
        )
        .where(models.Group.id == group.id)
    )
    result = await db.execute(stmt)
    group = result.scalars().first()

    # WS уведомления
    sender_key_map = {
        entry.recipient_device_id: {
            "encrypted_sender_key": entry.encrypted_sender_key,
            "sender_key_signature": entry.sender_key_signature
        }
        for entry in data.sender_keys
    }

    for device_id in data.member_device_ids:
        ws_payload = {
            "type": "group_created",
            "group_id": group.id,
            "group_name": data.name,
            "created_by": creator_device_id,
            "members": [m.device_id for m in group.members],
        }
        if device_id in sender_key_map:
            ws_payload["sender_key"] = sender_key_map[device_id]
            ws_payload["sender_key_from"] = creator_device_id
        await manager.send_personal_message(ws_payload, device_id)

    return group


@router.get("/list", response_model=list[schemas.GroupInfo])
@limiter.limit("60/minute")
async def list_groups(
    request: Request,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(models.Group)
        .join(models.GroupMember)
        .where(models.GroupMember.device_id == device_id)
        .options(
            selectinload(models.Group.members).selectinload(models.GroupMember.device)
        )
        .order_by(models.Group.created_at.asc(), models.Group.id.asc())
        .limit(1000)
    )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{group_id}/members", response_model=list[schemas.GroupMemberInfo])
@limiter.limit("60/minute")
async def get_members(
    request: Request,
    group_id: str,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """Возвращает участников группы."""
    _validate_group_id(group_id)
    await _assert_member(group_id, device_id, db)

    stmt = (
        select(models.GroupMember, models.Device)
        .join(models.Device, models.GroupMember.device_id == models.Device.id)
        .where(models.GroupMember.group_id == group_id)
    )
    result = await db.execute(stmt)
    rows = result.all()

    return [
        schemas.GroupMemberInfo(
            device_id=device.id,
            device_name=device.device_name,
            public_key=device.public_key,
            role=member.role,
            joined_at=member.joined_at
        )
        for member, device in rows
    ]


@router.get("/{group_id}/sender_keys", response_model=list[schemas.SenderKeyBundle])
@limiter.limit("60/minute")
async def get_sender_keys(
    request: Request,
    group_id: str,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Возвращает все SenderKey предназначенные этому устройству в группе.
    Вызывается при первом входе в группу или после ротации.
    """
    _validate_group_id(group_id)
    await _assert_member(group_id, device_id, db)

    stmt = select(models.SenderKeyDistribution).where(
        and_(
            models.SenderKeyDistribution.group_id == group_id,
            models.SenderKeyDistribution.recipient_device_id == device_id
        )
    )
    result = await db.execute(stmt)
    distributions = result.scalars().all()

    return [
        schemas.SenderKeyBundle(
            group_id=skd.group_id,
            sender_device_id=skd.sender_device_id,
            encrypted_sender_key=skd.encrypted_sender_key,
            sender_key_signature=skd.sender_key_signature,
            epoch=skd.epoch or 1,
        )
        for skd in distributions
    ]


@router.post("/send", response_model=schemas.GroupMessageResponse)
@limiter.limit("60/minute")
async def send_group_message(
    request: Request,
    msg: schemas.GroupMessageSend,
    sender_device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Принимает ONE зашифрованный blob (Sender Keys).
    Сохраняет и пушит всем участникам.
    Создаёт per-device delivery записи для надёжного sync.
    """
    _require_legacy_groups_enabled()
    await _assert_member(msg.group_id, sender_device_id, db)

    # Сохраняем сообщение
    new_msg = models.GroupMessage(
        group_id=msg.group_id,
        sender_device_id=sender_device_id,
        encrypted_blob=msg.encrypted_blob,
        signature=msg.signature,
        sender_key_id=msg.sender_key_id,
        chain_index=msg.chain_index
    )
    db.add(new_msg)
    await db.flush()  # получаем new_msg.id

    # Получаем всех участников кроме отправителя
    stmt = select(models.GroupMember).where(
        and_(
            models.GroupMember.group_id == msg.group_id,
            models.GroupMember.device_id != sender_device_id
        )
    )
    result = await db.execute(stmt)
    members = result.scalars().all()

    # Создаём per-device delivery записи
    for member in members:
        delivery = models.GroupMessageDelivery(
            message_id=new_msg.id,
            device_id=member.device_id,
            is_delivered=False
        )
        db.add(delivery)

    await db.commit()
    await db.refresh(new_msg)

    # WS payload
    ws_payload = {
        "type": "group_message",
        "message_id": new_msg.id,
        "group_id": msg.group_id,
        "sender_device_id": sender_device_id,
        "encrypted_blob": msg.encrypted_blob,
        "signature": msg.signature,
        "sender_key_id": msg.sender_key_id,
        "chain_index": msg.chain_index,
        "created_at": new_msg.created_at.isoformat()
    }

    # A successful WebSocket send does not prove the client saved the message.
    # Leave every delivery pending for sync/explicit acknowledgement.
    for member in members:
        await manager.send_personal_message(ws_payload, member.device_id)
    return new_msg


@router.post("/invite")
@limiter.limit("10/hour")
async def invite_member(
    request: Request,
    data: schemas.GroupInvite,
    inviter_device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Приглашает нового участника.
    Inviter передаёт SenderKey от каждого участника
    зашифрованный pub key нового участника.
    """
    _require_legacy_groups_enabled()
    await _assert_member(data.group_id, inviter_device_id, db)

    # A client may distribute only its own signed key, never impersonate
    # another group member or address the key to a different device.
    if (len(data.sender_keys) != 1 or any(
        entry.sender_device_id != inviter_device_id
        or entry.recipient_device_id != data.new_member_device_id
        for entry in data.sender_keys
    )):
        raise HTTPException(status_code=400, detail="Некорректные данные ключа")

    # Проверяем что новый участник существует
    stmt = select(models.Device).where(
        and_(
            models.Device.id == data.new_member_device_id,
            models.Device.is_revoked == False
        )
    )
    result = await db.execute(stmt)
    if not result.scalars().first():
        raise HTTPException(status_code=404, detail="Устройство не найдено")

    # Проверяем что ещё не участник
    stmt = select(models.GroupMember).where(
        and_(
            models.GroupMember.group_id == data.group_id,
            models.GroupMember.device_id == data.new_member_device_id
        )
    )
    result = await db.execute(stmt)
    if result.scalars().first():
        raise HTTPException(status_code=409, detail="Уже участник группы")

    # Добавляем нового участника
    new_member = models.GroupMember(
        group_id=data.group_id,
        device_id=data.new_member_device_id,
        role="member"
    )
    db.add(new_member)

    # Сохраняем SenderKey distributions для нового участника.
    # Каждый entry — ключ от одного существующего участника, зашифрованный
    # для нового. entry.sender_device_id указывает КТО шлёт свой ключ.
    for entry in data.sender_keys:
        if not entry.sender_device_id:
            raise HTTPException(
                status_code=400,
                detail="Каждый SenderKeyEntry в invite обязан содержать sender_device_id"
            )
        skd = models.SenderKeyDistribution(
            group_id=data.group_id,
            sender_device_id=entry.sender_device_id,
            recipient_device_id=data.new_member_device_id,
            encrypted_sender_key=entry.encrypted_sender_key,
            sender_key_signature=entry.sender_key_signature
        )
        db.add(skd)

    await db.commit()

    # Нотифицируем нового участника
    # Собираем все его SenderKey в одном пакете
    sender_keys_payload = [
        {
            "sender_device_id": entry.sender_device_id,
            "encrypted_sender_key": entry.encrypted_sender_key,
            "sender_key_signature": entry.sender_key_signature
        }
        for entry in data.sender_keys
    ]

    await manager.send_personal_message({
        "type": "group_invited",
        "group_id": data.group_id,
        "invited_by": inviter_device_id,
        "sender_keys": sender_keys_payload
    }, data.new_member_device_id)

    # Нотифицируем существующих участников о новом члене
    existing_device_ids = await _get_member_device_ids(data.group_id, db)
    for device_id in existing_device_ids:
        if device_id != data.new_member_device_id:
            await manager.send_personal_message({
                "type": "group_member_joined",
                "group_id": data.group_id,
                "new_member_device_id": data.new_member_device_id
            }, device_id)

    return {"status": "ok"}


@router.post("/{group_id}/leave")
@limiter.limit("20/minute")
async def leave_group(
    request: Request,
    group_id: str,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Покидает группу.
    Уведомляет оставшихся — они должны сделать ротацию SenderKey.
    """
    _validate_group_id(group_id)
    await db.rollback()
    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        await _assert_active_device_locked(db, device_id)
        member = await _assert_member(group_id, device_id, db)

        if member.role == "owner":
            raise HTTPException(status_code=409, detail="Создатель должен удалить группу, а не покидать её")

        group_obj = (
            await db.execute(select(models.Group).where(models.Group.id == group_id))
        ).scalar_one_or_none()
        new_epoch = 1
        if group_obj is not None:
            group_obj.epoch = int(group_obj.epoch or 1) + 1
            new_epoch = group_obj.epoch

        await db.delete(member)
        # Keep old sender bundles for remaining members: they may still need to
        # decrypt messages sent before departure. Remove bundles and pending
        # deliveries addressed to the departed device.
        await db.execute(delete(models.SenderKeyDistribution).where(
            models.SenderKeyDistribution.group_id == group_id,
            models.SenderKeyDistribution.recipient_device_id == device_id,
        ))
        group_message_ids = select(models.GroupMessage.id).where(models.GroupMessage.group_id == group_id)
        await db.execute(delete(models.GroupMessageDelivery).where(
            models.GroupMessageDelivery.device_id == device_id,
            models.GroupMessageDelivery.message_id.in_(group_message_ids),
        ))
        remaining_ids = await _get_member_device_ids(group_id, db)
        await db.commit()
    except BaseException:
        await db.rollback()
        raise

    # Нотифицируем оставшихся — нужна ротация ключей
    for remaining_device_id in remaining_ids:
        await manager.send_personal_message({
            "type": "group_member_left",
            "group_id": group_id,
            "left_device_id": device_id,
            "epoch": new_epoch,
            "rotation_required": True
        }, remaining_device_id)

    return {"status": "ok", "epoch": new_epoch}


@router.get("/sync", response_model=list[schemas.GroupMessageResponse])
@limiter.limit("60/minute")
async def sync_group_messages(
    request: Request,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Синхронизация непрочитанных групповых сообщений.
    Per-device delivery — каждый участник получает своё независимо.
    """
    # The legacy endpoint marks data delivered before the client has stored it.
    # Keep it only for explicitly enabled, unsafe migration deployments.
    _require_legacy_groups_enabled()
    stmt = (
        select(models.GroupMessage)
        .join(
            models.GroupMessageDelivery,
            and_(
                models.GroupMessageDelivery.message_id == models.GroupMessage.id,
                models.GroupMessageDelivery.device_id == device_id,
                models.GroupMessageDelivery.is_delivered == False
            )
        )
        .join(models.GroupMember, and_(
            models.GroupMember.group_id == models.GroupMessage.group_id,
            models.GroupMember.device_id == device_id,
        ))
        .where(models.GroupMessage.sender_device_id != device_id)
        .order_by(models.GroupMessage.created_at.asc())
    )

    result = await db.execute(stmt)
    messages = result.scalars().all()

    if not messages:
        return []

    # Помечаем delivered
    now = datetime.now(timezone.utc)
    for msg in messages:
        stmt = select(models.GroupMessageDelivery).where(
            and_(
                models.GroupMessageDelivery.message_id == msg.id,
                models.GroupMessageDelivery.device_id == device_id
            )
        )
        result = await db.execute(stmt)
        delivery = result.scalars().first()
        if delivery:
            delivery.is_delivered = True
            delivery.delivered_at = now

    await db.commit()
    return messages

@router.get("/sync-safe", response_model=list[schemas.GroupMessageResponse])
@limiter.limit("60/minute")
async def sync_group_messages_safe(
    request: Request,
    after: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=100),
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    """Bounded queue; delivery remains pending until explicitly acknowledged."""
    if after is not None and not _SAFE_GROUP_ID_RE.fullmatch(after):
        raise HTTPException(status_code=400, detail="Invalid cursor")
    stmt = (
        select(models.GroupMessage)
        .join(models.GroupMessageDelivery, models.GroupMessageDelivery.message_id == models.GroupMessage.id)
        .join(models.GroupMember, and_(
            models.GroupMember.group_id == models.GroupMessage.group_id,
            models.GroupMember.device_id == device_id,
        ))
        .where(models.GroupMessageDelivery.device_id == device_id,
               models.GroupMessageDelivery.is_delivered == False)
    )
    if after:
        cursor_result = await db.execute(
            select(models.GroupMessage)
            .join(models.GroupMessageDelivery, models.GroupMessageDelivery.message_id == models.GroupMessage.id)
            .join(models.GroupMember, and_(
                models.GroupMember.group_id == models.GroupMessage.group_id,
                models.GroupMember.device_id == device_id,
            ))
            .where(models.GroupMessage.id == after, models.GroupMessageDelivery.device_id == device_id)
        )
        cursor = cursor_result.scalars().first()
        if cursor is None:
            raise HTTPException(status_code=400, detail="Invalid cursor")
        stmt = stmt.where(or_(
            models.GroupMessage.created_at > cursor.created_at,
            and_(models.GroupMessage.created_at == cursor.created_at, models.GroupMessage.id > cursor.id),
        ))
    result = await db.execute(stmt.order_by(models.GroupMessage.created_at, models.GroupMessage.id).limit(limit))
    return result.scalars().all()


@router.post("/ack")
@limiter.limit("60/minute")
async def acknowledge_group_messages(
    request: Request,
    ack: schemas.MessageDeliveryAck,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    """Acknowledge only deliveries belonging to current group memberships."""
    await db.rollback()
    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        await _assert_active_device_locked(db, device_id)
        allowed_messages = (
            select(models.GroupMessage.id)
            .join(models.GroupMember, and_(
                models.GroupMember.group_id == models.GroupMessage.group_id,
                models.GroupMember.device_id == device_id,
            ))
            .where(models.GroupMessage.id.in_(ack.message_ids))
        )
        now = datetime.now(timezone.utc)
        await db.execute(
            update(models.GroupMessageDelivery)
            .where(models.GroupMessageDelivery.device_id == device_id,
                   models.GroupMessageDelivery.message_id.in_(allowed_messages))
            .values(
                is_delivered=True,
                delivered_at=now,
            )
        )
        await db.commit()
        return {"status": "ok"}
    except BaseException:
        await db.rollback()
        raise


@router.delete("/{group_id}")
@limiter.limit("20/minute")
async def delete_group(
    request: Request,
    group_id: str,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Удаляет группу полностью.
    Только создатель (owner) может удалить группу.
    Уведомляет всех участников через WS.
    """
    _validate_group_id(group_id)
    await db.rollback()
    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        await _assert_active_device_locked(db, device_id)
        await _assert_member(group_id, device_id, db)

        stmt = select(models.Group).where(models.Group.id == group_id)
        result = await db.execute(stmt)
        group = result.scalars().first()

        if not group:
            raise HTTPException(status_code=404, detail="Группа не найдена")

        if group.created_by_device_id != device_id:
            raise HTTPException(
                status_code=403,
                detail="Только создатель может удалить группу"
            )

        member_ids = await _get_member_device_ids(group_id, db)

        # SQLAlchemy cascade удалит связанные записи автоматически:
        # GroupMessageDelivery → GroupMessage → GroupMember → SenderKeyDistribution → Group
        await db.delete(group)
        await db.commit()
    except BaseException:
        await db.rollback()
        raise

    # Уведомляем всех участников
    for member_device_id in member_ids:
        await manager.send_personal_message({
            "type": "group_deleted",
            "group_id": group_id
        }, member_device_id)

    return {"status": "ok"}


# ============================================================================
# PROTECTED V2 GROUP PROTOCOL (Authenticated Ratcheted Sender Keys + Epochs)
# ============================================================================

@router.post("/v2/create", response_model=schemas.GroupInfo)
@limiter.limit("20/hour")
async def create_group_v2(
    request: Request,
    data: schemas.GroupV2Create,
    creator_device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Пустое имя группы")

    recipients = set(data.member_device_ids)
    if (
        creator_device_id in recipients
        or len(recipients) != len(data.member_device_ids)
        or len(recipients) + 1 > MAX_GROUP_DEVICES
    ):
        raise HTTPException(status_code=400, detail="Некорректный список участников")

    key_recipients = [entry.recipient_device_id for entry in data.sender_keys]
    if (
        set(key_recipients) != recipients
        or len(key_recipients) != len(recipients)
        or any(entry.sender_device_id not in (None, creator_device_id) for entry in data.sender_keys)
    ):
        raise HTTPException(status_code=400, detail="Некорректный список ключей участников")

    await db.rollback()
    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        creator_dev = await _get_active_device_row(db, creator_device_id)

        for entry in data.sender_keys:
            if not _verify_sender_key_entry_signature(creator_dev.public_key, entry):
                raise HTTPException(status_code=400, detail="Неверная подпись ключа участника")

        all_device_ids = [creator_device_id] + list(data.member_device_ids)
        active_rows = (
            await db.execute(
                select(models.Device.id)
                .join(models.User, models.User.id == models.Device.user_id)
                .where(
                    models.Device.id.in_(all_device_ids),
                    models.Device.is_revoked == False,
                    models.User.is_active == True,
                )
            )
        ).scalars().all()
        if len(set(active_rows)) != len(all_device_ids):
            raise HTTPException(status_code=404, detail="Одно или несколько устройств недоступны")

        group = models.Group(
            name=name,
            created_by_device_id=creator_device_id,
            epoch=1,
        )
        db.add(group)
        await db.flush()

        for dev_id in all_device_ids:
            role = "owner" if dev_id == creator_device_id else "member"
            db.add(models.GroupMember(group_id=group.id, device_id=dev_id, role=role))

        for entry in data.sender_keys:
            db.add(
                models.SenderKeyDistribution(
                    group_id=group.id,
                    sender_device_id=creator_device_id,
                    recipient_device_id=entry.recipient_device_id,
                    encrypted_sender_key=entry.encrypted_sender_key,
                    sender_key_signature=entry.sender_key_signature,
                    epoch=1,
                )
            )

        await db.commit()
    except BaseException:
        await db.rollback()
        raise

    loaded = (
        await db.execute(
            select(models.Group)
            .options(selectinload(models.Group.members).selectinload(models.GroupMember.device))
            .where(models.Group.id == group.id)
        )
    ).scalars().first()

    sender_key_map = {
        entry.recipient_device_id: {
            "encrypted_sender_key": entry.encrypted_sender_key,
            "sender_key_signature": entry.sender_key_signature,
            "epoch": 1,
        }
        for entry in data.sender_keys
    }
    member_list = [m.device_id for m in loaded.members]
    for dev_id in data.member_device_ids:
        ws_payload = {
            "type": "group_created",
            "protocol_version": 2,
            "group_id": loaded.id,
            "group_name": loaded.name,
            "epoch": 1,
            "created_by": creator_device_id,
            "members": member_list,
        }
        if dev_id in sender_key_map:
            ws_payload["sender_key"] = sender_key_map[dev_id]
            ws_payload["sender_key_from"] = creator_device_id
        await manager.send_personal_message(ws_payload, dev_id)

    return loaded


@router.post("/v2/{group_id}/distribute-key")
@limiter.limit("60/minute")
async def distribute_group_sender_key_v2(
    request: Request,
    group_id: str,
    data: schemas.GroupKeyRotateRequest,
    sender_device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    _validate_group_id(group_id)
    await db.rollback()
    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        sender_dev = await _get_active_device_row(db, sender_device_id)
        await _assert_member(group_id, sender_device_id, db)

        group = (
            await db.execute(select(models.Group).where(models.Group.id == group_id))
        ).scalar_one_or_none()
        if group is None:
            raise HTTPException(status_code=404, detail="Группа не найдена")

        current_epoch = int(group.epoch or 1)
        if data.epoch < current_epoch:
            raise HTTPException(status_code=409, detail="Устаревшая эпоха ключа группы")

        other_members = set(
            (
                await db.execute(
                    select(models.GroupMember.device_id)
                    .join(models.Device, models.Device.id == models.GroupMember.device_id)
                    .join(models.User, models.User.id == models.Device.user_id)
                    .where(
                        models.GroupMember.group_id == group_id,
                        models.GroupMember.device_id != sender_device_id,
                        models.Device.is_revoked == False,
                        models.User.is_active == True,
                    )
                )
            ).scalars().all()
        )

        given_recipients = [entry.recipient_device_id for entry in data.sender_keys]
        if (
            set(given_recipients) != other_members
            or len(given_recipients) != len(other_members)
            or any(entry.sender_device_id not in (None, sender_device_id) for entry in data.sender_keys)
        ):
            raise HTTPException(status_code=400, detail="Список получателей ключа не совпадает с составом группы")

        for entry in data.sender_keys:
            if not _verify_sender_key_entry_signature(sender_dev.public_key, entry):
                raise HTTPException(status_code=400, detail="Неверная подпись ключа")

        effective_epoch = max(current_epoch, int(data.epoch))
        group.epoch = effective_epoch

        await db.execute(
            delete(models.SenderKeyDistribution).where(
                models.SenderKeyDistribution.group_id == group_id,
                models.SenderKeyDistribution.sender_device_id == sender_device_id,
            )
        )
        for entry in data.sender_keys:
            db.add(
                models.SenderKeyDistribution(
                    group_id=group_id,
                    sender_device_id=sender_device_id,
                    recipient_device_id=entry.recipient_device_id,
                    encrypted_sender_key=entry.encrypted_sender_key,
                    sender_key_signature=entry.sender_key_signature,
                    epoch=effective_epoch,
                )
            )
        await db.commit()
    except BaseException:
        await db.rollback()
        raise

    for entry in data.sender_keys:
        await manager.send_personal_message(
            {
                "type": "group_sender_key_updated",
                "protocol_version": 2,
                "group_id": group_id,
                "epoch": effective_epoch,
                "sender_device_id": sender_device_id,
                "encrypted_sender_key": entry.encrypted_sender_key,
                "sender_key_signature": entry.sender_key_signature,
            },
            entry.recipient_device_id,
        )

    return {"status": "ok", "epoch": effective_epoch}


@router.post("/v2/invite")
@limiter.limit("20/hour")
async def invite_member_v2(
    request: Request,
    data: schemas.GroupV2Invite,
    inviter_device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    _validate_group_id(data.group_id)
    if not _SAFE_GROUP_ID_RE.fullmatch(data.new_member_device_id):
        raise HTTPException(status_code=400, detail="Некорректный идентификатор устройства")

    await db.rollback()
    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        inviter_dev = await _get_active_device_row(db, inviter_device_id)
        await _assert_member(data.group_id, inviter_device_id, db)

        group = (
            await db.execute(select(models.Group).where(models.Group.id == data.group_id))
        ).scalar_one_or_none()
        if group is None:
            raise HTTPException(status_code=404, detail="Группа не найдена")

        target_dev = (
            await db.execute(
                select(models.Device)
                .join(models.User, models.User.id == models.Device.user_id)
                .where(
                    models.Device.id == data.new_member_device_id,
                    models.Device.is_revoked == False,
                    models.User.is_active == True,
                )
            )
        ).scalar_one_or_none()
        if target_dev is None:
            raise HTTPException(status_code=404, detail="Устройство не найдено")

        already = (
            await db.execute(
                select(models.GroupMember.id).where(
                    models.GroupMember.group_id == data.group_id,
                    models.GroupMember.device_id == data.new_member_device_id,
                )
            )
        ).scalar_one_or_none()
        if already is not None:
            raise HTTPException(status_code=409, detail="Уже участник группы")

        active_members = set(
            (
                await db.execute(
                    select(models.GroupMember.device_id)
                    .join(models.Device, models.Device.id == models.GroupMember.device_id)
                    .join(models.User, models.User.id == models.Device.user_id)
                    .where(
                        models.GroupMember.group_id == data.group_id,
                        models.Device.is_revoked == False,
                        models.User.is_active == True,
                    )
                )
            ).scalars().all()
        )
        if len(active_members) + 1 > MAX_GROUP_DEVICES:
            raise HTTPException(status_code=400, detail="Превышен лимит участников группы")

        expected_recipients = (active_members - {inviter_device_id}) | {data.new_member_device_id}
        given_recipients = [entry.recipient_device_id for entry in data.sender_keys]
        if (
            set(given_recipients) != expected_recipients
            or len(given_recipients) != len(expected_recipients)
            or any(entry.sender_device_id not in (None, inviter_device_id) for entry in data.sender_keys)
        ):
            raise HTTPException(
                status_code=400,
                detail="При приглашении требуется ротированный ключ приглашающего для всех активных участников",
            )

        for entry in data.sender_keys:
            if not _verify_sender_key_entry_signature(inviter_dev.public_key, entry):
                raise HTTPException(status_code=400, detail="Неверная подпись ключа")

        new_epoch = int(group.epoch or 1) + 1
        group.epoch = new_epoch
        group_name = group.name
        created_by_dev = group.created_by_device_id

        db.add(
            models.GroupMember(
                group_id=data.group_id,
                device_id=data.new_member_device_id,
                role="member",
            )
        )

        await db.execute(
            delete(models.SenderKeyDistribution).where(
                models.SenderKeyDistribution.group_id == data.group_id,
                models.SenderKeyDistribution.sender_device_id == inviter_device_id,
            )
        )
        for entry in data.sender_keys:
            db.add(
                models.SenderKeyDistribution(
                    group_id=data.group_id,
                    sender_device_id=inviter_device_id,
                    recipient_device_id=entry.recipient_device_id,
                    encrypted_sender_key=entry.encrypted_sender_key,
                    sender_key_signature=entry.sender_key_signature,
                    epoch=new_epoch,
                )
            )

        all_member_ids = list(active_members | {data.new_member_device_id})
        await db.commit()
    except BaseException:
        await db.rollback()
        raise

    entry_by_recipient = {e.recipient_device_id: e for e in data.sender_keys}
    new_entry = entry_by_recipient.get(data.new_member_device_id)

    await manager.send_personal_message(
        {
            "type": "group_invited",
            "protocol_version": 2,
            "group_id": data.group_id,
            "group_name": group_name,
            "created_by": created_by_dev,
            "invited_by": inviter_device_id,
            "epoch": new_epoch,
            "members": all_member_ids,
            "sender_keys": (
                [
                    {
                        "sender_device_id": inviter_device_id,
                        "encrypted_sender_key": new_entry.encrypted_sender_key,
                        "sender_key_signature": new_entry.sender_key_signature,
                        "epoch": new_epoch,
                    }
                ]
                if new_entry
                else []
            ),
        },
        data.new_member_device_id,
    )

    for dev_id in active_members:
        if dev_id == inviter_device_id:
            continue
        upd_entry = entry_by_recipient.get(dev_id)
        if upd_entry:
            await manager.send_personal_message(
                {
                    "type": "group_sender_key_updated",
                    "protocol_version": 2,
                    "group_id": data.group_id,
                    "epoch": new_epoch,
                    "sender_device_id": inviter_device_id,
                    "encrypted_sender_key": upd_entry.encrypted_sender_key,
                    "sender_key_signature": upd_entry.sender_key_signature,
                },
                dev_id,
            )
        await manager.send_personal_message(
            {
                "type": "group_member_joined",
                "protocol_version": 2,
                "group_id": data.group_id,
                "epoch": new_epoch,
                "new_member_device_id": data.new_member_device_id,
                "rotation_required": True,
            },
            dev_id,
        )

    return {"status": "ok", "epoch": new_epoch}


@router.post("/v2/send", response_model=schemas.GroupMessageResponse)
@limiter.limit("60/minute")
async def send_group_message_v2(
    request: Request,
    msg: schemas.GroupV2MessageSend,
    sender_device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    _validate_group_id(msg.group_id)
    if not _SAFE_KEY_ID_RE.fullmatch(msg.sender_key_id):
        raise HTTPException(status_code=400, detail="Некорректный sender_key_id")

    await db.rollback()
    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        sender_dev = await _get_active_device_row(db, sender_device_id)
        await _assert_member(msg.group_id, sender_device_id, db)

        group = (
            await db.execute(select(models.Group).where(models.Group.id == msg.group_id))
        ).scalar_one_or_none()
        if group is None:
            raise HTTPException(status_code=404, detail="Группа не найдена")

        current_epoch = int(group.epoch or 1)
        if msg.epoch != current_epoch:
            raise HTTPException(
                status_code=409,
                detail=f"Несовпадение эпохи группы (ожидалась {current_epoch})",
            )

        canonical_bytes = _canonical_group_v2_msg_bytes(
            group_id=msg.group_id,
            sender_device_id=sender_device_id,
            sender_key_id=msg.sender_key_id,
            epoch=msg.epoch,
            chain_index=msg.chain_index,
            encrypted_blob=msg.encrypted_blob,
        )
        if not _verify_ed25519_raw(sender_dev.public_key, msg.signature, canonical_bytes):
            raise HTTPException(status_code=400, detail="Неверная подпись группового сообщения")

        recipient_ids = list(
            (
                await db.execute(
                    select(models.GroupMember.device_id)
                    .join(models.Device, models.Device.id == models.GroupMember.device_id)
                    .join(models.User, models.User.id == models.Device.user_id)
                    .where(
                        models.GroupMember.group_id == msg.group_id,
                        models.GroupMember.device_id != sender_device_id,
                        models.Device.is_revoked == False,
                        models.User.is_active == True,
                    )
                )
            ).scalars().all()
        )

        if len(msg.encrypted_blob.encode("utf-8")) > int(settings.MAX_MESSAGE_PAYLOAD_BYTES):
            raise HTTPException(status_code=413, detail="Размер группового сообщения превышает лимит")

        # Enforce per-recipient pending queue cap to prevent unbounded DB growth.
        max_pending = int(settings.MAX_PENDING_PER_DEVICE)
        if recipient_ids and max_pending > 0:
            overloaded = (
                await db.execute(
                    select(models.GroupMessageDelivery.device_id)
                    .where(
                        models.GroupMessageDelivery.device_id.in_(recipient_ids),
                        models.GroupMessageDelivery.is_delivered == False,
                    )
                    .group_by(models.GroupMessageDelivery.device_id)
                    .having(func.count(models.GroupMessageDelivery.id) >= max_pending)
                    .limit(1)
                )
            ).scalar_one_or_none()
            if overloaded is not None:
                raise HTTPException(
                    status_code=429,
                    detail="Очередь недоставленных групповых сообщений переполнена",
                )

        new_msg = models.GroupMessage(
            group_id=msg.group_id,
            sender_device_id=sender_device_id,
            encrypted_blob=msg.encrypted_blob,
            signature=msg.signature,
            sender_key_id=msg.sender_key_id,
            epoch=msg.epoch,
            chain_index=msg.chain_index,
        )
        db.add(new_msg)
        await db.flush()

        for rec_id in recipient_ids:
            db.add(
                models.GroupMessageDelivery(
                    message_id=new_msg.id,
                    device_id=rec_id,
                    is_delivered=False,
                )
            )

        await db.commit()
        await db.refresh(new_msg)
    except BaseException:
        await db.rollback()
        raise

    ws_payload = {
        "type": "group_message",
        "protocol_version": 2,
        "id": new_msg.id,
        "message_id": new_msg.id,
        "group_id": msg.group_id,
        "sender_device_id": sender_device_id,
        "encrypted_blob": msg.encrypted_blob,
        "signature": msg.signature,
        "sender_key_id": msg.sender_key_id,
        "epoch": msg.epoch,
        "chain_index": msg.chain_index,
        "created_at": new_msg.created_at.isoformat(),
    }
    for rec_id in recipient_ids:
        await manager.send_personal_message(ws_payload, rec_id)

    return new_msg