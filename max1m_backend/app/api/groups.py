from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_
from datetime import datetime, timezone
from sqlalchemy.orm import selectinload

from .. import schemas, models
from ..database import get_db
from ..api.messages import manager, get_current_device_id
from ..rate_limit import limiter

router = APIRouter(prefix="/groups", tags=["Groups"])


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
        # Для create_group отправитель всегда создатель, но если клиент
        # явно передал sender_device_id — доверяем ему (consistency).
        actual_sender = entry.sender_device_id or creator_device_id
        skd = models.SenderKeyDistribution(
            group_id=group.id,
            sender_device_id=actual_sender,
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
async def list_groups(
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
    )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{group_id}/members", response_model=list[schemas.GroupMemberInfo])
async def get_members(
    group_id: str,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """Возвращает участников группы."""
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
async def get_sender_keys(
    group_id: str,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Возвращает все SenderKey предназначенные этому устройству в группе.
    Вызывается при первом входе в группу или после ротации.
    """
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
            sender_key_signature=skd.sender_key_signature
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

    # Пушим онлайн участникам и помечаем delivered
    for member in members:
        if member.device_id in manager.active_connections:
            await manager.send_personal_message(ws_payload, member.device_id)
            # Помечаем delivered для онлайн участников
            stmt = select(models.GroupMessageDelivery).where(
                and_(
                    models.GroupMessageDelivery.message_id == new_msg.id,
                    models.GroupMessageDelivery.device_id == member.device_id
                )
            )
            result = await db.execute(stmt)
            delivery = result.scalars().first()
            if delivery:
                delivery.is_delivered = True
                delivery.delivered_at = datetime.now(timezone.utc)

    await db.commit()
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
    await _assert_member(data.group_id, inviter_device_id, db)

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
async def leave_group(
    group_id: str,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Покидает группу.
    Уведомляет оставшихся — они должны сделать ротацию SenderKey.
    """
    member = await _assert_member(group_id, device_id, db)

    await db.delete(member)

    # Удаляем SenderKey distributions связанные с этим участником
    stmt = select(models.SenderKeyDistribution).where(
        and_(
            models.SenderKeyDistribution.group_id == group_id,
            models.SenderKeyDistribution.sender_device_id == device_id
        )
    )
    result = await db.execute(stmt)
    for skd in result.scalars().all():
        await db.delete(skd)

    await db.commit()

    # Нотифицируем оставшихся — нужна ротация ключей
    remaining_ids = await _get_member_device_ids(group_id, db)
    for remaining_device_id in remaining_ids:
        await manager.send_personal_message({
            "type": "group_member_left",
            "group_id": group_id,
            "left_device_id": device_id,
            # Флаг — клиент ОБЯЗАН сделать ротацию SenderKey
            "rotation_required": True
        }, remaining_device_id)

    return {"status": "ok"}


@router.get("/sync", response_model=list[schemas.GroupMessageResponse])
async def sync_group_messages(
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Синхронизация непрочитанных групповых сообщений.
    Per-device delivery — каждый участник получает своё независимо.
    """
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

@router.delete("/{group_id}")
async def delete_group(
    group_id: str,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Удаляет группу полностью.
    Только создатель (owner) может удалить группу.
    Уведомляет всех участников через WS.
    """
    # Проверяем членство
    await _assert_member(group_id, device_id, db)

    # Проверяем что это создатель
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

    # Получаем всех участников до удаления
    member_ids = await _get_member_device_ids(group_id, db)

    # SQLAlchemy cascade удалит связанные записи автоматически:
    # GroupMessageDelivery → GroupMessage → GroupMember → SenderKeyDistribution → Group
    await db.delete(group)
    await db.commit()

    # Уведомляем всех участников
    for member_device_id in member_ids:
        await manager.send_personal_message({
            "type": "group_deleted",
            "group_id": group_id
        }, member_device_id)

    return {"status": "ok"}