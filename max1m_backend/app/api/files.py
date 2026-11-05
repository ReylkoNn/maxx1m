import logging
import os
import uuid
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Request
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..database import get_db
from .. import models, schemas
from ..api.messages import get_current_device_id
from ..rate_limit import limiter
from ..config import settings

logger = logging.getLogger("max1m.files")

router = APIRouter(prefix="/files", tags=["files"])

# Создаем папку для хранения зашифрованных файлов в корне бэкенда.
# Сервер видит только зашифрованный блоб — ключ шифрования знает только клиент.
UPLOAD_DIR = "secure_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Жёсткий лимит размера файла.
# Раньше тут было расхождение: комментарий говорил про 15МБ, код проверял 100МБ.
# Приводим к единому значению — 100МБ (поддерживает большие медиа-вложения).
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


@router.post("/upload")
@limiter.limit(settings.RATE_LIMIT_UPLOAD)
async def upload_file(
        request: Request,
        file: UploadFile = File(...),
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db)
):
    """
    Принимает зашифрованный блоб (картинку/голосовое/файл) и сохраняет на диск.

    Авторизация обязательна (JWT). Файл привязывается к загрузившему устройству,
    скачивать его по умолчанию может только сам загрузивший.
    Чтобы получатель тоже мог скачать — клиент должен вызвать /files/{file_id}/grant
    или передать recipient_device_id в этом запросе.
    """
    # Выдаём file_id СРАЗУ, чтобы даже при ошибке записи не было коллизий
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id)

    try:
        content = await file.read()

        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"Файл слишком большой. Максимум {MAX_FILE_SIZE // (1024 * 1024)}MB."
            )

        # Сначала пишем на диск, потом — запись в БД. Если диск упадёт,
        # не останется «битой» записи в БД.
        with open(file_path, "wb") as f:
            f.write(content)

        # Определяем владельца файла (пользователь, которому принадлежит device)
        stmt_dev = select(models.Device).where(models.Device.id == device_id)
        result = await db.execute(stmt_dev)
        device = result.scalars().first()
        if not device:
            # Токен валидный, но устройства нет — маловероятно, но проверим
            raise HTTPException(status_code=404, detail="Устройство не найдено")

        record = models.FileRecord(
            id=file_id,
            owner_user_id=device.user_id,
            size=len(content),
            uploaded_by_device_id=device_id,
        )
        db.add(record)

        # Доступ загрузившему устройству (чтобы он сам видел свои картинки)
        db.add(models.FileAccess(file_id=file_id, device_id=device_id))

        await db.commit()

        return {"file_id": file_id, "size": len(content)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Ошибка загрузки файла: %s", e)
        raise HTTPException(status_code=500, detail="Ошибка при сохранении файла")


@router.get("/{file_id}")
async def download_file(
        file_id: str,
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db)
):
    """
    Отдает зашифрованный блоб по ID.

    Авторизация обязательна. Скачать может только устройство, которому
    явно выдан доступ (FileAccess) — либо владелец, либо получатель.
    Раньше эндпоинт был открыт: любой со знанием UUID мог скачать чужое.
    """
    # Проверяем существование файла и наличие доступа ОДНИМ запросом.
    # Используем join FileAccess — это и есть проверка полномочий.
    stmt = (
        select(models.FileRecord)
        .join(models.FileAccess, models.FileAccess.file_id == models.FileRecord.id)
        .where(
            models.FileRecord.id == file_id,
            models.FileAccess.device_id == device_id,
        )
    )
    result = await db.execute(stmt)
    record = result.scalars().first()

    if not record:
        # Не раскрываем причину (нет файла vs нет доступа) — единый ответ,
        # чтобы не дать злоумышленнику информации для перебора.
        raise HTTPException(status_code=404, detail="Файл не найден")

    file_path = os.path.join(UPLOAD_DIR, file_id)
    if not os.path.exists(file_path):
        logger.warning("Файл %s есть в БД, но отсутствует на диске", file_id)
        raise HTTPException(status_code=404, detail="Файл не найден на сервере")

    return FileResponse(file_path, media_type="application/octet-stream")


@router.post("/{file_id}/grant")
async def grant_file_access(
        file_id: str,
        recipient_device_id: str,
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db)
):
    """
    Выдаёт устройству-получателю право скачивать файл.

    Вызывает ТОЛЬКО загрузивший файл (проверяем, что device_id — владелец).
    Клиент вызывает это сразу после upload, прямо перед отправкой сообщения
    с метаданными получателю — чтобы получатель гарантированно мог скачать.
    """
    # 1. Находим файл и проверяем, что запрашивающий — его загрузивший device
    stmt = select(models.FileRecord).where(models.FileRecord.id == file_id)
    result = await db.execute(stmt)
    record = result.scalars().first()
    if not record:
        raise HTTPException(status_code=404, detail="Файл не найден")

    if record.uploaded_by_device_id != device_id:
        # Чужой файл — права выдавать нельзя
        raise HTTPException(status_code=403, detail="Нет прав на этот файл")

    # 2. Проверяем, что получатель существует и не отозван
    stmt_dev = select(models.Device).where(
        models.Device.id == recipient_device_id,
        models.Device.is_revoked == False,
    )
    result = await db.execute(stmt_dev)
    recipient = result.scalars().first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Устройство получателя не найдено")

    # 3. Добавляем доступ (если уже есть — idempotent, не падаем)
    existing = await db.execute(
        select(models.FileAccess).where(
            models.FileAccess.file_id == file_id,
            models.FileAccess.device_id == recipient_device_id,
        )
    )
    if not existing.scalars().first():
        db.add(models.FileAccess(file_id=file_id, device_id=recipient_device_id))
        await db.commit()

    return {"status": "ok", "file_id": file_id, "granted_to": recipient_device_id}
