import logging
import time
from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from jose import jwt, JWTError
from typing import List, Dict

from .. import schemas, models
from ..database import get_db, AsyncSessionLocal
from ..config import settings
import json

logger = logging.getLogger("max1m.messages")
router = APIRouter(prefix="/messages", tags=["Messages"])
security_scheme = HTTPBearer()


# ==========================================
# МЕНЕДЖЕР WEBSOCKET ПОДКЛЮЧЕНИЙ
# ==========================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self._device_cache: Dict[str, float] = {}
        self._CACHE_TTL = 60.0

    def _is_device_valid_cached(self, device_id: str) -> bool:
        ts = self._device_cache.get(device_id)
        if ts is not None and (time.monotonic() - ts) < self._CACHE_TTL:
            return True
        return False

    def _cache_device(self, device_id: str):
        self._device_cache[device_id] = time.monotonic()

    def _invalidate_device_cache(self, device_id: str):
        self._device_cache.pop(device_id, None)

    async def connect(self, websocket: WebSocket, device_id: str):
        await websocket.accept()
        self.active_connections[device_id] = websocket
        logger.info("Устройство %s подключилось.", device_id)

    def disconnect(self, device_id: str):
        if device_id in self.active_connections:
            del self.active_connections[device_id]
            logger.info("Устройство %s отключилось.", device_id)

    async def send_personal_message(self, message: dict, device_id: str):
        if device_id in self.active_connections:
            websocket = self.active_connections[device_id]
            try:
                await websocket.send_json(message)
                logger.debug("Пакет доставлен устройству %s.", device_id)
            except Exception as e:
                logger.warning("Ошибка отправки %s: %s", device_id, e)
                self.disconnect(device_id)

    async def send_personal_binary(self, data: bytes, device_id: str):
        if device_id in self.active_connections:
            websocket = self.active_connections[device_id]
            try:
                await websocket.send_bytes(data)
            except Exception as e:
                logger.warning("Binary send error %s: %s", device_id, e)
                self.disconnect(device_id)


manager = ConnectionManager()


# ==========================================
# WEBSOCKET ЭНДПОИНТ (ДЛЯ КЛИЕНТОВ)
# ==========================================
@router.websocket("/ws/{device_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    device_id: str,
    token: str = Query(...)
):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        token_device_id = payload.get("device_id")
        if token_device_id != device_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    if not manager._is_device_valid_cached(device_id):
        async with AsyncSessionLocal() as db:
            stmt = select(models.Device).where(
                models.Device.id == device_id,
                models.Device.is_revoked == False
            )
            result = await db.execute(stmt)
            if not result.scalars().first():
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
        manager._cache_device(device_id)

    await manager.connect(websocket, device_id)
    logger.info("WS connected: %s", device_id)

    RELAY_TYPES = {
        "webrtc_signal",
        "call_offer",
        "call_accept",
        "call_ended",
        "screen_frame",
        "screen_control",
    }

    try:
        while True:
            message = await websocket.receive()

            if message["type"] == "websocket.disconnect":
                break

            if message.get("text") is not None:
                raw = message["text"]
                try:
                    data = json.loads(raw)
                except Exception as e:
                    logger.warning("Bad json from %s: %s", device_id, e)
                    continue

                msg_type = data.get("type")
                to_device_id = data.get("to_device_id")

                if msg_type in RELAY_TYPES and to_device_id:
                    data["from_device_id"] = device_id
                    logger.debug("RELAY %s: %s → %s", msg_type, device_id, to_device_id)
                    await manager.send_personal_message(data, to_device_id)
                else:
                    logger.debug("recv %s from %s", msg_type, device_id)

            elif message.get("bytes") is not None:
                raw_bytes = message["bytes"]
                try:
                    header_len = int.from_bytes(raw_bytes[:2], "big")
                    header_json = raw_bytes[2:2 + header_len].decode("utf-8")
                    header = json.loads(header_json)
                    to_device_id = header.get("to_device_id")
                    if to_device_id:
                        header["from_device_id"] = device_id
                        header_bytes = json.dumps(header).encode("utf-8")
                        new_header_len = len(header_bytes).to_bytes(2, "big")
                        relay_data = new_header_len + header_bytes + raw_bytes[2 + header_len:]
                        await manager.send_personal_binary(relay_data, to_device_id)
                except Exception as e:
                    logger.warning("Bad binary from %s: %s", device_id, e)

    except WebSocketDisconnect:
        logger.info("WS disconnect: %s", device_id)
        manager.disconnect(device_id)
    except Exception as e:
        logger.error("WS fatal for %s: %s", device_id, e, exc_info=True)
        manager.disconnect(device_id)

# ==========================================
# HTTP ЭНДПОИНТЫ
# ==========================================
async def get_current_device_id(token: HTTPAuthorizationCredentials = Depends(security_scheme)):
    try:
        payload = jwt.decode(token.credentials, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        device_id = payload.get("device_id")
        if not device_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return device_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.post("/send", response_model=schemas.MessageResponse)
async def send_message(
        msg_in: schemas.MessageSend,
        sender_device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db)
):
    """Принимает E2EE blob, сохраняет в БД и МГНОВЕННО пушит получателю по WS."""
    stmt = select(models.Device).where(
        models.Device.id == msg_in.receiver_device_id,
        models.Device.is_revoked == False
    )
    result = await db.execute(stmt)
    receiver = result.scalars().first()

    if not receiver:
        raise HTTPException(status_code=404, detail="Устройство получателя не найдено.")

    # 1. Сохраняем в БД
    new_msg = models.Message(
        sender_device_id=sender_device_id,
        receiver_device_id=msg_in.receiver_device_id,
        encrypted_blob=msg_in.encrypted_blob,
        signature=msg_in.signature
    )
    db.add(new_msg)
    await db.commit()
    await db.refresh(new_msg)

    # 2. ПУШИМ ПО WEBSOCKET ПОЛУЧАТЕЛЮ (Если он онлайн)
    ws_payload = {
        "type": "new_message",
        "message_id": new_msg.id,
        "sender_device_id": sender_device_id,
        "encrypted_blob": msg_in.encrypted_blob,
        "signature": msg_in.signature,
        "created_at": new_msg.created_at.isoformat()
    }
    # Вызываем асинхронную отправку в фоне
    await manager.send_personal_message(ws_payload, msg_in.receiver_device_id)

    return new_msg


@router.get("/sync", response_model=List[schemas.MessageResponse])
async def sync_messages(
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db)
):
    """Отдает устройству все его непрочитанные сообщения (если оно было оффлайн)."""
    stmt = select(models.Message).where(
        models.Message.receiver_device_id == device_id,
        models.Message.is_delivered == False
    ).order_by(models.Message.created_at.asc())

    result = await db.execute(stmt)
    messages = result.scalars().all()

    for m in messages:
        m.is_delivered = True

    await db.commit()
    return messages