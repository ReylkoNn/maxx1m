import asyncio
import hashlib
import logging
import re
import time
from contextlib import suppress
from datetime import datetime, timezone
from types import SimpleNamespace
from fastapi import APIRouter, Depends, HTTPException, Request, status, WebSocket, WebSocketDisconnect, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import and_, or_, update, delete, func, cast, LargeBinary, text
from sqlalchemy.future import select
from jose import jwt, JWTError
from typing import List, Dict

from .. import schemas, models, security
from ..database import get_db, AsyncSessionLocal
from ..config import settings
from ..rate_limit import limiter
from ..logging_security import safe_identifier_tag
import json

logger = logging.getLogger("max1m.messages")
router = APIRouter(prefix="/messages", tags=["Messages"])
security_scheme = HTTPBearer()
# Limits how long an idle WebSocket remains open after revocation or expiry.
WS_AUTH_CHECK_INTERVAL = 5.0
# Signaling is small; cap the application-level WebSocket payload as well as
# the server-level limit in run_server.py.
MAX_SIGNAL_BYTES = 128 * 1024
# Bound per-connection pending sends and time spent on a slow socket. Persistent
# messages remain in the database for sync when a live notification is dropped.
MAX_WS_PENDING_SENDS = 16
WS_SEND_TIMEOUT = 5.0
WS_CLOSE_TIMEOUT = 1.0
WS_RECV_MAX_BURST = 80
WS_RECV_REFILL_PER_SEC = 30.0
LAST_SEEN_TOUCH_INTERVAL_SECONDS = 300.0
MAX_RELAY_JSON_DEPTH = 16
_SAFE_WS_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ALLOWED_RELAY_FIELDS = frozenset({
    "type",
    "to_device_id",
    "encrypted_call",
    "call_signature",
    "payload",
    "call_id",
})


def _reject_non_finite_json(constant: str):
    raise ValueError(f"Unsupported JSON constant: {constant}")


def _json_depth_within_limit(obj, max_depth: int = MAX_RELAY_JSON_DEPTH) -> bool:
    stack = [(obj, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            return False
        if isinstance(current, dict):
            for k, v in current.items():
                if not isinstance(k, str) or len(k) > 128:
                    return False
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(current, list):
            for item in current:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))
    return True


def _validate_relay_frame(relayed: dict) -> bool:
    if not _json_depth_within_limit(relayed, MAX_RELAY_JSON_DEPTH):
        return False
    enc = relayed.get("encrypted_call")
    if enc is not None and (not isinstance(enc, str) or len(enc) > MAX_SIGNAL_BYTES):
        return False
    sig = relayed.get("call_signature")
    if sig is not None and (not isinstance(sig, str) or len(sig) > 1024):
        return False
    cid = relayed.get("call_id")
    if cid is not None and (not isinstance(cid, str) or len(cid) > 64):
        return False
    try:
        encoded = json.dumps(relayed, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        return False
    return len(encoded.encode("utf-8")) <= MAX_SIGNAL_BYTES + 256


# ==========================================
# МЕНЕДЖЕР WEBSOCKET ПОДКЛЮЧЕНИЙ
# ==========================================
class _SocketSendState:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.pending = 0


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self._send_states: Dict[WebSocket, _SocketSendState] = {}

    async def _close_bounded(self, websocket):
        with suppress(Exception):
            await asyncio.wait_for(websocket.close(code=status.WS_1008_POLICY_VIOLATION), WS_CLOSE_TIMEOUT)

    async def connect(self, websocket: WebSocket, device_id: str):
        await websocket.accept()
        previous = self.active_connections.get(device_id)
        self.active_connections[device_id] = websocket
        self._send_states[websocket] = _SocketSendState()
        if previous is not None and previous is not websocket:
            self._send_states.pop(previous, None)
            await self._close_bounded(previous)
        logger.info("ws.device.connected device_tag=%s", safe_identifier_tag(device_id))

    def disconnect(self, device_id: str):
        websocket = self.active_connections.pop(device_id, None)
        if websocket is not None:
            self._send_states.pop(websocket, None)
            logger.info("ws.device.disconnected device_tag=%s", safe_identifier_tag(device_id))

    async def close_device(self, device_id: str):
        websocket = self.active_connections.pop(device_id, None)
        if websocket is not None:
            self._send_states.pop(websocket, None)
            await self._close_bounded(websocket)
            logger.info("ws.device.revoked_connection_closed device_tag=%s", safe_identifier_tag(device_id))

    async def _send(self, data, device_id, *, binary=False):
        websocket = self.active_connections.get(device_id)
        state = self._send_states.get(websocket)
        if websocket is None or state is None or state.pending >= MAX_WS_PENDING_SENDS:
            return False
        # No await between the count check and increment: this is per event loop.
        state.pending += 1
        acquired = False
        try:
            try:
                async with asyncio.timeout(WS_SEND_TIMEOUT):
                    await state.lock.acquire()
                    acquired = True
            except asyncio.TimeoutError:
                return False
            if self.active_connections.get(device_id) is not websocket:
                return False
            operation = websocket.send_bytes(data) if binary else websocket.send_json(data)
            try:
                await asyncio.wait_for(operation, WS_SEND_TIMEOUT)
            except asyncio.CancelledError:
                # A cancelled send may have partially written a frame. Do not
                # reuse that socket for subsequent notifications.
                if self.active_connections.get(device_id) is websocket:
                    self.disconnect(device_id)
                    await self._close_bounded(websocket)
                raise
            except Exception as exc:
                logger.warning("ws.send.failed device_tag=%s error_type=%s",
                               safe_identifier_tag(device_id), type(exc).__name__)
                if self.active_connections.get(device_id) is websocket:
                    self.disconnect(device_id)
                    await self._close_bounded(websocket)
                return False
            return True
        finally:
            if acquired:
                state.lock.release()
            state.pending -= 1

    async def send_personal_message(self, message: dict, device_id: str):
        return await self._send(message, device_id)

    async def send_personal_binary(self, data: bytes, device_id: str):
        return await self._send(data, device_id, binary=True)


manager = ConnectionManager()


# ==========================================
# WEBSOCKET ЭНДПОИНТ (ДЛЯ КЛИЕНТОВ)
# ==========================================
@router.websocket("/ws/{device_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    device_id: str,
    token: str | None = Query(default=None)
):
    # Updated clients authenticate in the header to keep tokens out of URLs.
    # Query tokens remain temporarily supported for legacy clients unless disabled.
    authorization = websocket.headers.get("authorization")
    device_tag = safe_identifier_tag(device_id)
    if authorization is not None:
        scheme, separator, credentials = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not credentials.strip():
            logger.warning("ws.auth.rejected reason=malformed_authorization device_tag=%s", device_tag)
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        token = credentials.strip()
    elif token is not None and not settings.ALLOW_LEGACY_WS_QUERY_TOKEN:
        logger.warning("ws.auth.rejected reason=legacy_query_token_disabled device_tag=%s", device_tag)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    if not token:
        logger.warning("ws.auth.rejected reason=missing_token device_tag=%s", device_tag)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    try:
        payload = security.decode_access_token(token)
        user_id = payload.get("sub")
        token_sv = _parse_session_version(payload)
        if (payload.get("device_id") != device_id or not isinstance(user_id, str)
                or not user_id or not isinstance(payload.get("exp"), (int, float))
                or token_sv is None):
            logger.warning("ws.auth.rejected reason=invalid_claims device_tag=%s", device_tag)
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except JWTError as exc:
        logger.warning("ws.auth.rejected reason=invalid_token error_type=%s device_tag=%s",
                       type(exc).__name__, device_tag)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Do not cache authorisation: a newly revoked device or invalidated session must not reconnect.
    try:
        async with AsyncSessionLocal() as db:
            if not await _device_is_authorized(db, device_id, user_id, token_sv):
                logger.warning("ws.auth.rejected reason=device_or_session_unavailable device_tag=%s", device_tag)
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
            await _touch_device_last_seen_throttled(db, device_id)
    except Exception as exc:
        logger.error("ws.auth.failed stage=database_check error_type=%s device_tag=%s",
                     type(exc).__name__, device_tag)
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return

    await manager.connect(websocket, device_id)
    logger.info("ws.connected device_tag=%s", device_tag)

    async def revalidate_connection():
        while True:
            await asyncio.sleep(WS_AUTH_CHECK_INTERVAL)
            try:
                cur_payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
                cur_sv = _parse_session_version(cur_payload)
                async with AsyncSessionLocal() as db:
                    authorized = (
                        cur_sv is not None
                        and await _device_is_authorized(db, device_id, user_id, cur_sv)
                    )
                if authorized:
                    continue
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Fail closed if the token expires or authorization cannot be checked.
                logger.warning("ws.auth.revalidation_failed error_type=%s device_tag=%s",
                               type(exc).__name__, device_tag)
            logger.warning("ws.auth.rejected reason=expired_revoked_or_unavailable device_tag=%s", device_tag)
            if manager.active_connections.get(device_id) is websocket:
                manager.disconnect(device_id)
            with suppress(Exception):
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    auth_task = asyncio.create_task(revalidate_connection())

    RELAY_TYPES = {
        "webrtc_signal",
        "call_offer",
        "call_accept",
        "call_ended",
    }
    recv_tokens = float(WS_RECV_MAX_BURST)
    last_recv_ts = time.monotonic()

    try:
        while True:
            message = await websocket.receive()

            if manager.active_connections.get(device_id) is not websocket:
                break
            if message["type"] == "websocket.disconnect":
                break

            if message.get("text") is not None:
                now_mono = time.monotonic()
                recv_tokens = min(
                    float(WS_RECV_MAX_BURST),
                    recv_tokens + max(0.0, now_mono - last_recv_ts) * WS_RECV_REFILL_PER_SEC,
                )
                last_recv_ts = now_mono
                if recv_tokens < 1.0:
                    logger.warning("ws.receive.rejected reason=rate_limit device_tag=%s", device_tag)
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    break
                recv_tokens -= 1.0

                raw = message["text"]
                if len(raw) > MAX_SIGNAL_BYTES or len(raw.encode("utf-8")) > MAX_SIGNAL_BYTES:
                    await websocket.close(code=1009)
                    break
                try:
                    data = json.loads(raw, parse_constant=_reject_non_finite_json)
                except Exception as e:
                    logger.warning("ws.receive.rejected reason=invalid_json error_type=%s device_tag=%s",
                                   type(e).__name__, device_tag)
                    continue

                if not isinstance(data, dict):
                    continue
                msg_type = data.get("type")
                to_device_id = data.get("to_device_id")

                if (isinstance(msg_type, str) and msg_type in RELAY_TYPES
                        and isinstance(to_device_id, str)
                        and _SAFE_WS_DEVICE_ID_RE.fullmatch(to_device_id)):
                    relayed = {k: v for k, v in data.items() if k in ALLOWED_RELAY_FIELDS}
                    relayed["from_device_id"] = device_id
                    if not _validate_relay_frame(relayed):
                        logger.warning("ws.relay.rejected reason=invalid_payload device_tag=%s", device_tag)
                        continue
                    logger.debug("ws.relay.forwarded event_type=%s sender_tag=%s recipient_tag=%s",
                                 msg_type, device_tag, safe_identifier_tag(to_device_id))
                    await manager.send_personal_message(relayed, to_device_id)
                else:
                    logger.debug("ws.frame.ignored reason=unrecognized_type device_tag=%s", device_tag)

            elif message.get("bytes") is not None:
                # Binary relay is unsupported; close rather than accepting an
                # unbounded stream of legacy unencrypted screen frames.
                await websocket.close(code=1008)
                break

    except WebSocketDisconnect:
        logger.info("ws.disconnected device_tag=%s", device_tag)
    except Exception as exc:
        # Exception strings may include peer-controlled content or credentials.
        logger.error("ws.failed error_type=%s device_tag=%s", type(exc).__name__, device_tag)
    finally:
        auth_task.cancel()
        with suppress(asyncio.CancelledError):
            await auth_task
        # An old connection must not remove a newer one for the same device.
        if manager.active_connections.get(device_id) is websocket:
            manager.disconnect(device_id)
            with suppress(Exception):
                from app.api.calls import device_in_any_voice_room, evict_device_from_all_voice_rooms
                if device_in_any_voice_room(device_id):
                    async with AsyncSessionLocal() as _evict_db:
                        await evict_device_from_all_voice_rooms(device_id, _evict_db)
                        await _evict_db.rollback()

# ==========================================
# HTTP ЭНДПОИНТЫ
# ==========================================
def _parse_session_version(payload: dict) -> int | None:
    sv = payload.get("sv", 0)
    if isinstance(sv, bool) or not isinstance(sv, int) or sv < 0:
        return None
    return sv


async def _touch_device_last_seen_throttled(db: AsyncSession, device_id: str) -> None:
    """Update Device.last_seen only when stale and coarsened so reconnects neither contend on SQLite nor leak exact activity seconds."""
    try:
        granularity = int(getattr(settings, "LAST_SEEN_GRANULARITY_SECONDS", 3600))
        if granularity <= 0:
            return
        row = (await db.execute(
            select(models.Device.last_seen, models.Device.created_at).where(models.Device.id == device_id)
        )).first()
        await db.rollback()
        if row is None:
            return
        current, created_at = row[0], row[1]
        now_utc = datetime.now(timezone.utc)
        last_utc = _as_utc(current)
        min_interval = max(LAST_SEEN_TOUCH_INTERVAL_SECONDS, granularity)
        if last_utc is not None and (now_utc - last_utc).total_seconds() < min_interval:
            return
        coarsened = security.coarsen_device_last_seen(now_utc, floor_dt=created_at)
        if coarsened is None or (last_utc is not None and coarsened <= last_utc):
            return
        await db.execute(
            update(models.Device)
            .where(models.Device.id == device_id)
            .values(last_seen=coarsened)
            .execution_options(synchronize_session=False)
        )
        await db.commit()
    except Exception:
        await db.rollback()


async def _device_is_authorized(
    db: AsyncSession,
    device_id: str,
    user_id: str,
    token_session_version: int = 0,
) -> bool:
    result = await db.execute(
        select(models.Device.id)
        .join(models.User, models.Device.user_id == models.User.id)
        .where(
            models.Device.id == device_id,
            models.Device.user_id == user_id,
            models.Device.is_revoked == False,
            models.User.is_active == True,
            func.coalesce(models.Device.session_version, 0) == token_session_version,
        )
    )
    return result.scalar_one_or_none() is not None


async def get_current_device_id(
    token: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
):
    """Validate both the token and the current account/device/session state on every request."""
    try:
        payload = security.decode_access_token(token.credentials)
        device_id = payload.get("device_id")
        user_id = payload.get("sub")
        token_sv = _parse_session_version(payload)
        if (not isinstance(device_id, str) or not device_id or not isinstance(user_id, str)
                or not user_id or not isinstance(payload.get("exp"), (int, float))
                or token_sv is None):
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not await _device_is_authorized(db, device_id, user_id, token_sv):
        raise HTTPException(status_code=401, detail="Invalid token")
    return device_id


async def _check_pending_capacity(db, sender_device_id: str, msg_in: schemas.MessageSend):
    """Called inside a SQLite BEGIN IMMEDIATE transaction, before insertion."""
    if min(settings.MAX_PENDING_PER_DEVICE, settings.MAX_PENDING_PER_SENDER,
           settings.MAX_PENDING_BYTES_PER_DEVICE, settings.MAX_MESSAGE_PAYLOAD_BYTES) < 1:
        raise HTTPException(503, "Invalid queue limit configuration")
    try:
        byte_count = len(msg_in.encrypted_blob.encode('utf-8')) + len(msg_in.signature.encode('utf-8'))
    except UnicodeEncodeError:
        raise HTTPException(422, "Invalid message encoding")
    if byte_count > settings.MAX_MESSAGE_PAYLOAD_BYTES:
        raise HTTPException(413, "Message payload too large")
    recipient = (await db.execute(select(models.Device.id).join(models.User).where(
        models.Device.id == msg_in.receiver_device_id, models.Device.is_revoked == False,
        models.User.is_active == True))).scalar_one_or_none()
    if recipient is None:
        raise HTTPException(404, "Устройство получателя недоступно")
    pending = (models.Message.receiver_device_id == msg_in.receiver_device_id,
               models.Message.is_delivered == False)
    size_expr = (func.length(cast(models.Message.encrypted_blob, LargeBinary))
                 + func.length(cast(models.Message.signature, LargeBinary)))
    total_count, total_bytes = (await db.execute(select(func.count(), func.coalesce(func.sum(size_expr), 0))
        .where(*pending))).one()
    sender_count = (await db.execute(select(func.count()).select_from(models.Message)
        .where(*pending, models.Message.sender_device_id == sender_device_id))).scalar_one()
    if (total_count >= settings.MAX_PENDING_PER_DEVICE
            or sender_count >= settings.MAX_PENDING_PER_SENDER
            or total_bytes + byte_count > settings.MAX_PENDING_BYTES_PER_DEVICE):
        raise HTTPException(429, "Очередь получателя заполнена; повторите позже")


def _envelope_sha256(encrypted_blob: str, signature: str) -> str:
    blob_bytes = encrypted_blob.encode("utf-8")
    sig_bytes = signature.encode("utf-8")
    digest = hashlib.sha256()
    digest.update(f"{len(blob_bytes)}:".encode("ascii"))
    digest.update(blob_bytes)
    digest.update(b":")
    digest.update(sig_bytes)
    return digest.hexdigest()


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


async def _create_message(db: AsyncSession, sender_device_id: str,
                          msg_in: schemas.MessageSend, message_id: str | None = None):
    # SQLite's reserved writer lock serializes the quota check with all message
    # insertions and ACKs, including concurrent requests in separate processes.
    try:
        await db.execute(text("BEGIN IMMEDIATE"))
        sender = (await db.execute(
            select(models.User.id, models.User.username)
            .select_from(models.Device)
            .join(models.User, models.User.id == models.Device.user_id)
            .where(models.Device.id == sender_device_id, models.Device.is_revoked == False,
                   models.User.is_active == True)
        )).one_or_none()
        if sender is None:
            raise HTTPException(401, "Sender device is unavailable")
        sender_user_id, sender_username = sender
        if message_id:
            existing = await db.get(models.Message, message_id)
            if existing:
                if (existing.sender_device_id != sender_device_id
                        or existing.receiver_device_id != msg_in.receiver_device_id
                        or existing.encrypted_blob != msg_in.encrypted_blob
                        or existing.signature != msg_in.signature):
                    raise HTTPException(409, "Message identifier conflict")
                # An idempotent retry must work even when the queue is full.
                existing.sender_user_id = sender_user_id
                existing.sender_username = sender_username
                await db.commit()
                return existing, False
            tombstone = await db.get(models.MessageIdempotencyRecord, message_id)
            if tombstone is not None:
                try:
                    incoming_hash = _envelope_sha256(msg_in.encrypted_blob, msg_in.signature)
                except UnicodeEncodeError:
                    raise HTTPException(422, "Invalid message encoding")
                if (tombstone.sender_device_id != sender_device_id
                        or tombstone.receiver_device_id != msg_in.receiver_device_id
                        or tombstone.payload_sha256 != incoming_hash):
                    raise HTTPException(409, "Message identifier conflict")
                await db.commit()
                echo = SimpleNamespace(
                    id=message_id,
                    sender_device_id=sender_device_id,
                    sender_user_id=sender_user_id,
                    sender_username=sender_username,
                    receiver_device_id=msg_in.receiver_device_id,
                    encrypted_blob=msg_in.encrypted_blob,
                    signature=msg_in.signature,
                    created_at=tombstone.original_created_at,
                )
                return echo, False
        await _check_pending_capacity(db, sender_device_id, msg_in)
        values = dict(sender_device_id=sender_device_id, receiver_device_id=msg_in.receiver_device_id,
                      encrypted_blob=msg_in.encrypted_blob, signature=msg_in.signature)
        if message_id:
            values['id'] = message_id
        message = models.Message(**values)
        db.add(message)
        await db.commit()
        await db.refresh(message)
        message.sender_user_id = sender_user_id
        message.sender_username = sender_username
        return message, True
    except Exception:
        await db.rollback()
        raise


async def _attach_sender_directory_metadata(db: AsyncSession, messages: list):
    """Attach server-resolved sender ownership as an untrusted directory hint."""
    sender_ids = {
        message.sender_device_id for message in messages
        if isinstance(getattr(message, "sender_device_id", None), str)
    }
    if not sender_ids:
        return messages
    rows = await db.execute(
        select(models.Device.id, models.User.id, models.User.username)
        .select_from(models.Device)
        .join(models.User, models.User.id == models.Device.user_id)
        .where(models.Device.id.in_(sender_ids))
    )
    owners = {device_id: (user_id, username) for device_id, user_id, username in rows.all()}
    for message in messages:
        owner = owners.get(getattr(message, "sender_device_id", None))
        message.sender_user_id = owner[0] if owner else None
        message.sender_username = owner[1] if owner else None
    return messages


async def _notify_message(message):
    # `id` is the canonical sync-safe delivery ID. Keep `message_id` as an alias
    # for clients that consumed the original WebSocket event shape.
    sent = await manager.send_personal_message({
        "type": "new_message",
        "id": message.id,
        "message_id": message.id,
        "sender_device_id": message.sender_device_id,
        "sender_user_id": getattr(message, "sender_user_id", None),
        "sender_username": getattr(message, "sender_username", None),
        "encrypted_blob": message.encrypted_blob,
        "signature": message.signature, "created_at": message.created_at.isoformat(),
    }, message.receiver_device_id)
    logger.info(
        "message.live_notification.result status=%s delivery_tag=%s sender_tag=%s recipient_tag=%s",
        "sent" if sent else "pending_sync",
        safe_identifier_tag(message.id),
        safe_identifier_tag(message.sender_device_id),
        safe_identifier_tag(message.receiver_device_id),
    )


_SAFE_SEND_REJECTION_REASONS = {
    (401, "Sender device is unavailable"): "sender_device_unavailable",
    (404, "Устройство получателя недоступно"): "recipient_unavailable",
    (409, "Message identifier conflict"): "idempotency_conflict",
    (413, "Message payload too large"): "payload_too_large",
    (422, "Invalid message encoding"): "invalid_message_encoding",
    (429, "Очередь получателя заполнена; повторите позже"): "recipient_queue_full",
    (503, "Invalid queue limit configuration"): "server_queue_configuration",
}


def _safe_send_rejection_reason(exc: HTTPException) -> str:
    """Map known server responses to log-safe reasons; never echo exception detail."""
    detail = exc.detail if isinstance(exc.detail, str) else ""
    return _SAFE_SEND_REJECTION_REASONS.get((exc.status_code, detail), "server_policy")


@router.post("/send", response_model=schemas.MessageResponse)
@limiter.limit(lambda: settings.RATE_LIMIT_MESSAGE_SEND)
async def send_message(request: Request,
                       msg_in: schemas.MessageSend,
                       sender_device_id: str = Depends(get_current_device_id),
                       db: AsyncSession = Depends(get_db)):
    """Legacy non-idempotent send, with bounded pending queue."""
    sender_tag = safe_identifier_tag(sender_device_id)
    recipient_tag = safe_identifier_tag(msg_in.receiver_device_id)
    if not _SAFE_WS_DEVICE_ID_RE.fullmatch(msg_in.receiver_device_id):
        logger.warning("message.send.rejected status=404 reason=invalid_recipient_id sender_tag=%s recipient_tag=%s",
                       sender_tag, recipient_tag)
        raise HTTPException(status_code=404, detail="Устройство получателя недоступно")
    try:
        message, _ = await _create_message(db, sender_device_id, msg_in)
    except HTTPException as exc:
        logger.warning("message.send.rejected status=%d reason=%s sender_tag=%s recipient_tag=%s",
                       exc.status_code, _safe_send_rejection_reason(exc), sender_tag, recipient_tag)
        raise
    except Exception as exc:
        logger.error("message.send.failed stage=database error_type=%s sender_tag=%s recipient_tag=%s",
                     type(exc).__name__, sender_tag, recipient_tag)
        raise
    logger.info("message.send.accepted mode=legacy delivery_tag=%s sender_tag=%s recipient_tag=%s",
                safe_identifier_tag(message.id), sender_tag, recipient_tag)
    await _notify_message(message)
    return message


@router.post("/send-reliable", response_model=schemas.ReliableSendResponse)
@limiter.limit(lambda: settings.RATE_LIMIT_MESSAGE_SEND)
async def send_reliable_message(request: Request,
                                msg_in: schemas.ReliableMessageSend,
                                sender_device_id: str = Depends(get_current_device_id),
                                db: AsyncSession = Depends(get_db)):
    """Retry identical ciphertext by UUID without allocating a second queue slot."""
    sender_tag = safe_identifier_tag(sender_device_id)
    recipient_tag = safe_identifier_tag(msg_in.receiver_device_id)
    client_tag = safe_identifier_tag(str(msg_in.client_message_id))
    if not _SAFE_WS_DEVICE_ID_RE.fullmatch(msg_in.receiver_device_id):
        logger.warning("message.send.rejected mode=reliable status=404 reason=invalid_recipient_id client_tag=%s sender_tag=%s recipient_tag=%s",
                       client_tag, sender_tag, recipient_tag)
        raise HTTPException(status_code=404, detail="Устройство получателя недоступно")
    try:
        message, inserted = await _create_message(db, sender_device_id, msg_in, str(msg_in.client_message_id))
    except HTTPException as exc:
        logger.warning("message.send.rejected mode=reliable status=%d reason=%s client_tag=%s sender_tag=%s recipient_tag=%s",
                       exc.status_code, _safe_send_rejection_reason(exc), client_tag, sender_tag, recipient_tag)
        raise
    except Exception as exc:
        logger.error("message.send.failed mode=reliable stage=database error_type=%s client_tag=%s sender_tag=%s recipient_tag=%s",
                     type(exc).__name__, client_tag, sender_tag, recipient_tag)
        raise
    logger.info("message.send.accepted mode=reliable result=%s delivery_tag=%s sender_tag=%s recipient_tag=%s",
                "inserted" if inserted else "idempotent_retry",
                safe_identifier_tag(message.id), sender_tag, recipient_tag)
    if inserted:
        await _notify_message(message)
    return message


@router.get("/sync", response_model=List[schemas.MessageResponse])
@limiter.limit(lambda: settings.RATE_LIMIT_MESSAGE_SYNC)
async def sync_messages(
        request: Request,
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db)
):
    """Destructive legacy sync is opt-in only; prefer sync-safe plus ACK."""
    if not settings.ALLOW_DESTRUCTIVE_LEGACY_SYNC:
        raise HTTPException(503, "Обновите клиент: небезопасная синхронизация отключена")
    stmt = select(models.Message).where(
        models.Message.receiver_device_id == device_id,
        models.Message.is_delivered == False
    ).order_by(models.Message.created_at.asc())

    result = await db.execute(stmt)
    messages = result.scalars().all()

    now = datetime.now(timezone.utc)
    for m in messages:
        m.is_delivered = True
        if m.delivered_at is None:
            m.delivered_at = now

    await db.commit()
    return await _attach_sender_directory_metadata(db, messages)

@router.get("/sync-safe", response_model=List[schemas.MessageResponse])
@limiter.limit(lambda: settings.RATE_LIMIT_MESSAGE_SYNC)
async def sync_messages_safe(
        request: Request,
        after: str | None = Query(default=None, max_length=64),
        limit: int = Query(default=100, ge=1, le=100),
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db),
):
    """Return a bounded page without marking it delivered.

    The cursor is a message ID belonging to this device; acknowledged rows (or
    their compact idempotency tombstones) keep the cursor valid across pages.
    """
    device_tag = safe_identifier_tag(device_id)
    after_tag = safe_identifier_tag(after)
    if after is not None and not _SAFE_WS_DEVICE_ID_RE.fullmatch(after):
        logger.warning("message.sync.rejected reason=invalid_cursor device_tag=%s after_tag=%s",
                       device_tag, after_tag)
        raise HTTPException(status_code=400, detail="Invalid cursor")
    stmt = select(models.Message).where(
        models.Message.receiver_device_id == device_id,
        models.Message.is_delivered == False,
    )
    if after:
        result = await db.execute(select(models.Message).where(
            models.Message.id == after, models.Message.receiver_device_id == device_id,
        ))
        cursor = result.scalars().first()
        if cursor is not None:
            cursor_created_at = cursor.created_at
            cursor_id = cursor.id
        else:
            tombstone = await db.get(models.MessageIdempotencyRecord, after)
            if tombstone is None or tombstone.receiver_device_id != device_id:
                logger.warning("message.sync.rejected reason=cursor_not_found device_tag=%s after_tag=%s",
                               device_tag, after_tag)
                raise HTTPException(status_code=400, detail="Invalid cursor")
            cursor_created_at = tombstone.original_created_at
            cursor_id = tombstone.message_id
        stmt = stmt.where(or_(
            models.Message.created_at > cursor_created_at,
            and_(models.Message.created_at == cursor_created_at, models.Message.id > cursor_id),
        ))
    result = await db.execute(stmt.order_by(models.Message.created_at, models.Message.id).limit(limit))
    messages = result.scalars().all()
    messages = await _attach_sender_directory_metadata(db, messages)
    delivery_tags = ",".join(safe_identifier_tag(message.id) for message in messages)
    logger.info(
        "message.sync.completed device_tag=%s after_tag=%s count=%d limit=%d has_more=%s delivery_tags=%s",
        device_tag, after_tag, len(messages), limit, len(messages) == limit, delivery_tags or "-",
    )
    return messages


@router.post("/ack")
@limiter.limit(lambda: settings.RATE_LIMIT_MESSAGE_SYNC)
async def acknowledge_messages(
        request: Request,
        ack: schemas.MessageDeliveryAck,
        device_id: str = Depends(get_current_device_id),
        db: AsyncSession = Depends(get_db),
):
    """Idempotently acknowledge only messages addressed to this device."""
    device_tag = safe_identifier_tag(device_id)
    delivery_tags = ",".join(safe_identifier_tag(message_id) for message_id in ack.message_ids)
    logger.info("message.ack.started device_tag=%s requested=%d delivery_tags=%s",
                device_tag, len(ack.message_ids), delivery_tags or "-")
    # Authentication runs before the endpoint, so revocation could otherwise
    # race it and mark messages delivered after a device has been disabled.
    try:
        await db.execute(text("BEGIN IMMEDIATE"))
        authorized = (await db.execute(select(models.Device.id).join(models.User).where(
            models.Device.id == device_id, models.Device.is_revoked == False,
            models.User.is_active == True))).scalar_one_or_none()
        if authorized is None:
            raise HTTPException(401, "Device unavailable")
        now = datetime.now(timezone.utc)
        update_result = await db.execute(
            update(models.Message)
            .where(models.Message.receiver_device_id == device_id, models.Message.id.in_(ack.message_ids))
            .values(
                is_delivered=True,
                delivered_at=func.coalesce(models.Message.delivered_at, now),
            )
        )
        affected = getattr(update_result, "rowcount", None)
        await db.commit()
        logger.info("message.ack.completed device_tag=%s requested=%d affected=%s delivery_tags=%s",
                    device_tag, len(ack.message_ids), affected if affected is not None else "unknown",
                    delivery_tags or "-")
        return {"status": "ok"}
    except BaseException as exc:
        await db.rollback()
        logger.warning("message.ack.failed error_type=%s device_tag=%s requested=%d",
                       type(exc).__name__, device_tag, len(ack.message_ids))
        raise


async def compact_delivered_messages(
        db: AsyncSession,
        retention_seconds: float | None = None,
        tombstone_ttl_seconds: float | None = None,
        batch_size: int = 500,
) -> dict:
    """Prune acknowledged personal message ciphertexts into compact SHA-256 tombstones.

    Never touches undelivered messages (is_delivered == False). Preserves both
    /messages/send-reliable idempotency/conflict detection and /messages/sync-safe
    cursors until tombstones themselves expire after IDEMPOTENCY_TOMBSTONE_TTL_SECONDS.
    """
    summary = {"compacted": 0, "expired_tombstones": 0}
    if retention_seconds is None:
        if settings.DELIVERED_MESSAGE_RETENTION_SECONDS <= 0:
            return summary
        ret_sec = float(settings.DELIVERED_MESSAGE_RETENTION_SECONDS)
    else:
        if float(retention_seconds) < 0:
            return summary
        ret_sec = float(retention_seconds)

    tomb_ttl = (
        float(settings.IDEMPOTENCY_TOMBSTONE_TTL_SECONDS)
        if tombstone_ttl_seconds is None
        else float(tombstone_ttl_seconds)
    )

    # Read-only pre-check avoids taking a SQLite writer lock or issuing an empty
    # commit when no rows have reached the compaction horizon.
    oldest_delivered = (await db.execute(
        select(models.Message.delivered_at, models.Message.created_at)
        .where(models.Message.is_delivered == True)
        .order_by(func.coalesce(models.Message.delivered_at, models.Message.created_at).asc())
        .limit(1)
    )).first()
    oldest_tomb = (await db.execute(
        select(models.MessageIdempotencyRecord.compacted_at)
        .order_by(models.MessageIdempotencyRecord.compacted_at.asc())
        .limit(1)
    )).scalar_one_or_none()
    await db.rollback()

    now_utc = datetime.now(timezone.utc)
    has_eligible_msg = False
    if oldest_delivered is not None:
        ref_dt = _as_utc(oldest_delivered[0] or oldest_delivered[1])
        if ref_dt is not None and (now_utc - ref_dt).total_seconds() >= ret_sec:
            has_eligible_msg = True

    has_eligible_tomb = False
    if tomb_ttl >= 0 and oldest_tomb is not None:
        tomb_dt = _as_utc(oldest_tomb)
        if tomb_dt is not None and (now_utc - tomb_dt).total_seconds() >= tomb_ttl:
            has_eligible_tomb = True

    if not has_eligible_msg and not has_eligible_tomb:
        return summary

    await db.execute(text("BEGIN IMMEDIATE"))
    try:
        now_utc = datetime.now(timezone.utc)
        candidates = (await db.execute(
            select(models.Message)
            .where(models.Message.is_delivered == True)
            .order_by(func.coalesce(models.Message.delivered_at, models.Message.created_at).asc())
            .limit(max(1, int(batch_size)))
        )).scalars().all()

        for msg in candidates:
            ref_dt = _as_utc(msg.delivered_at or msg.created_at)
            if ref_dt is None or (now_utc - ref_dt).total_seconds() < ret_sec:
                continue
            existing_tomb = await db.get(models.MessageIdempotencyRecord, msg.id)
            if existing_tomb is None and len(msg.id) <= 64:
                db.add(models.MessageIdempotencyRecord(
                    message_id=msg.id,
                    sender_device_id=msg.sender_device_id,
                    receiver_device_id=msg.receiver_device_id,
                    payload_sha256=_envelope_sha256(msg.encrypted_blob, msg.signature),
                    original_created_at=msg.created_at,
                    compacted_at=now_utc,
                ))
            await db.delete(msg)
            summary["compacted"] += 1

        if tomb_ttl >= 0:
            tomb_candidates = (await db.execute(
                select(models.MessageIdempotencyRecord)
                .order_by(models.MessageIdempotencyRecord.compacted_at.asc())
                .limit(max(1, int(batch_size)))
            )).scalars().all()
            for tomb in tomb_candidates:
                tomb_dt = _as_utc(tomb.compacted_at)
                if tomb_dt is not None and (now_utc - tomb_dt).total_seconds() >= tomb_ttl:
                    await db.delete(tomb)
                    summary["expired_tombstones"] += 1

        if summary["compacted"] or summary["expired_tombstones"]:
            await db.commit()
        else:
            await db.rollback()
        return summary
    except BaseException:
        await db.rollback()
        raise
