"""
Autonomous WebRTC ICE/TURN configuration (ephemeral coturn HMAC-SHA1 credentials
including TURNS over TCP/TLS 443 for VPN-free operation in RU) and RAM-only
Discord-style Group Voice & Screen-Share Rooms (2-8 participants, E2EE signaling).
"""

import asyncio
import base64
import hashlib
import hmac
import re
import time
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import models
from app.api.messages import get_current_device_id
from app.config import settings
from app.database import get_db

router = APIRouter(prefix="/calls", tags=["calls"])

_STUN_URI_RE = re.compile(r"^stun:(?P<host>[A-Za-z0-9._-]+)(?::(?P<port>[0-9]{1,5}))?$")
_TURN_URI_RE = re.compile(
    r"^(?P<scheme>turn|turns):(?P<host>[A-Za-z0-9._-]+)(?::(?P<port>[0-9]{1,5}))?"
    r"(?:\?transport=(?P<transport>udp|tcp))?$"
)

MAX_SIGNAL_CIPHERTEXT_CHARS = 128 * 1024
MAX_SIGNAL_SIGNATURE_CHARS = 512
VOICE_ROOM_STALE_SECONDS = 120.0

# Strictly RAM-only volatile presence (never persisted to SQLite — anti-seizure safe).
# group_id -> { device_id: {"joined_at": float, "updated_at": float, "is_muted": bool, "is_deafened": bool, "is_sharing_screen": bool} }
_VOICE_ROOMS: Dict[str, Dict[str, dict]] = {}
_VOICE_LOCK = asyncio.Lock()


def _valid_port(port_str: str | None) -> bool:
    if port_str is None:
        return True
    port = int(port_str)
    return 1 <= port <= 65535


def _parse_stun_urls(raw: str) -> List[str]:
    urls: List[str] = []
    for item in (raw or "").split(","):
        uri = item.strip()
        if not uri:
            continue
        m = _STUN_URI_RE.fullmatch(uri) if "@" not in uri else None
        if not m or not _valid_port(m.group("port")):
            raise HTTPException(status_code=500, detail="Invalid server STUN configuration")
        urls.append(uri)
    return urls


def _parse_turn_urls(raw: str) -> List[str]:
    urls: List[str] = []
    for item in (raw or "").split(","):
        uri = item.strip()
        if not uri:
            continue
        m = _TURN_URI_RE.fullmatch(uri) if "@" not in uri else None
        if not m or not _valid_port(m.group("port")):
            raise HTTPException(status_code=500, detail="Invalid server TURN configuration")
        if m.group("scheme") == "turns" and m.group("transport") not in (None, "tcp"):
            raise HTTPException(status_code=500, detail="Invalid server TURNS transport")
        urls.append(uri)
    return urls


def generate_coturn_ephemeral_credentials(
    device_id: str,
    shared_secret: str,
    ttl_seconds: int = 3600,
    now_ts: int | None = None,
) -> tuple[str, str, int]:
    """
    Generate RFC-draft coturn REST API ephemeral credentials (`use-auth-secret`):
      username = "<unix_expiry>:<device_id>"
      credential = base64(HMAC-SHA1(shared_secret, username))
    """
    now_int = int(time.time()) if now_ts is None else int(now_ts)
    bounded_ttl = max(120, min(86400, int(ttl_seconds)))
    expires_at = now_int + bounded_ttl
    turn_username = f"{expires_at}:{device_id}"
    digest = hmac.new(
        shared_secret.encode("utf-8"),
        turn_username.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    turn_credential = base64.b64encode(digest).decode("ascii")
    return turn_username, turn_credential, expires_at


@router.get("/ice-config")
async def get_ice_config(
    device_id: str = Depends(get_current_device_id),
):
    stun_urls = _parse_stun_urls(settings.CALL_STUN_URLS)
    turn_urls = _parse_turn_urls(settings.CALL_TURN_URLS)
    shared_secret = (settings.CALL_TURN_SHARED_SECRET or "").strip()

    ice_servers: List[dict] = [{"urls": [u]} for u in stun_urls]
    turn_configured = False
    has_turns_443 = False
    expires_at = None
    ttl_seconds = max(120, min(86400, int(settings.CALL_TURN_CREDENTIAL_TTL_SECONDS)))

    if turn_urls and shared_secret:
        turn_user, turn_cred, expires_at = generate_coturn_ephemeral_credentials(
            device_id=device_id,
            shared_secret=shared_secret,
            ttl_seconds=ttl_seconds,
        )
        ice_servers.append(
            {
                "urls": turn_urls,
                "username": turn_user,
                "credential": turn_cred,
            }
        )
        turn_configured = True
        has_turns_443 = any(
            u.startswith("turns:") and (":443" in u or "?transport=tcp" in u)
            for u in turn_urls
        )

    return {
        "ice_servers": ice_servers,
        "turn_configured": turn_configured,
        "has_turns_443": has_turns_443,
        "ttl_seconds": ttl_seconds if turn_configured else None,
        "expires_at": expires_at,
        "relay_only_recommended": bool(settings.CALL_FORCE_RELAY_RECOMMENDED and turn_configured),
    }


# ═════════════════════════════════════════════════════════════════════════════
# DISCORD-GRADE GROUP VOICE & SCREEN-SHARE ROOMS (2–8 PARTICIPANTS, RAM-ONLY)
# ═════════════════════════════════════════════════════════════════════════════

class VoiceRoomStateUpdate(BaseModel):
    is_muted: bool = False
    is_deafened: bool = False
    is_sharing_screen: bool = False


class GroupVoiceSignalRequest(BaseModel):
    target_device_id: str = Field(..., min_length=1, max_length=128)
    channel: str = Field(default="voice", pattern=r"^(voice|screen)$")
    encrypted_blob: str = Field(..., min_length=1, max_length=MAX_SIGNAL_CIPHERTEXT_CHARS)
    signature: str = Field(..., min_length=1, max_length=MAX_SIGNAL_SIGNATURE_CHARS)


async def _fetch_active_group_devices(group_id: str, db: AsyncSession) -> Dict[str, dict]:
    """Return all currently valid (non-revoked, active user) member devices of `group_id`."""
    stmt = (
        select(
            models.Device.id,
            models.Device.public_key,
            models.Device.fingerprint,
            models.User.username,
        )
        .join(models.GroupMember, models.GroupMember.device_id == models.Device.id)
        .join(models.User, models.User.id == models.Device.user_id)
        .where(
            and_(
                models.GroupMember.group_id == group_id,
                models.Device.is_revoked.is_(False),
                models.User.is_active.is_(True),
            )
        )
    )
    rows = (await db.execute(stmt)).all()
    return {
        row[0]: {
            "device_id": row[0],
            "public_key": row[1],
            "fingerprint": row[2],
            "username": row[3],
        }
        for row in rows
    }


async def _require_group_member_device(
    group_id: str,
    device_id: str,
    db: AsyncSession,
) -> Dict[str, dict]:
    member_map = await _fetch_active_group_devices(group_id, db)
    if device_id not in member_map:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Не участник группы")
    return member_map


def _prune_and_serialize_room_locked(
    group_id: str,
    member_map: Dict[str, dict],
    now_mono: float | None = None,
) -> List[dict]:
    now_m = time.monotonic() if now_mono is None else now_mono
    room = _VOICE_ROOMS.get(group_id)
    if not room:
        return []
    stale_ids = [
        dev_id
        for dev_id, st in room.items()
        if dev_id not in member_map or (now_m - st["updated_at"]) > VOICE_ROOM_STALE_SECONDS
    ]
    for dev_id in stale_ids:
        room.pop(dev_id, None)
    if not room:
        _VOICE_ROOMS.pop(group_id, None)
        return []

    participants: List[dict] = []
    for dev_id, st in sorted(room.items(), key=lambda kv: (kv[1]["joined_at"], kv[0])):
        meta = member_map[dev_id]
        participants.append(
            {
                "device_id": dev_id,
                "username": meta["username"],
                "public_key": meta["public_key"],
                "fingerprint": meta["fingerprint"],
                "is_muted": bool(st.get("is_muted", False)),
                "is_deafened": bool(st.get("is_deafened", False)),
                "is_sharing_screen": bool(st.get("is_sharing_screen", False)),
            }
        )
    return participants


async def _broadcast_voice_room_state(
    group_id: str,
    member_device_ids: List[str],
    participants: List[dict],
) -> None:
    from app.api.messages import manager

    event = {
        "type": "group_voice_state",
        "group_id": group_id,
        "participants": participants,
        "max_peers": int(settings.MAX_GROUP_VOICE_PEERS),
    }
    for dev_id in member_device_ids:
        if dev_id in manager.active_connections:
            await manager.send_personal_message(event, dev_id)


def device_in_any_voice_room(device_id: str) -> bool:
    """Fast O(R) RAM check so ordinary WS disconnects never touch SQLite."""
    return any(device_id in room for room in _VOICE_ROOMS.values())


async def evict_device_from_all_voice_rooms(device_id: str, db: AsyncSession) -> None:
    """Automatically remove a disconnected device from any active group voice room."""
    affected_groups: List[str] = []
    async with _VOICE_LOCK:
        for gid, room in list(_VOICE_ROOMS.items()):
            if device_id in room:
                room.pop(device_id, None)
                affected_groups.append(gid)
                if not room:
                    _VOICE_ROOMS.pop(gid, None)

    for gid in affected_groups:
        member_map = await _fetch_active_group_devices(gid, db)
        async with _VOICE_LOCK:
            participants = _prune_and_serialize_room_locked(gid, member_map)
        await _broadcast_voice_room_state(gid, list(member_map.keys()), participants)


@router.get("/groups/{group_id}/voice/state")
async def get_group_voice_state(
    group_id: str,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    member_map = await _require_group_member_device(group_id, device_id, db)
    async with _VOICE_LOCK:
        if group_id in _VOICE_ROOMS and device_id in _VOICE_ROOMS[group_id]:
            _VOICE_ROOMS[group_id][device_id]["updated_at"] = time.monotonic()
        participants = _prune_and_serialize_room_locked(group_id, member_map)
    return {
        "group_id": group_id,
        "participants": participants,
        "max_peers": int(settings.MAX_GROUP_VOICE_PEERS),
    }


@router.post("/groups/{group_id}/voice/join")
async def join_group_voice_room(
    group_id: str,
    body: VoiceRoomStateUpdate | None = None,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    member_map = await _require_group_member_device(group_id, device_id, db)
    state_in = body or VoiceRoomStateUpdate()
    max_peers = max(2, min(16, int(settings.MAX_GROUP_VOICE_PEERS)))
    now_m = time.monotonic()

    async with _VOICE_LOCK:
        _prune_and_serialize_room_locked(group_id, member_map, now_m)
        room = _VOICE_ROOMS.setdefault(group_id, {})
        if device_id not in room and len(room) >= max_peers:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Голосовая комната заполнена (максимум {max_peers} участников)",
            )
        existing = room.get(device_id)
        room[device_id] = {
            "joined_at": existing["joined_at"] if existing else now_m,
            "updated_at": now_m,
            "is_muted": bool(state_in.is_muted),
            "is_deafened": bool(state_in.is_deafened),
            "is_sharing_screen": bool(state_in.is_sharing_screen),
        }
        participants = _prune_and_serialize_room_locked(group_id, member_map, now_m)

    await _broadcast_voice_room_state(group_id, list(member_map.keys()), participants)
    return {
        "group_id": group_id,
        "participants": participants,
        "max_peers": max_peers,
    }


@router.post("/groups/{group_id}/voice/state")
async def update_group_voice_state(
    group_id: str,
    body: VoiceRoomStateUpdate,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    member_map = await _require_group_member_device(group_id, device_id, db)
    now_m = time.monotonic()
    changed = False

    async with _VOICE_LOCK:
        room = _VOICE_ROOMS.get(group_id)
        if not room or device_id not in room:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Устройство не в голосовой комнате")
        cur = room[device_id]
        new_tuple = (bool(body.is_muted), bool(body.is_deafened), bool(body.is_sharing_screen))
        old_tuple = (bool(cur.get("is_muted")), bool(cur.get("is_deafened")), bool(cur.get("is_sharing_screen")))
        cur["updated_at"] = now_m
        cur["is_muted"] = new_tuple[0]
        cur["is_deafened"] = new_tuple[1]
        cur["is_sharing_screen"] = new_tuple[2]
        changed = new_tuple != old_tuple
        participants = _prune_and_serialize_room_locked(group_id, member_map, now_m)

    if changed:
        await _broadcast_voice_room_state(group_id, list(member_map.keys()), participants)
    return {
        "group_id": group_id,
        "participants": participants,
        "max_peers": int(settings.MAX_GROUP_VOICE_PEERS),
    }


@router.post("/groups/{group_id}/voice/leave")
async def leave_group_voice_room(
    group_id: str,
    device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    member_map = await _fetch_active_group_devices(group_id, db)
    removed = False
    async with _VOICE_LOCK:
        room = _VOICE_ROOMS.get(group_id)
        if room and device_id in room:
            room.pop(device_id, None)
            removed = True
            if not room:
                _VOICE_ROOMS.pop(group_id, None)
        participants = _prune_and_serialize_room_locked(group_id, member_map)

    if removed:
        await _broadcast_voice_room_state(group_id, list(member_map.keys()), participants)
    return {
        "group_id": group_id,
        "participants": participants,
        "max_peers": int(settings.MAX_GROUP_VOICE_PEERS),
    }


@router.post("/groups/{group_id}/voice/signal")
async def relay_group_voice_signal(
    request: Request,
    group_id: str,
    body: GroupVoiceSignalRequest,
    sender_device_id: str = Depends(get_current_device_id),
    db: AsyncSession = Depends(get_db),
):
    """
    Relay an Ed25519-signed & E2EE-encrypted SDP/ICE WebRTC packet between two
    active participants currently inside `group_id`'s voice room.
    Plaintext SDP/IPs/DTLS fingerprints are NEVER visible to the server.
    """
    if body.target_device_id == sender_device_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Self signaling rejected")

    member_map = await _require_group_member_device(group_id, sender_device_id, db)
    if body.target_device_id not in member_map:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Целевое устройство не в группе")

    now_m = time.monotonic()
    async with _VOICE_LOCK:
        _prune_and_serialize_room_locked(group_id, member_map, now_m)
        room = _VOICE_ROOMS.get(group_id)
        if not room or sender_device_id not in room or body.target_device_id not in room:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Оба участника должны находиться в голосовой комнате группы",
            )
        room[sender_device_id]["updated_at"] = now_m

    from app.api.messages import manager

    sender_meta = member_map[sender_device_id]
    delivered = await manager.send_personal_message(
        {
            "type": "group_voice_signal",
            "group_id": group_id,
            "sender_device_id": sender_device_id,
            "sender_username": sender_meta["username"],
            "sender_public_key": sender_meta["public_key"],
            "channel": body.channel,
            "encrypted_blob": body.encrypted_blob,
            "signature": body.signature,
        },
        body.target_device_id,
    )
    return {"status": "relayed" if delivered else "offline", "delivered": bool(delivered)}
