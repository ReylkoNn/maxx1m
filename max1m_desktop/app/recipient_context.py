"""Immutable recipient snapshot for asynchronous attachment workflows."""
from dataclasses import dataclass


@dataclass(frozen=True)
class RecipientContext:
    username: str
    device_id: str
    public_key: str
    owner_username: str
    owner_device_id: str
    server_url: str


def capture_recipient(state):
    if getattr(state, "current_chat_type", None) != "ally":
        raise ValueError("Выберите личный чат")
    username = state.current_chat_username
    device_id = state.current_chat_device_id
    contact = state.allies.get(username, {})
    device = next((d for d in contact.get("devices", []) if d.get("device_id") == device_id), None)
    if not username or not device_id or not device or not device.get("public_key"):
        raise ValueError("Не найдено устройство получателя")
    if not state.username or not state.device_id or not state.server_url:
        raise ValueError("Нет активного подключения")
    return RecipientContext(username, device_id, device["public_key"], state.username,
                            state.device_id, state.server_url.rstrip("/"))


def recipient_still_trusted(state, context):
    if not state.username or not state.device_id or not state.server_url:
        return False
    if (state.username != context.owner_username or state.device_id != context.owner_device_id
            or state.server_url.rstrip("/") != context.server_url):
        return False
    matches = [(username, device) for username, contact in state.allies.items()
               for device in contact.get("devices", []) if device.get("device_id") == context.device_id]
    return (len(matches) == 1 and matches[0][0] == context.username
            and matches[0][1].get("public_key") == context.public_key)


def verification_scope(context):
    return {"username": context.owner_username, "device_id": context.owner_device_id,
            "server_url": context.server_url.rstrip("/")}


def recipient_is_verified(state, context):
    if not recipient_still_trusted(state, context):
        return False
    from app.contact_keys import fingerprint_public_key
    device = next(d for d in state.allies[context.username]["devices"]
                  if d.get("device_id") == context.device_id and d.get("public_key") == context.public_key)
    try:
        return (device.get("verified_fingerprint") == fingerprint_public_key(context.public_key)
                and device.get("verified_scope") == verification_scope(context))
    except (ValueError, TypeError):
        return False


def is_active_recipient(state, context):
    return (recipient_still_trusted(state, context) and state.current_chat_type == "ally"
            and state.current_chat_username == context.username
            and state.current_chat_device_id == context.device_id)
