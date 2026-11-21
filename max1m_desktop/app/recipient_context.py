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


def recipient_local_entry_is_verified(state, context, expected_user_id=None):
    """Verify one exact local entry, optionally disambiguated by a saved user ID.

    This is used only for an incoming message whose server hint selected one
    locally stored match. The hint never supplies the key or fingerprint.
    """
    if (not state.username or not state.device_id or not state.server_url
            or state.username != context.owner_username
            or state.device_id != context.owner_device_id
            or state.server_url.rstrip("/") != context.server_url):
        return False
    allies = getattr(state, "allies", None)
    contact = allies.get(context.username) if isinstance(allies, dict) else None
    if not isinstance(contact, dict):
        return False
    if expected_user_id is not None and (
        not isinstance(expected_user_id, str) or not expected_user_id
        or contact.get("user_id") != expected_user_id
    ):
        return False
    matches = [device for device in contact.get("devices", [])
               if isinstance(device, dict)
               and device.get("device_id") == context.device_id
               and device.get("public_key") == context.public_key]
    if len(matches) != 1:
        return False
    from app.contact_keys import fingerprint_public_key
    device = matches[0]
    try:
        return (device.get("verified_fingerprint") == fingerprint_public_key(context.public_key)
                and device.get("verified_scope") == verification_scope(context))
    except (ValueError, TypeError):
        return False


def recipient_is_verified(state, context):
    if not recipient_still_trusted(state, context):
        return False
    return recipient_local_entry_is_verified(
        state, context, expected_user_id=state.allies[context.username].get("user_id")
    )


def is_active_recipient(state, context):
    return (recipient_still_trusted(state, context) and state.current_chat_type == "ally"
            and state.current_chat_username == context.username
            and state.current_chat_device_id == context.device_id)


def choose_online_device(devices, online_device_ids, preferred_device_id=None,
                         verified_device_ids=()):
    """Choose an online, locally trusted device; never fall back to an unverified key."""
    if not isinstance(devices, list) or not isinstance(online_device_ids, (list, tuple, set)):
        return None
    ordered_ids = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        device_id = device.get("device_id")
        if isinstance(device_id, str) and device_id and device_id not in ordered_ids:
            ordered_ids.append(device_id)
    online = {device_id for device_id in online_device_ids
              if isinstance(device_id, str) and device_id}
    if not isinstance(verified_device_ids, (list, tuple, set)):
        verified_device_ids = ()
    verified = {device_id for device_id in verified_device_ids
                if isinstance(device_id, str) and device_id}
    candidates = [device_id for device_id in ordered_ids
                  if device_id in online and device_id in verified]
    if not candidates:
        return None
    if isinstance(preferred_device_id, str) and preferred_device_id in candidates:
        return preferred_device_id
    return candidates[-1]
