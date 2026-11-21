"""Local consent checks for legacy WebRTC signaling.

These checks do not authenticate call-control messages against a malicious
server and do not replace end-to-end identity verification or replay protection.
"""


def allow_webrtc_signal(sender_device_id, active_device_id, user_approved):
    return bool(user_approved and active_device_id and sender_device_id == active_device_id)


def resolve_call_peer(state, device_id):
    """Pin one local peer and account, without trusting any server name or key."""
    from app.recipient_context import RecipientContext, recipient_still_trusted
    if not isinstance(device_id, str) or not device_id or not state.server_url:
        return None
    try:
        matches = [(name, device) for name, contact in state.allies.items()
                   for device in contact.get("devices", []) if device.get("device_id") == device_id]
        if len(matches) != 1:
            return None
        name, device = matches[0]
        context = RecipientContext(name, device_id, device["public_key"], state.username,
                                   state.device_id, state.server_url.rstrip("/"))
        return context if context.public_key and recipient_still_trusted(state, context) else None
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def call_context_valid(state, context, require_verified=True):
    from app.recipient_context import recipient_still_trusted, recipient_is_verified
    if context is None:
        return False
    try:
        return (recipient_is_verified(state, context) if require_verified
                else recipient_still_trusted(state, context))
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
