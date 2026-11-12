"""Fail-closed identity checks for personal-message envelopes."""
from app.recipient_context import RecipientContext, recipient_is_verified


MAX_INCOMING_BLOB_CHARS = 1024 * 1024
MAX_INCOMING_SIGNATURE_CHARS = 512
MAX_DEVICE_ID_CHARS = 64


class IncomingIdentityError(ValueError):
    """The message must remain unacknowledged on the server."""


def verify_incoming(state, crypto, envelope):
    try:
        if not isinstance(envelope, dict) or not state.username or not state.device_id or not state.server_url:
            raise ValueError("missing session")
        sender_id = envelope.get("sender_device_id")
        blob, signature = envelope.get("encrypted_blob"), envelope.get("signature")
        if (not all(isinstance(x, str) and x for x in (sender_id, blob, signature))
                or len(sender_id) > MAX_DEVICE_ID_CHARS
                or len(blob) > MAX_INCOMING_BLOB_CHARS
                or len(signature) > MAX_INCOMING_SIGNATURE_CHARS):
            raise ValueError("invalid envelope")
        matches = [(username, device) for username, ally in state.allies.items()
                   for device in ally.get("devices", []) if device.get("device_id") == sender_id]
        if len(matches) != 1:
            raise ValueError("unknown or ambiguous device")
        username, device = matches[0]
        context = RecipientContext(username, sender_id, device["public_key"], state.username,
                                   state.device_id, state.server_url.rstrip("/"))
        if not recipient_is_verified(state, context):
            raise ValueError("device fingerprint not verified")
        if not crypto.verify_signature(blob, signature, context.public_key):
            raise ValueError("invalid signature")
        from app.double_ratchet import (
            RatchetStore,
            ReplayAlreadyProcessed,
            is_double_ratchet_blob,
        )
        if is_double_ratchet_blob(blob):
            if getattr(crypto, "private_key", None) is None:
                raise ValueError("missing local private key")
            try:
                pt = RatchetStore(state.username).decrypt_from_peer(
                    our_signing_key=crypto.private_key,
                    our_ik_b64=crypto.get_public_key_b64(),
                    our_device_id=state.device_id,
                    peer_device_id=sender_id,
                    peer_verified_ik_b64=context.public_key,
                    wire_blob=blob,
                    server_delivery_id=envelope.get("id") if isinstance(envelope.get("id"), str) else None,
                )
                return context, pt
            except ReplayAlreadyProcessed:
                return context, '{"type":"dr_already_processed"}'
        return context, crypto.decrypt_message(blob, context.public_key)
    except Exception as exc:
        raise IncomingIdentityError("Incoming sender cannot be authenticated") from exc
