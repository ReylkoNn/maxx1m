"""Fail-closed identity checks for personal-message envelopes."""
import hashlib
import re

from app.recipient_context import (
    RecipientContext,
    recipient_is_verified,
    recipient_local_entry_is_verified,
)


MAX_INCOMING_BLOB_CHARS = 1024 * 1024
MAX_INCOMING_SIGNATURE_CHARS = 512
MAX_DEVICE_ID_CHARS = 64
_SAFE_DIRECTORY_VALUE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SAFE_DELIVERY_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def delivery_id_from_envelope(envelope):
    """Return the stable server ID from sync-safe or legacy WebSocket envelopes.

    Sync-safe uses ``id`` while the original live notification used
    ``message_id``. Both represent the same server delivery and must map to the
    same ratchet replay record. Conflicting aliases are rejected.
    """
    if not isinstance(envelope, dict):
        return None
    message_id = envelope.get("id")
    legacy_message_id = envelope.get("message_id")
    if message_id is not None and legacy_message_id is not None and message_id != legacy_message_id:
        raise ValueError("Conflicting server delivery identifiers")
    candidate = message_id if message_id is not None else legacy_message_id
    if candidate is None:
        return None
    if not isinstance(candidate, str) or not _SAFE_DELIVERY_ID.fullmatch(candidate):
        raise ValueError("Invalid server delivery identifier")
    return candidate


_SAFE_CAUSE_REASONS = {
    "missing session": "missing_session",
    "invalid envelope": "invalid_envelope",
    "invalid sender directory metadata": "invalid_sender_directory_metadata",
    "unknown sender device": "unknown_sender_device",
    "ambiguous sender device": "ambiguous_sender_device",
    "sender account identity changed": "sender_account_identity_changed",
    "device fingerprint not verified": "sender_device_not_verified",
    "invalid signature": "sender_signature_invalid",
    "missing local private key": "local_private_key_missing",
    "Expected base64 string": "malformed_ratchet_envelope",
    "Invalid base64 encoding": "malformed_ratchet_envelope",
    "Non-canonical base64 encoding": "malformed_ratchet_envelope",
    "Unexpected decoded byte length": "invalid_ratchet_key_length",
    "Invalid X25519 key length": "invalid_ratchet_key_length",
    "Rejected invalid/low-order X25519 point": "invalid_ratchet_dh_key",
    "All-zero X25519 shared secret": "invalid_ratchet_dh_key",
    "Bundle identity key or version mismatch": "local_prekey_identity_mismatch",
    "Signed prekey failed Ed25519 signature verification": "local_signed_prekey_signature_invalid",
    "Malformed one_time_key in bundle": "malformed_local_prekey_bundle",
    "Exceeded MAX_SKIP out-of-order message window": "ratchet_message_gap_too_large",
    "Duplicate or replayed message number": "ratchet_duplicate_or_replayed",
    "Double Ratchet AEAD authentication failed": "ratchet_authentication_failed",
    "Not a Double Ratchet envelope": "malformed_ratchet_envelope",
    "Invalid Double Ratchet wire magic": "malformed_ratchet_envelope",
    "Invalid Double Ratchet outer JSON": "malformed_ratchet_envelope",
    "Malformed Double Ratchet outer fields": "malformed_ratchet_envelope",
    "Encrypted ratchet store scope mismatch": "ratchet_store_scope_mismatch",
    "Corrupt ratchet store record": "ratchet_store_corrupt",
    "No active Double Ratchet session for peer": "ratchet_session_missing",
    "Missing active Double Ratchet state": "ratchet_state_missing",
    "Double Ratchet envelope addressed to different device/key": "ratchet_recipient_key_mismatch",
    "Conflicting ciphertext on duplicate server delivery ID": "conflicting_duplicate_delivery",
    "Unknown Double Ratchet session without valid X3DH init header": "ratchet_session_missing_or_invalid_init",
    "Referenced Signed PreKey not found or mismatched": "local_signed_prekey_missing_or_mismatched",
    "Invalid opk_id": "malformed_x3dh_header",
    "One-time prekey missing or already consumed": "local_one_time_prekey_missing_or_consumed",
    "Missing server delivery identifier": "missing_server_delivery_id",
    "Conflicting server delivery identifiers": "conflicting_server_delivery_id",
    "Invalid server delivery identifier": "invalid_server_delivery_id",
}


class IncomingIdentityError(ValueError):
    """The message must remain unacknowledged on the server."""

    def __init__(self, reason="identity_verification_failed", *, sender_tag=None, match_count=None):
        super().__init__("Incoming sender cannot be authenticated")
        self.reason = reason
        self.sender_tag = sender_tag
        self.match_count = match_count


def _sender_tag(sender_id):
    if not isinstance(sender_id, str) or not sender_id:
        return None
    return hashlib.sha256(sender_id.encode("utf-8", errors="replace")).hexdigest()[:12]


def _reason_for_cause(exc):
    message = str(exc)
    if message in _SAFE_CAUSE_REASONS:
        return _SAFE_CAUSE_REASONS[message]
    if isinstance(exc, ValueError):
        return "invalid_crypto_envelope"
    return "identity_validation_error"


def verify_incoming(state, crypto, envelope):
    sender_id = None
    match_count = None
    try:
        if (not isinstance(envelope, dict) or not state.username
                or not state.device_id or not state.server_url):
            raise ValueError("missing session")
        sender_id = envelope.get("sender_device_id")
        blob, signature = envelope.get("encrypted_blob"), envelope.get("signature")
        if (not all(isinstance(value, str) and value for value in (sender_id, blob, signature))
                or len(sender_id) > MAX_DEVICE_ID_CHARS
                or len(blob) > MAX_INCOMING_BLOB_CHARS
                or len(signature) > MAX_INCOMING_SIGNATURE_CHARS):
            raise ValueError("invalid envelope")

        sender_username = envelope.get("sender_username")
        sender_user_id = envelope.get("sender_user_id")
        has_valid_directory_hint = (
            isinstance(sender_username, str) and _SAFE_DIRECTORY_VALUE.fullmatch(sender_username)
            and isinstance(sender_user_id, str) and _SAFE_DIRECTORY_VALUE.fullmatch(sender_user_id)
        )

        allies = getattr(state, "allies", None)
        if not isinstance(allies, dict):
            raise ValueError("invalid envelope")
        matches = [
            (username, device)
            for username, ally in allies.items()
            if isinstance(ally, dict)
            for device in ally.get("devices", [])
            if isinstance(device, dict) and device.get("device_id") == sender_id
        ]
        match_count = len(matches)
        if match_count == 0:
            raise ValueError("unknown sender device")
        if match_count > 1:
            # Device IDs should be unique, but old contact books can contain
            # duplicates. Server metadata is only a selector among locally
            # stored matches; it never supplies or validates a public key.
            contact = allies.get(sender_username) if has_valid_directory_hint else None
            narrowed = [
                (username, device) for username, device in matches
                if username == sender_username and isinstance(contact, dict)
                and contact.get("user_id") == sender_user_id
            ]
            if len(narrowed) != 1:
                raise ValueError("ambiguous sender device")
            username, device = narrowed[0]
        else:
            # A unique local device mapping is authoritative. Directory hints
            # are advisory and must not block a valid signed message.
            username, device = matches[0]

        context = RecipientContext(
            username, sender_id, device["public_key"], state.username,
            state.device_id, state.server_url.rstrip("/"),
        )
        if match_count > 1:
            # The selected duplicate is allowed only if that exact local entry
            # was independently verified for this account and server. The
            # directory hint alone is never sufficient to trust it.
            is_verified = recipient_local_entry_is_verified(
                state, context, expected_user_id=sender_user_id
            )
        else:
            is_verified = recipient_is_verified(state, context)
        if not is_verified:
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
            delivery_id = delivery_id_from_envelope(envelope)
            if delivery_id is None:
                raise ValueError("Missing server delivery identifier")
            try:
                plaintext = RatchetStore(state.username).decrypt_from_peer(
                    our_signing_key=crypto.private_key,
                    our_ik_b64=crypto.get_public_key_b64(),
                    our_device_id=state.device_id,
                    peer_device_id=sender_id,
                    peer_verified_ik_b64=context.public_key,
                    wire_blob=blob,
                    server_delivery_id=delivery_id,
                )
                return context, plaintext
            except ReplayAlreadyProcessed:
                return context, '{"type":"dr_already_processed"}'
        return context, crypto.decrypt_message(blob, context.public_key)
    except Exception as exc:
        raise IncomingIdentityError(
            _reason_for_cause(exc),
            sender_tag=_sender_tag(sender_id),
            match_count=match_count,
        ) from exc
