"""Fail-closed recipient verification for all queued personal envelopes.

This also handles records created before recipient metadata was stored: Box
ciphertexts can be decrypted by the sender using the sender's own private key
and the verified recipient public key. No plaintext is logged or sent here.
"""
import json
import math
from app.recipient_context import RecipientContext, recipient_is_verified
from app.outbox import ALLOWED_RECORD_FIELDS


class OutboxRecipientError(ValueError):
    """Queued data must remain on disk and must not be sent."""


def _verify_history_content(history, message):
    """Local history must describe the same message as the signed ciphertext."""
    from app.media_identity import valid_file_id, valid_file_key
    timestamp = history.get("timestamp")
    if timestamp is not None and not isinstance(timestamp, str):
        raise ValueError("invalid history timestamp")
    msg_id = message.get("msg_id")
    if (not isinstance(msg_id, str) or not 1 <= len(msg_id) <= 256
            or history.get("msg_id") != msg_id):
        raise ValueError("history message id mismatch")
    kind = message.get("type")
    if kind == "text":
        text = message.get("text", "")
        if not isinstance(text, str):
            raise ValueError("invalid text")
    else:
        file_id, key = message.get("file_id"), message.get("secret_key")
        if not valid_file_id(file_id) or not valid_file_key(key):
            raise ValueError("invalid attachment")
        if kind == "image":
            caption = message.get("caption", "")
            if not isinstance(caption, str):
                raise ValueError("invalid caption")
            text = f"[IMAGE_META]|{file_id}|{key}|{caption}"
        elif kind == "file":
            from app.media_identity import MAX_DOCUMENT_BYTES, build_file_meta, sanitize_attachment_filename
            fname = message.get("filename")
            fsize = message.get("size_bytes")
            caption = message.get("caption", "")
            if (not isinstance(fname, str) or not 1 <= len(fname) <= 255
                    or fname != sanitize_attachment_filename(fname)
                    or isinstance(fsize, bool) or not isinstance(fsize, int)
                    or not 0 <= fsize <= MAX_DOCUMENT_BYTES
                    or not isinstance(caption, str)):
                raise ValueError("invalid document attachment")
            text = build_file_meta(file_id, key, fname, fsize, caption)
        else:
            duration = message.get("duration", 0)
            if (isinstance(duration, bool) or not isinstance(duration, (int, float))
                    or not math.isfinite(duration) or not 0 <= duration <= 86400):
                raise ValueError("invalid duration")
            text = f"[VOICE_META]|{file_id}|{key}|{duration:.1f}"
    if history.get("text") != text:
        raise ValueError("history text mismatch")
    reply = message.get("reply_to")
    if reply is not None and not isinstance(reply, dict):
        raise ValueError("invalid reply")
    reply = reply or {}
    if any(value is not None and not isinstance(value, str)
           for value in (reply.get("msg_id"), reply.get("text"), reply.get("sender"))):
        raise ValueError("invalid reply")
    reply_id = reply.get("msg_id") or None
    history_id = history.get("reply_to_msg_id") or None
    if reply_id != history_id:
        raise ValueError("history reply mismatch")
    if reply_id and (not isinstance(reply_id, str) or len(reply_id) > 256
            or reply.get("text") != history.get("reply_to_text")
            or reply.get("sender") != history.get("reply_to_sender")):
        raise ValueError("history reply mismatch")
    ttl_val = message.get("ttl_seconds")
    if ttl_val is not None:
        if isinstance(ttl_val, bool) or not isinstance(ttl_val, int) or not (5 <= ttl_val <= 30 * 86400):
            raise ValueError("invalid message ttl_seconds")
    hist_exp = history.get("expires_at")
    if hist_exp is not None:
        if isinstance(hist_exp, bool) or not isinstance(hist_exp, (int, float)) or not math.isfinite(hist_exp) or hist_exp <= 0:
            raise ValueError("invalid history expires_at")


def verify_queued_recipient(state, crypto, record, attachment_file_id=None, *, return_attachment_key=False):
    try:
        if not isinstance(record, dict) or set(record) - ALLOWED_RECORD_FIELDS:
            raise ValueError("unsupported queued fields")
        if "_send_attempted" in record and not isinstance(record["_send_attempted"], bool):
            raise ValueError("invalid send_attempted flag")
        device_id = record["receiver_device_id"]
        if not isinstance(device_id, str) or not device_id:
            raise ValueError("bad device")
        matches = [(username, device) for username, contact in state.allies.items()
                   for device in contact.get("devices", []) if device.get("device_id") == device_id]
        if len(matches) != 1:
            raise ValueError("unknown or ambiguous device")
        username, device = matches[0]
        history = record.get("_local_history")
        if history is not None and (not isinstance(history, dict) or history.get("ally_username") != username):
            raise ValueError("history recipient mismatch")
        context = RecipientContext(username, device_id, device["public_key"], state.username,
                                   state.device_id, state.server_url.rstrip("/"))
        if not recipient_is_verified(state, context):
            raise ValueError("unverified recipient")
        encrypted, signature = record["encrypted_blob"], record["signature"]
        if not isinstance(encrypted, str) or not isinstance(signature, str):
            raise ValueError("invalid envelope")
        if not crypto.verify_signature(encrypted, signature, crypto.get_public_key_b64()):
            raise ValueError("incorrect sender signature")
        from app.double_ratchet import (
            attachment_commitment,
            is_double_ratchet_blob,
            parse_double_ratchet_outer,
        )
        if is_double_ratchet_blob(encrypted):
            import hmac as _hmac
            outer = parse_double_ratchet_outer(encrypted)
            if outer.get("recipient_ik") != context.public_key or outer.get("recipient_device_id") != context.device_id:
                raise ValueError("DR recipient key or device mismatch")
            mkind = outer.get("msg_kind")
            if mkind not in {"text", "image", "voice", "file", "delete_msg", "edit_msg", "pin_msg"}:
                raise ValueError("invalid DR personal message kind")
            if mkind in {"delete_msg", "edit_msg", "pin_msg"}:
                if history is not None or attachment_file_id is not None:
                    raise ValueError("invalid DR control payload")
            elif history is not None:
                if (not isinstance(history.get("msg_id"), str)
                        or not 1 <= len(history["msg_id"]) <= 256
                        or not isinstance(history.get("text"), str)):
                    raise ValueError("invalid DR history")
            if attachment_file_id is not None:
                from app.media_identity import parse_file_meta, valid_file_id, valid_file_key
                if (mkind not in {"image", "voice", "file"}
                        or not valid_file_id(attachment_file_id)
                        or not isinstance(history, dict)
                        or not isinstance(history.get("msg_id"), str)
                        or not history["msg_id"]
                        or not isinstance(history.get("text"), str)):
                    raise ValueError("DR attachment history missing")
                if mkind == "file":
                    fmeta = parse_file_meta(history["text"])
                    if fmeta is None:
                        raise ValueError("DR file meta malformed")
                    fid, skey = fmeta["file_id"], fmeta["secret_key"]
                else:
                    parts = history["text"].split("|", 3)
                    expected_prefix = "[IMAGE_META]" if mkind == "image" else "[VOICE_META]"
                    if len(parts) < 4 or parts[0] != expected_prefix:
                        raise ValueError("DR attachment meta malformed")
                    fid, skey = parts[1], parts[2]
                if fid != attachment_file_id or not valid_file_key(skey):
                    raise ValueError("DR attachment file_id or key mismatch")
                expected_commit = attachment_commitment(attachment_file_id, skey, history["msg_id"])
                actual_commit = outer.get("attachment_commit")
                if not isinstance(actual_commit, str) or not _hmac.compare_digest(actual_commit, expected_commit):
                    raise ValueError("DR attachment commitment mismatch")
                if return_attachment_key:
                    return context, skey
            elif return_attachment_key:
                raise ValueError("attachment context required")
            return context
        # Sender-side Box decryption proves that this exact ciphertext was
        # encrypted for the currently verified key, including old queue records.
        plaintext = crypto.decrypt_message(encrypted, context.public_key)
        message = json.loads(plaintext)
        if not isinstance(message, dict) or message.get("type") not in {
            "text", "image", "voice", "file", "delete_msg", "edit_msg", "pin_msg"
        }:
            raise ValueError("invalid personal message")
        if message.get("type") == "delete_msg":
            msg_id = message.get("msg_id")
            if (set(message) != {"type", "msg_id"}
                    or not isinstance(msg_id, str)
                    or not 1 <= len(msg_id) <= 256
                    or history is not None
                    or attachment_file_id is not None):
                raise ValueError("invalid delete_msg payload")
        elif message.get("type") == "edit_msg":
            msg_id = message.get("msg_id")
            new_text = message.get("new_text")
            if (set(message) != {"type", "msg_id", "new_text"}
                    or not isinstance(msg_id, str) or not 1 <= len(msg_id) <= 256
                    or not isinstance(new_text, str) or not 1 <= len(new_text) <= 256 * 1024
                    or history is not None or attachment_file_id is not None):
                raise ValueError("invalid edit_msg payload")
        elif message.get("type") == "pin_msg":
            msg_id = message.get("msg_id")
            preview = message.get("preview", "")
            if (not isinstance(msg_id, str) or len(msg_id) > 256
                    or not isinstance(preview, str) or len(preview) > 1024
                    or history is not None or attachment_file_id is not None):
                raise ValueError("invalid pin_msg payload")
        elif history is not None:
            _verify_history_content(history, message)
        if attachment_file_id is not None:
            from app.media_identity import valid_file_id, valid_file_key
            if (message.get("type") not in {"image", "voice", "file"}
                    or not valid_file_id(attachment_file_id)
                    or message.get("file_id") != attachment_file_id
                    or not valid_file_key(message.get("secret_key"))
                    or not isinstance(history, dict)
                    or not isinstance(message.get("msg_id"), str)
                    or not message["msg_id"] or history.get("msg_id") != message["msg_id"]):
                raise ValueError("attachment message does not match job")
        if return_attachment_key:
            if attachment_file_id is None:
                raise ValueError("attachment context required")
            return context, message["secret_key"]
        return context
    except Exception as exc:
        raise OutboxRecipientError("Очередь ожидает проверки получателя или содержит несовместимый пакет") from exc
