import asyncio
import datetime
import logging
from types import SimpleNamespace

import pytest

from fastapi import HTTPException

from app.api import messages
from app.logging_security import safe_identifier_tag


def test_send_rejection_logs_use_whitelisted_safe_reasons_only():
    assert messages._safe_send_rejection_reason(
        HTTPException(429, "Очередь получателя заполнена; повторите позже")
    ) == "recipient_queue_full"
    assert messages._safe_send_rejection_reason(
        HTTPException(409, "Message identifier conflict")
    ) == "idempotency_conflict"
    secret = "peer-controlled-detail-with-sensitive-content"
    assert messages._safe_send_rejection_reason(HTTPException(400, secret)) == "server_policy"


@pytest.mark.parametrize("sent", [True, False])
def test_live_notification_uses_canonical_delivery_id_and_safe_diagnostics(monkeypatch, caplog, sent):
    delivery_id = "12345678-1234-4234-8234-123456789abc"
    sender_id = "sender-device-full-id"
    receiver_id = "receiver-device-full-id"
    ciphertext = "private-ciphertext-must-not-be-logged"
    signature = "private-signature-must-not-be-logged"
    message = SimpleNamespace(
        id=delivery_id,
        sender_device_id=sender_id,
        receiver_device_id=receiver_id,
        sender_user_id="private-user-id",
        sender_username="private-username",
        encrypted_blob=ciphertext,
        signature=signature,
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    delivered = []

    async def fake_send(envelope, device_id):
        delivered.append((envelope, device_id))
        return sent

    monkeypatch.setattr(messages.manager, "send_personal_message", fake_send)
    with caplog.at_level(logging.INFO, logger="max1m.messages"):
        asyncio.run(messages._notify_message(message))

    assert len(delivered) == 1
    envelope, target = delivered[0]
    assert target == receiver_id
    assert envelope["id"] == envelope["message_id"] == delivery_id
    assert envelope["encrypted_blob"] == ciphertext
    assert envelope["signature"] == signature
    assert safe_identifier_tag(delivery_id) in caplog.text
    for secret in (sender_id, receiver_id, "private-user-id", "private-username", ciphertext, signature):
        assert secret not in caplog.text
    assert ("status=sent" if sent else "status=pending_sync") in caplog.text
