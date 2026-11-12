import json

MAX_SYNC_RESPONSE_BYTES = 24 * 1024 * 1024
MAX_READ_ACK_IDS = 1024


def bounded_json_response(response):
    data = bytearray()
    for chunk in response.iter_content(64 * 1024):
        if not isinstance(chunk, bytes) or len(data) + len(chunk) > MAX_SYNC_RESPONSE_BYTES:
            raise ValueError("Sync response exceeds size limit")
        data.extend(chunk)
    return json.loads(data)


"""Pure helpers for the bounded personal-message delivery protocol."""

SYNC_PAGE_SIZE = 20


def process_delivery_page(messages, process_message):
    """Return IDs successfully handled and a cursor for the next page.

    A rejected message is deliberately not acknowledged; advancing the cursor
    lets later messages through, and the next scan starts again from the top.
    """
    # A repeated ID could otherwise acknowledge a failed occurrence merely
    # because a different occurrence with the same ID succeeded.
    ids = [message.get("id") for message in messages if isinstance(message, dict)]
    valid_ids = [value for value in ids if isinstance(value, str) and 0 < len(value) <= 64]
    if len(set(valid_ids)) != len(valid_ids):
        return [], None
    processed = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        message_id = message.get("id")
        if not isinstance(message_id, str) or not 0 < len(message_id) <= 64:
            continue
        try:
            accepted = process_message(message)
        except Exception:
            # Leave this record pending but allow independent records through.
            # Do not log exception text, which may contain message data.
            accepted = False
        if accepted:
            processed.append(message_id)
    cursor = None
    if len(messages) >= SYNC_PAGE_SIZE and isinstance(messages[-1], dict):
        last_id = messages[-1].get("id")
        if isinstance(last_id, str) and 0 < len(last_id) <= 64:
            cursor = last_id
    return processed, cursor
