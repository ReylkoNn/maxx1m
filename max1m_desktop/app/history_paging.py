"""Select a chronological page from the end without discarding history."""
from dataclasses import dataclass

PAGE_SIZE = 25


class HistoryStale(Exception):
    """History changed during a background read; discard and retry."""


class HistoryCancelled(Exception):
    """A cooperative history read was cancelled without modifying data."""


def check_cancel(cancel):
    if cancel is not None and cancel():
        raise HistoryCancelled()

@dataclass(frozen=True)
class HistoryPage:
    messages: list
    offset: int
    total: int
    has_older: bool
    has_newer: bool


def history_page(messages, offset=0, page_size=PAGE_SIZE):
    if not isinstance(offset, int) or offset < 0 or not isinstance(page_size, int) or page_size < 1:
        raise ValueError('Invalid history page')
    total = len(messages)
    # If deletions shrink the history, fall back to the oldest nonempty page.
    offset = min(offset, max(total - 1, 0))
    end = total - offset
    start = max(0, end - page_size)
    return HistoryPage(messages[start:end], offset, total, start > 0, offset > 0)


def searchable_text(message):
    """Search user-visible content, never attachment identifiers or keys."""
    text = message.get("text", "")
    if not isinstance(text, str):
        raise ValueError("Invalid message text")
    if text.startswith("[IMAGE_META]|"):
        parts = text.split("|", 3)
        return "Фото" + (" " + parts[3] if len(parts) == 4 and parts[3] else "")
    if text.startswith("[VOICE_META]|"):
        return "Голосовое сообщение"
    return text


@dataclass(frozen=True)
class HistoryView:
    """A chronological page and the unread count for the entire chat."""
    messages: list
    offset: int
    total: int
    unread: int
    has_older: bool
    has_newer: bool


def legacy_history_view(messages, offset=0, page_size=PAGE_SIZE, query=None, cancel=None):
    """Adapter for monolithic histories; still holds all messages in memory."""
    if (type(offset) is not int or offset < 0 or type(page_size) is not int
            or not 1 <= page_size <= PAGE_SIZE or (query is not None and not isinstance(query, str))):
        raise ValueError("Invalid history page")
    query_lower = query.lower() if query is not None else None
    candidates = [] if query_lower is not None else messages
    unread = 0
    for message in messages:
        check_cancel(cancel)
        if message.get("is_mine") is False and not message.get("is_read") and message.get("msg_id"):
            unread += 1
        if query_lower is not None and query_lower in searchable_text(message).lower():
            candidates.append(message)
    check_cancel(cancel)
    page = history_page(candidates, offset, page_size)
    return HistoryView(page.messages, page.offset, page.total, unread,
                       page.has_older, page.has_newer)
