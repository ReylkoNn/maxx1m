from app.delivery import process_delivery_page


def test_only_successful_durable_processing_is_acknowledged():
    items = [{"id": "ok"}, {"id": "unknown"}, {"bad": "missing id"}]
    visited = []
    def process(message):
        visited.append(message["id"])
        return message["id"] == "ok"
    ids, cursor = process_delivery_page(items, process)
    assert ids == ["ok"]
    assert visited == ["ok", "unknown"]
    assert cursor is None


def test_full_page_advances_even_when_some_messages_are_unprocessed():
    items = [{"id": str(i)} for i in range(100)]
    ids, cursor = process_delivery_page(items, lambda item: item["id"] != "99")
    assert len(ids) == 99
    assert cursor == "99"


def test_smaller_page_advances_past_unprocessed_messages():
    items = [{"id": str(i)} for i in range(20)]
    ids, cursor = process_delivery_page(items, lambda item: item['id'] != '19')
    assert len(ids) == 19 and cursor == '19'


def test_sync_reader_stops_at_bounded_response(monkeypatch):
    import pytest
    from app import delivery
    class Response:
        def iter_content(self, size):
            yield b'123456'
            yield b'789012'
            raise AssertionError('must not keep reading after limit')
    monkeypatch.setattr(delivery, 'MAX_SYNC_RESPONSE_BYTES', 10)
    with pytest.raises(ValueError, match='size limit'):
        delivery.bounded_json_response(Response())


def test_oversized_ids_are_never_processed_or_used_as_cursors():
    messages = [{'id': f'ok-{i}'} for i in range(19)] + [{'id': 'x' * 65}]
    visited = []
    ack, cursor = process_delivery_page(messages, lambda message: visited.append(message) or True)
    assert len(ack) == 19 and len(visited) == 19 and cursor is None
