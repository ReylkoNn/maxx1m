import logging
from app.logging_security import TokenRedactionFilter, install_uvicorn_token_filter, safe_identifier_tag


def test_redacts_token_in_formatted_websocket_url():
    record = logging.LogRecord("uvicorn.error", logging.INFO, __file__, 1,
        'WebSocket %s accepted', ('/messages/ws/id?token=secret.jwt&other=ok',), None)
    assert TokenRedactionFilter().filter(record)
    assert record.getMessage() == 'WebSocket /messages/ws/[DEVICE]?token=[REDACTED]&other=ok accepted'
    assert 'secret.jwt' not in str(record.args)
    assert '/messages/ws/id' not in record.getMessage()


def test_identifier_tags_are_short_and_do_not_reveal_input():
    value = "full-device-id-that-must-not-appear"
    tag = safe_identifier_tag(value)
    assert len(tag) == 12 and tag != value
    assert safe_identifier_tag(value) == tag


def test_filter_install_is_idempotent():
    install_uvicorn_token_filter()
    install_uvicorn_token_filter()
    for name in ("uvicorn.error", "uvicorn.access"):
        assert sum(isinstance(f, TokenRedactionFilter) for f in logging.getLogger(name).filters) == 1


def test_uvicorn_access_formatter_still_receives_five_args():
    from uvicorn.logging import AccessFormatter
    record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1,
        '%s - "%s %s HTTP/%s" %d',
        ('127.0.0.1', 'GET', '/path?token=secret', '1.1', 200), None)
    TokenRedactionFilter().filter(record)
    assert len(record.args) == 5
    rendered = AccessFormatter('%(message)s', use_colors=False).format(record)
    assert 'secret' not in rendered
    assert '[REDACTED]' in rendered
