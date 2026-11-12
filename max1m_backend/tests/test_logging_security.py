import logging
from app.logging_security import TokenRedactionFilter, install_uvicorn_token_filter


def test_redacts_token_in_formatted_websocket_url():
    record = logging.LogRecord("uvicorn.error", logging.INFO, __file__, 1,
        'WebSocket %s accepted', ('/messages/ws/id?token=secret.jwt&other=ok',), None)
    assert TokenRedactionFilter().filter(record)
    assert record.getMessage() == 'WebSocket /messages/ws/id?token=[REDACTED]&other=ok accepted'
    assert 'secret.jwt' not in str(record.args)


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
