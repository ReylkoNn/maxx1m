"""Avoid recording WebSocket query-string credentials in Uvicorn logs."""
import logging
import re

_TOKEN_QUERY = re.compile(r"([?&]token=)[^&\s\"']*", re.IGNORECASE)
_BEARER_HEADER = re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/-]+=*", re.IGNORECASE)


def _redact(value):
    if isinstance(value, str):
        redacted = _TOKEN_QUERY.sub(r"\1[REDACTED]", value)
        return _BEARER_HEADER.sub(r"\1[REDACTED]", redacted)
    if isinstance(value, tuple):
        return tuple(_redact(item) for item in value)
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    return value


class TokenRedactionFilter(logging.Filter):
    def filter(self, record):
        # Keep the original argument structure; Uvicorn's access formatter
        # expects five fields and would fail if we pre-formatted the message.
        record.msg = _redact(record.msg)
        record.args = _redact(record.args)
        return True


def install_uvicorn_token_filter():
    for name in ("uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        if not any(isinstance(f, TokenRedactionFilter) for f in logger.filters):
            logger.addFilter(TokenRedactionFilter())
