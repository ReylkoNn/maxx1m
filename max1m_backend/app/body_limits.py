"""Bound message JSON bodies before FastAPI buffers/parses them.

Limits individual non-upload request bodies before parsing; uploads use a
separate streaming cap. Aggregate memory and slow clients still require reverse
proxy connection limits and timeouts.
"""
MAX_MESSAGE_BODY_BYTES = 2 * 1024 * 1024
MAX_OTHER_BODY_BYTES = 2 * 1024 * 1024
MESSAGE_PATHS = frozenset(('/messages/send', '/messages/send-reliable'))


class MessageBodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    def applies(self, scope):
        return (scope['type'] == 'http' and scope.get('method') == 'POST'
                and scope.get('path') in MESSAGE_PATHS)

    def limit(self):
        return MAX_MESSAGE_BODY_BYTES

    async def __call__(self, scope, receive, send):
        if not self.applies(scope):
            await self.app(scope, receive, send)
            return
        limit = self.limit()

        async def reject(status):
            body = b'{"detail":"Request body too large"}' if status == 413 else b'{"detail":"Invalid Content-Length"}'
            await send({'type': 'http.response.start', 'status': status,
                        'headers': [(b'content-type', b'application/json'),
                                    (b'content-length', str(len(body)).encode('ascii'))]})
            await send({'type': 'http.response.body', 'body': body})

        lengths = [v for k, v in scope.get('headers', []) if k.lower() == b'content-length']
        if len(lengths) > 1:
            await reject(400)
            return
        if lengths:
            try:
                value = lengths[0]
                if not value or not value.isdigit():
                    raise ValueError('Invalid Content-Length')
                if int(value) > limit:
                    await reject(413)
                    return
            except (TypeError, ValueError):
                await reject(400)
                return

        buffered = bytearray()
        while True:
            event = await receive()
            if event['type'] == 'http.disconnect':
                return
            if event['type'] != 'http.request':
                continue
            chunk = event.get('body', b'')
            if len(buffered) + len(chunk) > limit:
                await reject(413)
                return
            buffered.extend(chunk)
            if not event.get('more_body', False):
                break

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {'type': 'http.request', 'body': bytes(buffered), 'more_body': False}
            return await receive()

        await self.app(scope, replay, send)

class GeneralBodyLimitMiddleware(MessageBodyLimitMiddleware):
    """Bound all other request bodies before FastAPI reads or validates them.

    Uploads have a separate streaming cap and are never buffered here.
    """
    def applies(self, scope):
        path = scope.get('path', '')
        method = scope.get('method')
        is_streaming_upload = (
            method == 'POST'
            and (path == '/files/upload' or path.startswith('/files/upload-reliable/'))
        )
        return (scope['type'] == 'http' and method in {'POST', 'PUT', 'PATCH', 'DELETE'}
                and path not in MESSAGE_PATHS and not is_streaming_upload)

    def limit(self):
        return MAX_OTHER_BODY_BYTES


# Raw reliable uploads are at most 100 MiB; multipart has extra envelope bytes.
RAW_UPLOAD_BODY_BYTES = 100 * 1024 * 1024
MULTIPART_UPLOAD_BODY_BYTES = RAW_UPLOAD_BODY_BYTES + 1024 * 1024


class UploadBodyLimitMiddleware:
    """Enforce upload body limits as chunks arrive, without buffering them here."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get('path', '')
        if scope['type'] != 'http' or scope.get('method') != 'POST':
            await self.app(scope, receive, send)
            return
        if path == '/files/upload':
            limit = MULTIPART_UPLOAD_BODY_BYTES
        elif path.startswith('/files/upload-reliable/'):
            limit = RAW_UPLOAD_BODY_BYTES
        else:
            await self.app(scope, receive, send)
            return

        lengths = [v for k, v in scope.get('headers', []) if k.lower() == b'content-length']
        if len(lengths) > 1 or (lengths and (not lengths[0] or not lengths[0].isdigit())):
            status = 400
        else:
            try:
                status = 413 if lengths and int(lengths[0]) > limit else None
            except ValueError:
                status = 400
        if status:
            body = b'{"detail":"Invalid or oversized upload body"}'
            await send({'type': 'http.response.start', 'status': status,
                        'headers': [(b'content-type', b'application/json'),
                                    (b'content-length', str(len(body)).encode('ascii'))]})
            await send({'type': 'http.response.body', 'body': body})
            return

        total = 0
        async def bounded_receive():
            nonlocal total
            event = await receive()
            if event['type'] == 'http.request':
                total += len(event.get('body', b''))
                if total > limit:
                    # FastAPI and Starlette preserve HTTPException from body
                    # parsing, while closing the form and upload temp files.
                    from fastapi import HTTPException
                    raise HTTPException(413, 'Upload request body too large')
            return event
        await self.app(scope, bounded_receive, send)
