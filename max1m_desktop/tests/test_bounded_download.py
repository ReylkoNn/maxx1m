from app import client_api


class Response:
    def __init__(self, chunks, status=200):
        self.chunks = chunks
        self.status_code = status
        self.closed = False
    def iter_content(self, size):
        assert size in (4096, 64 * 1024)
        yield from self.chunks
    def close(self):
        self.closed = True


def test_download_streamed_with_bound_and_closed(monkeypatch):
    monkeypatch.setattr(client_api, 'MAX_DOWNLOAD_BYTES', 10)
    response = Response([b'abcd', b'ef'])
    calls = []
    def get(*args, **kwargs):
        calls.append(kwargs)
        return response
    monkeypatch.setattr(client_api.requests, 'get', get)
    assert client_api.APIClient().download_file('https://node', 'token', '123e4567-e89b-42d3-a456-426614174000') == (True, b'abcdef')
    assert calls[0]['stream'] is True and calls[0]['allow_redirects'] is False and response.closed
    response = Response([b'123456', b'78901'])
    success, result = client_api.APIClient().download_file('https://node', 'token', '123e4567-e89b-42d3-a456-426614174000')
    assert not success and 'лимит' in result and response.closed


def test_download_errors_do_not_read_untrusted_bodies(monkeypatch):
    response = Response([], status=503)
    def no_read(_):
        raise AssertionError('error body should not be read')
    response.iter_content = no_read
    monkeypatch.setattr(client_api.requests, 'get', lambda *args, **kwargs: response)
    success, result = client_api.APIClient().download_file('https://node', 'token', '123e4567-e89b-42d3-a456-426614174000')
    assert not success and result == 'HTTP 503' and response.closed


def test_reliable_send_caps_response_and_preserves_error_status(monkeypatch):
    payload = {'client_message_id': 'a'}
    monkeypatch.setattr(client_api, 'MAX_SEND_RESPONSE_BYTES', 16 * 1024)
    response = Response([b'x' * (16 * 1024 + 1)])
    monkeypatch.setattr(client_api.requests, 'post', lambda *a, **k: response)
    success, result = client_api.APIClient().send_reliable_message('https://node', 'token', payload)
    assert not success and response.closed
    response = Response([], 429)
    success, result = client_api.APIClient().send_reliable_message('https://node', 'token', payload)
    assert not success and result.startswith('HTTP 429:') and response.closed


def test_reliable_send_accepts_normal_large_legacy_server_echo(monkeypatch):
    import json
    body = json.dumps({'id': 'a', 'encrypted_blob': 'x' * (128 * 1024), 'signature': 's'}).encode()
    response = Response([body])
    monkeypatch.setattr(client_api.requests, 'post', lambda *a, **kw: response)
    payload = {'client_message_id': 'a', 'encrypted_blob': 'x' * (128 * 1024), 'signature': 's'}
    success, data = client_api.APIClient().send_reliable_message('https://node', 'token', payload)
    assert success and data['id'] == 'a' and response.closed


def test_auth_response_bounded_and_never_follows_password_redirect(monkeypatch):
    import json
    response = Response([json.dumps({'detail': 'wrong password'}).encode()], status=401)
    calls = []
    def post(*args, **kwargs):
        calls.append(kwargs)
        return response
    monkeypatch.setattr(client_api.requests, 'post', post)
    api = client_api.APIClient()
    ok, message = api.login('https://node', {'password': 'secret'})
    assert not ok and 'wrong password' in message and response.closed
    assert calls[-1]['stream'] and calls[-1]['allow_redirects'] is False
    response = Response([b'x' * (64 * 1024 + 1)], status=200)
    assert not api.login('https://node', {'password': 'secret'})[0] and response.closed
    response = Response([b'{}'], status=307)
    assert not api.register('https://node', {'password': 'secret'})[0] and response.closed
    assert calls[-1]['allow_redirects'] is False


def test_download_rejects_untrusted_ids_before_request(monkeypatch):
    def fail(*args, **kwargs): raise AssertionError('no HTTP request should be sent')
    monkeypatch.setattr(client_api.requests, 'get', fail)
    for file_id in ('../auth/login', 'file', '123e4567-e89b-12d3-a456-426614174000', None):
        assert not client_api.APIClient().download_file('https://node', 'token', file_id)[0]


def test_download_does_not_follow_redirect(monkeypatch):
    response = Response([], 302)
    monkeypatch.setattr(client_api.requests, 'get', lambda *a, **kw: response)
    ok, error = client_api.APIClient().download_file('https://node', 'token', '123e4567-e89b-42d3-a456-426614174000')
    assert not ok and error == 'HTTP 302' and response.closed


def test_transient_send_caps_response_closes_and_never_follows_redirect(monkeypatch):
    import json
    response=Response([json.dumps({'id':'ok'}).encode()]); calls=[]
    def post(*args,**kwargs): calls.append(kwargs); return response
    monkeypatch.setattr(client_api.requests,'post',post)
    api=client_api.APIClient()
    assert api.send_message('https://node','token',{'signature':'x'})==(True,{'id':'ok'})
    assert calls[-1]['stream'] and calls[-1]['allow_redirects'] is False and response.closed
    response=Response([],302)
    response.iter_content=lambda _: (_ for _ in ()).throw(AssertionError('must not read error body'))
    assert api.send_message('https://node','token',{})[0] is False and response.closed
    monkeypatch.setattr(client_api,'MAX_SEND_RESPONSE_BYTES',16)
    response=Response([b'x'*17])
    assert api.send_message('https://node','token',{})[0] is False and response.closed
