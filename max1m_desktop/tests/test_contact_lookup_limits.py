import json
from app.client_api import APIClient

class Response:
    def __init__(self, data, status=200): self.data, self.status_code, self.closed = data, status, False
    def iter_content(self, n): yield self.data
    def close(self): self.closed = True

def device(i='device'):
    return {'device_id': i, 'device_name': 'laptop', 'public_key': 'abc', 'fingerprint':'abc',
            'verified_fingerprint':'server cannot assert trust', 'verified_scope': 'bad'}

def test_lookup_sanitizes_trust_and_binds_username(monkeypatch):
    calls = []
    result = {'username': 'bob', 'user_id': 'u', 'devices': [device()], 'extra': 'ignored'}
    response = Response(json.dumps(result).encode())
    monkeypatch.setattr('app.client_api.requests.get', lambda url, **kw: calls.append((url, kw)) or response)
    ok, data = APIClient().find_user('https://server/', 'token', '@bob')
    assert ok and calls[0][0] == 'https://server/auth/find/bob'
    assert calls[0][1]['stream'] and not calls[0][1]['allow_redirects'] and response.closed
    assert set(data) == {'username', 'user_id', 'devices'} and 'verified_scope' not in data['devices'][0]
    result['username'] = 'eve'; response = Response(json.dumps(result).encode())
    assert not APIClient().find_user('https://server', 'token', 'bob')[0] and response.closed

def test_lookup_rejects_bad_path_and_large_or_ambiguous_result(monkeypatch):
    calls = []
    response = Response(b'x' * (1024 * 1024 + 1))
    monkeypatch.setattr('app.client_api.requests.get', lambda *a, **kw: calls.append(kw) or response)
    api = APIClient()
    assert not api.find_user('https://server', 'token', '../other')[0] and not calls
    assert not api.find_user('https://server', 'token', 'bob')[0] and response.closed
    for devices in ([], [device()] * 257, [device(), device()]):
        response = Response(json.dumps({'username':'bob','user_id':'u','devices':devices}).encode())
        assert not api.find_user('https://server', 'token', 'bob')[0] and response.closed
    response = Response(b'bad body', status=302)
    assert not api.find_user('https://server', 'token', 'bob')[0] and response.closed
