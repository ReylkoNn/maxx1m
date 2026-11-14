"""Fail closed before network traffic for invalid attachment IDs and sizes."""
import pytest
from app import client_api

FILE_ID = '123e4567-e89b-42d3-a456-426614174000'


@pytest.mark.parametrize('identifier', [None, '', '../messages/send', 'file',
    '123e4567-e89b-12d3-a456-426614174000', '123E4567-E89B-42D3-A456-426614174000'])
def test_upload_and_grant_reject_invalid_ids_before_io(monkeypatch, identifier):
    monkeypatch.setattr(client_api.requests, 'post', lambda *a, **k: pytest.fail('unexpected network'))
    api = client_api.APIClient()
    assert not api.upload_file_reliable('https://node', 'secret', identifier, '/nonexistent')[0]
    assert not api.grant_file_access('https://node', 'secret', identifier, 'recipient')[0]


def test_empty_and_oversized_upload_rejected_before_network(tmp_path, monkeypatch):
    monkeypatch.setattr(client_api.requests, 'post', lambda *a, **k: pytest.fail('unexpected network'))
    monkeypatch.setattr(client_api, 'MAX_DOWNLOAD_BYTES', 10)
    api = client_api.APIClient()
    path = tmp_path / 'blob'
    for data in (b'', b'x' * 11):
        path.write_bytes(data)
        assert not api.upload_file_reliable('https://node', 'secret', FILE_ID, path)[0]
        assert not api.upload_file_reliable('https://node', 'secret', FILE_ID, data)[0]
        assert path.read_bytes() == data
