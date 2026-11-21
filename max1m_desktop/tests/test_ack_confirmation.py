"""A 200 response alone is not a valid delivery acknowledgement."""
from types import SimpleNamespace
import pytest
from app import workers


def run(worker):
    result = []
    worker.finished.connect(lambda ok, detail: result.append((ok, detail)))
    worker.run()
    assert len(result) == 1
    return result[0]


@pytest.mark.parametrize('body', [b'{}', b'{"status":"error"}', b'[]', b'null', b'invalid', b'x' * 16385])
def test_invalid_ack_response_is_failure_and_closed(monkeypatch, body):
    closed = []
    response = SimpleNamespace(status_code=200, iter_content=lambda _: [body], close=lambda: closed.append(True))
    monkeypatch.setattr(workers.requests, 'post', lambda *a, **kw: response)
    ok, _ = run(workers.AcknowledgeMessagesWorker('https://node', 'secret', ['id']))
    assert not ok and closed == [True]


def test_error_ack_response_not_consumed(monkeypatch):
    def fail(_):
        pytest.fail('error body should not be consumed')
    closed = []
    response = SimpleNamespace(status_code=503, iter_content=fail, close=lambda: closed.append(True))
    monkeypatch.setattr(workers.requests, 'post', lambda *a, **kw: response)
    assert run(workers.AcknowledgeMessagesWorker('https://node', 'secret', ['id'])) == (False, 503)
    assert closed == [True]


@pytest.mark.parametrize('ids', [[], ['duplicate', 'duplicate'], [''], ['x' * 65], [None], ['x'] * 21, 'not-list'])
def test_bad_ack_ids_rejected_before_network(monkeypatch, ids):
    monkeypatch.setattr(workers.requests, 'post', lambda *a, **kw: pytest.fail('unexpected network'))
    ok, _ = run(workers.AcknowledgeMessagesWorker('https://node', 'secret', ids))
    assert not ok
