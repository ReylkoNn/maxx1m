"""Regression tests for upload bounds and WebSocket connection ownership."""
from fastapi.testclient import TestClient
import pytest

from app.api import files, messages
from app.database import get_db
from app.main import app
from app.security import create_access_token


class Result:
    def __init__(self, device):
        self.device = device

    def scalars(self):
        return self

    def first(self):
        return self.device


class FakeDB:
    def __init__(self, device):
        self.device = device
        self.records = []

    async def execute(self, stmt):
        return Result(self.device)

    def add(self, record):
        self.records.append(record)

    async def commit(self):
        pass


@pytest.fixture
def upload_client(tmp_path, monkeypatch):
    from types import SimpleNamespace
    db = FakeDB(SimpleNamespace(user_id="user"))
    async def override_db():
        yield db
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[messages.get_current_device_id] = lambda: "device"
    monkeypatch.setattr(files, "UPLOAD_DIR", str(tmp_path))
    monkeypatch.setattr(files, "MAX_FILE_SIZE", 2 * 1024 * 1024)
    token = create_access_token({"device_id": "device"})
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client, db, tmp_path, {"Authorization": f"Bearer {token}"}
    app.dependency_overrides.clear()


def test_upload_bounded_and_access_recorded(upload_client, monkeypatch):
    client, db, path, headers = upload_client
    from starlette.datastructures import UploadFile
    original = UploadFile.read
    sizes = []
    async def checked_read(self, size=-1):
        sizes.append(size)
        return await original(self, size)
    monkeypatch.setattr(UploadFile, "read", checked_read)
    payload = b"a" * (1024 * 1024 + 12)
    response = client.post("/files/upload", headers=headers, files={"file": ("x", payload)})
    assert response.status_code == 200, response.text
    assert response.json()["size"] == len(payload)
    assert (path / response.json()["file_id"]).read_bytes() == payload
    assert sizes and all(size == 1024 * 1024 for size in sizes)
    assert len(db.records) == 2


def test_oversize_upload_removes_partial_file(upload_client):
    client, db, path, headers = upload_client
    response = client.post("/files/upload", headers=headers, files={"file": ("x", b"a" * (2 * 1024 * 1024 + 1))})
    assert response.status_code == 400
    assert list(path.iterdir()) == []
    assert not db.records


def test_unknown_device_does_not_write(upload_client):
    client, db, path, headers = upload_client
    db.device = None
    response = client.post("/files/upload", headers=headers, files={"file": ("x", b"data")})
    assert response.status_code == 404
    assert list(path.iterdir()) == []


def test_old_websocket_does_not_remove_replacement(monkeypatch):
    async def authorized(*args):
        return True
    monkeypatch.setattr(messages, "_device_is_authorized", authorized)
    device = "ws-device"
    token = create_access_token({"device_id": device, "sub": "user"})
    with TestClient(app) as client:
        with client.websocket_connect(f"/messages/ws/{device}?token={token}") as first:
            with client.websocket_connect(f"/messages/ws/{device}?token={token}") as second:
                current = messages.manager.active_connections[device]
                first.close()
                # A subsequent connection can still receive server-sent events.
                assert messages.manager.active_connections.get(device) is current
        assert device not in messages.manager.active_connections


def test_failed_commit_keeps_file_when_outcome_is_uncertain(upload_client):
    client, db, path, headers = upload_client
    async def fail_commit():
        raise RuntimeError("database unavailable")
    db.commit = fail_commit
    response = client.post("/files/upload", headers=headers, files={"file": ("x", b"data")})
    assert response.status_code == 500
    assert len(list(path.iterdir())) == 1
    assert next(path.iterdir()).read_bytes() == b"data"


def test_legacy_screen_frames_are_not_relayed(monkeypatch):
    sender, receiver = "screen-sender", "screen-receiver"
    async def authorized(*args):
        return True
    monkeypatch.setattr(messages, "_device_is_authorized", authorized)
    sender_token = create_access_token({"device_id": sender, "sub": "user"})
    receiver_token = create_access_token({"device_id": receiver, "sub": "user"})
    with TestClient(app) as client:
        with client.websocket_connect(f"/messages/ws/{receiver}?token={receiver_token}") as incoming:
            with client.websocket_connect(f"/messages/ws/{sender}?token={sender_token}") as outgoing:
                outgoing.send_json({"type": "screen_frame", "to_device_id": receiver, "frame": "private"})
                outgoing.send_json({"type": "screen_control", "to_device_id": receiver})
                # Sentinel is ordered after the blocked frames; the receiver
                # must see it first rather than any legacy screen traffic.
                outgoing.send_json({"type": "webrtc_signal", "to_device_id": receiver})
                assert incoming.receive_json()["type"] == "webrtc_signal"


def test_websocket_closes_on_binary_or_oversized_payload(monkeypatch):
    from starlette.websockets import WebSocketDisconnect
    async def authorized(*args):
        return True
    monkeypatch.setattr(messages, "_device_is_authorized", authorized)
    monkeypatch.setattr(messages, "MAX_SIGNAL_BYTES", 32)
    token = create_access_token({"device_id": "ws-limits", "sub": "user"})
    with TestClient(app) as client:
        with client.websocket_connect(f"/messages/ws/ws-limits?token={token}") as ws:
            ws.send_bytes(b"legacy-frame")
            with pytest.raises(WebSocketDisconnect) as exc:
                ws.receive_json()
            assert exc.value.code == 1008
        with client.websocket_connect(f"/messages/ws/ws-limits?token={token}") as ws:
            ws.send_text("a" * 33)
            with pytest.raises(WebSocketDisconnect) as exc:
                ws.receive_json()
            assert exc.value.code == 1009


def test_websocket_ignores_bad_json_shapes_without_closing(monkeypatch):
    async def authorized(*args):
        return True
    monkeypatch.setattr(messages, "_device_is_authorized", authorized)
    token = create_access_token({"device_id": "ws-json", "sub": "user"})
    with TestClient(app) as client:
        with client.websocket_connect(f"/messages/ws/ws-json?token={token}") as ws:
            ws.send_json(["not", "an", "object"])
            ws.send_json({"type": [], "to_device_id": "ws-json"})
            ws.send_json({"type": "call_offer", "to_device_id": "ws-json"})
            assert ws.receive_json()["type"] == "call_offer"


def test_legacy_multipart_rejects_extra_fields_and_files(upload_client):
    client, db, path, headers = upload_client
    assert client.post('/files/upload', headers=headers, files={'file': ('x', b'a')}, data={'extra': 'x'}).status_code == 400
    assert client.post('/files/upload', headers=headers, files=[('file', ('x', b'a')), ('file', ('y', b'b'))]).status_code == 400
    assert list(path.iterdir()) == [] and not db.records
