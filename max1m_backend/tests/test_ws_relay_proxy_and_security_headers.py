"""Regression tests for Package #7 backend features:
- WebSocket relay nesting-depth & non-finite JSON DoS protection (never disconnects victim socket)
- Trusted reverse-proxy client IP resolution for rate limiting (TRUSTED_PROXY_IPS, right-to-left XFF walk)
- Security response headers (nosniff, DENY, no-referrer, no-store), encrypted file download headers,
  default-disabled OpenAPI docs (ENABLE_API_DOCS=False), and Bearer token log redaction
"""
import base64
import logging
import os
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import models
from app.api import files as files_api
from app.config import settings
from app.database import AsyncSessionLocal
from app.logging_security import TokenRedactionFilter
from app.main import app
from app.rate_limit import limiter, resolve_client_ip


@pytest.fixture(autouse=True)
def _reset_limiter():
    limiter.reset()
    yield
    limiter.reset()


def _seed_invite(client: TestClient) -> str:
    code = f"INV-{uuid.uuid4().hex[:12].upper()}"

    async def _ins():
        async with AsyncSessionLocal() as db:
            db.add(models.InviteCode(code=code))
            await db.commit()

    client.portal.call(_ins)
    return code


def _register_and_login(client: TestClient, invite: str, prefix: str, password: str = "StrongPass123!"):
    username = f"{prefix}_{uuid.uuid4().hex[:8]}"
    reg = client.post(
        "/auth/register",
        json={
            "username": username,
            "password": password,
            "invite_code": invite,
            "device_name": f"{prefix}-dev",
            "public_key": base64.b64encode(os.urandom(32)).decode("ascii"),
            "fingerprint": f"fp-{uuid.uuid4().hex}",
        },
    )
    assert reg.status_code == 201, reg.text
    dev_id = reg.json()["device_id"]

    login = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
            "device_id": dev_id,
        },
    )
    assert login.status_code == 200, login.text
    return dev_id, login.json()["access_token"]


def test_deep_or_non_finite_ws_relay_never_disconnects_recipient():
    with TestClient(app) as client:
        sender_dev, sender_token = _register_and_login(client, _seed_invite(client), "ws_snd")
        victim_dev, victim_token = _register_and_login(client, _seed_invite(client), "ws_vic")

        with client.websocket_connect(
            f"/messages/ws/{victim_dev}",
            headers={"Authorization": f"Bearer {victim_token}"},
        ) as ws_victim, client.websocket_connect(
            f"/messages/ws/{sender_dev}",
            headers={"Authorization": f"Bearer {sender_token}"},
        ) as ws_sender:
            # 1. Deeply nested JSON (> MAX_RELAY_JSON_DEPTH=16) dropped on sender side
            nested: list | str = "leaf"
            for _ in range(40):
                nested = [nested]
            ws_sender.send_json(
                {
                    "type": "webrtc_signal",
                    "to_device_id": victim_dev,
                    "payload": nested,
                }
            )

            # 2. Non-finite JSON constants (NaN / Infinity) rejected on parse
            ws_sender.send_text(
                f'{{"type":"webrtc_signal","to_device_id":"{victim_dev}","payload":{{"x":NaN}}}}'
            )

            # 3. Malformed field types (non-string encrypted_call / oversized call_id)
            ws_sender.send_json(
                {
                    "type": "call_offer",
                    "to_device_id": victim_dev,
                    "encrypted_call": {"not": "a-string"},
                }
            )
            ws_sender.send_json(
                {
                    "type": "call_ended",
                    "to_device_id": victim_dev,
                    "call_id": "x" * 128,
                }
            )

            # 4. Victim WebSocket must remain open and receive valid signaling!
            ws_sender.send_json(
                {
                    "type": "webrtc_signal",
                    "to_device_id": victim_dev,
                    "call_id": "call-ok-1",
                    "payload": {"sdp": "v=0"},
                }
            )
            received = ws_victim.receive_json()
            assert received == {
                "type": "webrtc_signal",
                "to_device_id": victim_dev,
                "from_device_id": sender_dev,
                "call_id": "call-ok-1",
                "payload": {"sdp": "v=0"},
            }


def test_trusted_proxy_client_ip_resolution(monkeypatch):
    def _make_req(peer_ip: str, headers: dict[str, str]):
        lower = {k.lower(): v for k, v in headers.items()}
        return SimpleNamespace(
            client=SimpleNamespace(host=peer_ip),
            headers=lower,
        )

    # Default: TRUSTED_PROXY_IPS="" ignores X-Forwarded-For / X-Real-IP completely
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "")
    req_untrusted_default = _make_req(
        "127.0.0.1",
        {"X-Forwarded-For": "203.0.113.10", "X-Real-IP": "203.0.113.11"},
    )
    assert resolve_client_ip(req_untrusted_default) == "127.0.0.1"

    # Configured trusted proxies: right-to-left hop walk skips trusted proxy hops
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "127.0.0.1, ::1, 10.0.0.0/8")
    req_chain = _make_req(
        "127.0.0.1",
        {"X-Forwarded-For": "198.51.100.25, 10.1.2.3"},
    )
    assert resolve_client_ip(req_chain) == "198.51.100.25"

    # Malformed spoofed prefix before real client IP stops right-to-left walk safely
    req_spoof_prefix = _make_req(
        "127.0.0.1",
        {"X-Forwarded-For": "not-an-ip, 203.0.113.44"},
    )
    assert resolve_client_ip(req_spoof_prefix) == "203.0.113.44"

    # Direct untrusted peer cannot spoof X-Forwarded-For even when TRUSTED_PROXY_IPS is set
    req_direct_attacker = _make_req(
        "192.0.2.99",
        {"X-Forwarded-For": "198.51.100.1"},
    )
    assert resolve_client_ip(req_direct_attacker) == "192.0.2.99"

    # Fallback to X-Real-IP when X-Forwarded-For is absent
    req_real_ip = _make_req("127.0.0.1", {"X-Real-IP": "2001:db8::42"})
    assert resolve_client_ip(req_real_ip) == "2001:db8::42"


def test_security_headers_docs_disabled_and_bearer_log_redaction(tmp_path, monkeypatch):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(files_api, "UPLOAD_DIR", upload_dir)

    with TestClient(app) as client:
        root_resp = client.get("/")
        assert root_resp.status_code == 200
        assert root_resp.headers.get("x-content-type-options") == "nosniff"
        assert root_resp.headers.get("x-frame-options") == "DENY"
        assert root_resp.headers.get("referrer-policy") == "no-referrer"
        assert root_resp.headers.get("cache-control") == "no-store"

        # Interactive OpenAPI endpoints disabled by default
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert client.get("/openapi.json").status_code == 404

        # File download response carries attachment + no-store + nosniff
        _, token = _register_and_login(client, _seed_invite(client), "hdr_usr")
        auth_h = {"Authorization": f"Bearer {token}"}
        att_id = str(uuid.uuid4())
        up = client.post(
            f"/files/upload-reliable/{att_id}",
            content=b"CIPHERTEXT_PAYLOAD",
            headers={**auth_h, "Content-Type": "application/octet-stream"},
        )
        assert up.status_code in (200, 201), up.text
        fid = up.json()["file_id"]
        dl = client.get(f"/files/{fid}", headers=auth_h)
        assert dl.status_code == 200
        assert dl.headers.get("content-disposition") == 'attachment; filename="encrypted.bin"'
        assert dl.headers.get("cache-control") == "no-store"
        assert dl.headers.get("x-content-type-options") == "nosniff"

    # Bearer & query token log redaction
    filt = TokenRedactionFilter()
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="GET %s Authorization: %s",
        args=("/messages/ws/dev1?token=eyJhbGciOiJIUzI1NiJ9.sec.sig", "Bearer eyJhbGciOiJIUzI1NiJ9.jwt.sig"),
        exc_info=None,
    )
    assert filt.filter(record) is True
    formatted = record.getMessage()
    assert "eyJhbGciOiJIUzI1NiJ9" not in formatted
    assert "token=[REDACTED]" in formatted
    assert "Bearer [REDACTED]" in formatted
