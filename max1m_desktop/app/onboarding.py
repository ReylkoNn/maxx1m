"""
1-Click Team Onboarding (`max1m-join://`) & Pre-Login TLS SPKI Pin Provisioning.

Allows an administrator or colleague to share a single self-contained string:
    max1m-join://<base64url_nopad(canonical_json)>
or query-style URI:
    max1m-join://join?server=https://chat.company.ru&pin=sha256/...&invite=INV-...

Security guarantees:
- Strictly validates `server_url` (`validate_server_url` — HTTPS required except loopback).
- Strictly validates every `spki_pin` (`normalize_spki_pin` — canonical `sha256/<44-char b64>`).
- Persists `spki_pins` into `local_state.json["tls_spki_pins"][host]` BEFORE the very
  first registration or login TLS handshake is attempted, eliminating TOFU MITM risk
  without requiring manual OS environment variables.
- Promotes pre-login pins into authenticated `tls_pins.enc` (`SecureStorage.save_tls_pins`)
  immediately upon successful registration or login for anti-downgrade protection.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from app.client_api import validate_server_url
from app.tls_pinning import normalize_host, normalize_spki_pin

JOIN_SCHEME_PREFIX = "max1m-join://"
_INVITE_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,128}$")
MAX_JOIN_STRING_LEN = 2048


@dataclass(frozen=True)
class JoinConfig:
    server_url: str
    spki_pins: Tuple[str, ...]
    invite_code: str = ""
    node_title: str = ""


def build_join_link(
    server_url: str,
    spki_pins: Iterable[str],
    *,
    invite_code: str = "",
    node_title: str = "",
) -> str:
    """Build a compact, URL-safe `max1m-join://...` onboarding string."""
    if not isinstance(server_url, str) or not server_url.strip():
        raise ValueError("Не указан адрес сервера")
    clean_url = server_url.strip().rstrip("/")
    ok, err = validate_server_url(clean_url)
    if not ok:
        raise ValueError(err or "Некорректный URL сервера")

    normalized_pins: List[str] = []
    for raw_pin in spki_pins or ():
        if not isinstance(raw_pin, str) or not raw_pin.strip():
            continue
        npin = normalize_spki_pin(raw_pin.strip())
        if npin not in normalized_pins:
            normalized_pins.append(npin)
    if not normalized_pins or len(normalized_pins) > 4:
        raise ValueError("Укажите от 1 до 4 корректных TLS SPKI пинов (sha256/...)")

    clean_invite = (invite_code or "").strip()
    if clean_invite and not _INVITE_RE.fullmatch(clean_invite):
        raise ValueError("Некорректный формат инвайт-кода")

    clean_title = re.sub(r"[\x00-\x1f\x7f]", "", (node_title or "").strip())[:64]

    payload = {
        "v": 1,
        "s": clean_url,
        "p": normalized_pins,
    }
    if clean_invite:
        payload["i"] = clean_invite
    if clean_title:
        payload["t"] = clean_title

    raw_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    token = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
    return f"{JOIN_SCHEME_PREFIX}{token}"


def parse_join_link(raw_text: str) -> JoinConfig:
    """Parse and validate a `max1m-join://` string (compact base64url JSON or query URI)."""
    if not isinstance(raw_text, str):
        raise ValueError("Ожидалась строка подключения max1m-join://")
    text = raw_text.strip()
    if not text or len(text) > MAX_JOIN_STRING_LEN:
        raise ValueError("Строка подключения пуста или превышает допустимый размер")
    if not text.lower().startswith(JOIN_SCHEME_PREFIX):
        raise ValueError("Строка подключения должна начинаться с max1m-join://")

    body = text[len(JOIN_SCHEME_PREFIX) :].strip()
    if not body:
        raise ValueError("Пустая строка подключения max1m-join://")

    server_url = ""
    raw_pins: List[str] = []
    invite_code = ""
    node_title = ""

    if "?" in body or body.lower().startswith("join"):
        parsed = urllib.parse.urlsplit(text)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        server_url = (qs.get("server") or qs.get("s") or [""])[0].strip()
        for key in ("pin", "pins", "p"):
            for item in qs.get(key, []):
                raw_pins.extend(p.strip() for p in item.split(",") if p.strip())
        invite_code = (qs.get("invite") or qs.get("i") or [""])[0].strip()
        node_title = (qs.get("title") or qs.get("t") or [""])[0].strip()
    else:
        body_clean = body.rstrip("/")
        pad = "=" * ((4 - len(body_clean) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode((body_clean + pad).encode("ascii"))
            obj = json.loads(decoded.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Повреждённый код подключения max1m-join://") from exc
        if not isinstance(obj, dict) or obj.get("v") != 1:
            raise ValueError("Неподдерживаемая версия строки подключения max1m-join://")
        server_url = obj.get("s") if isinstance(obj.get("s"), str) else ""
        pins_field = obj.get("p")
        if isinstance(pins_field, list) and all(isinstance(x, str) for x in pins_field):
            raw_pins = list(pins_field)
        invite_code = obj.get("i", "") if isinstance(obj.get("i", ""), str) else ""
        node_title = obj.get("t", "") if isinstance(obj.get("t", ""), str) else ""

    clean_url = server_url.strip().rstrip("/")
    ok, err = validate_server_url(clean_url)
    if not ok:
        raise ValueError(err or "Некорректный адрес сервера в строке подключения")

    normalized_pins: List[str] = []
    for p in raw_pins:
        npin = normalize_spki_pin(p)
        if npin not in normalized_pins:
            normalized_pins.append(npin)
    if not normalized_pins or len(normalized_pins) > 4:
        raise ValueError("В строке подключения отсутствует корректный TLS SPKI пин")

    clean_invite = invite_code.strip()
    if clean_invite and not _INVITE_RE.fullmatch(clean_invite):
        raise ValueError("Некорректный инвайт-код в строке подключения")

    clean_title = re.sub(r"[\x00-\x1f\x7f]", "", node_title.strip())[:64]
    return JoinConfig(
        server_url=clean_url,
        spki_pins=tuple(normalized_pins),
        invite_code=clean_invite,
        node_title=clean_title,
    )


def save_prelogin_spki_pins(server_url: str, spki_pins: Iterable[str], storage_obj=None) -> List[str]:
    """Persist verified SPKI pins for `server_url` into `local_state.json` prior to login/register."""
    from app.secure_storage import SecureStorage

    store = storage_obj or SecureStorage
    host = normalize_host(server_url)
    normalized: List[str] = []
    for p in spki_pins:
        if isinstance(p, str) and p.strip():
            npin = normalize_spki_pin(p.strip())
            if npin not in normalized:
                normalized.append(npin)
    if not normalized:
        return []

    try:
        local_data = store.load_local_state()
    except Exception:
        local_data = {}
    if not isinstance(local_data, dict):
        local_data = {}

    pins_map = dict(local_data.get("tls_spki_pins") or {})
    existing = [normalize_spki_pin(x) for x in pins_map.get(host, []) if isinstance(x, str)]
    for npin in normalized:
        if npin not in existing:
            existing.append(npin)
    pins_map[host] = existing
    local_data["tls_spki_pins"] = pins_map
    store.save_local_state(local_data)
    return existing


def promote_prelogin_spki_pins(username: str, server_url: str, storage_obj=None) -> List[str]:
    """Copy any pre-login SPKI pins for `server_url` into authenticated `tls_pins.enc`."""
    if not isinstance(username, str) or not username or not isinstance(server_url, str) or not server_url:
        return []
    from app.secure_storage import SecureStorage

    store = storage_obj or SecureStorage
    host = normalize_host(server_url)
    local_data = store.load_local_state()
    raw_map = local_data.get("tls_spki_pins") if isinstance(local_data, dict) else None
    pre_pins = [normalize_spki_pin(x) for x in (raw_map or {}).get(host, []) if isinstance(x, str)]
    if not pre_pins:
        return []

    auth_map = store.load_tls_pins(username)
    merged = list(auth_map.get(host, []))
    changed = False
    for npin in pre_pins:
        if npin not in merged:
            merged.append(npin)
            changed = True
    if changed:
        auth_map[host] = merged
        store.save_tls_pins(username, auth_map)
    return merged
