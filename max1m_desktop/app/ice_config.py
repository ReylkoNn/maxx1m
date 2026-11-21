"""STUN/TURN configuration with runtime ephemeral coturn REST support and IP-hiding Relay-Only mode."""
import os
import re
import threading
import time

DEFAULT_STUN_SERVERS = ("stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302")

_STUN_URI_RE = re.compile(r"^stun:(?P<host>[A-Za-z0-9._-]+)(?::(?P<port>[0-9]{1,5}))?$")
_TURN_URI_RE = re.compile(
    r"^(?P<scheme>turn|turns):(?P<host>[A-Za-z0-9._-]+)(?::(?P<port>[0-9]{1,5}))?"
    r"(?:\?transport=(?P<transport>udp|tcp))?$"
)
_RELAY_CANDIDATE_RE = re.compile(r"\btyp\s+relay\b")

_RUNTIME_LOCK = threading.Lock()
_RUNTIME_ICE_SERVERS: list[dict] = []
_RUNTIME_EXPIRES_AT: float | None = None
_UI_RELAY_ONLY: bool = False


def _valid_port(port_str):
    if port_str is None:
        return True
    port = int(port_str)
    return 1 <= port <= 65535


def _validate_stun_uri(uri: str) -> str:
    # aiortc ignores `stuns:` URIs; reject them explicitly rather than silently
    # running without the configured STUN endpoint.
    match = _STUN_URI_RE.fullmatch(uri) if isinstance(uri, str) and "@" not in uri else None
    if not match or not _valid_port(match.group("port")):
        raise ValueError("Некорректный STUN URL")
    return uri


def _validate_turn_uri(uri: str) -> str:
    match = _TURN_URI_RE.fullmatch(uri) if isinstance(uri, str) and "@" not in uri else None
    if not match or not _valid_port(match.group("port")):
        raise ValueError("Необходим корректный TURN URL, имя пользователя и пароль")
    if match.group("scheme") == "turns" and match.group("transport") not in (None, "tcp"):
        # aiortc silently skips `turns:` with UDP transport; fail closed.
        raise ValueError("TURN TLS (turns:) поддерживает только transport=tcp")
    return uri


def set_ui_relay_only(enabled: bool) -> None:
    """Set runtime UI preference for hiding local/public IP (`Relay-Only` via TURN)."""
    global _UI_RELAY_ONLY
    with _RUNTIME_LOCK:
        _UI_RELAY_ONLY = bool(enabled)


def get_ui_relay_only() -> bool:
    with _RUNTIME_LOCK:
        return bool(_UI_RELAY_ONLY)


def set_runtime_ice_config(payload: dict | None) -> list[dict]:
    """
    Validate and cache ephemeral ICE/TURN servers fetched from `GET /calls/ice-config`.
    Never logs credentials; rejects malformed URIs fail-closed.
    """
    global _RUNTIME_ICE_SERVERS, _RUNTIME_EXPIRES_AT
    if not payload or not isinstance(payload, dict):
        clear_runtime_ice_config()
        return []

    raw_servers = payload.get("ice_servers")
    if not isinstance(raw_servers, list):
        raise ValueError("Некорректный ответ /calls/ice-config")

    validated: list[dict] = []
    for entry in raw_servers:
        if not isinstance(entry, dict):
            continue
        urls_raw = entry.get("urls")
        if isinstance(urls_raw, str):
            urls_list = [urls_raw]
        elif isinstance(urls_raw, list):
            urls_list = [u for u in urls_raw if isinstance(u, str)]
        else:
            continue
        username = entry.get("username")
        credential = entry.get("credential")
        if username or credential or any(u.startswith(("turn:", "turns:")) for u in urls_list):
            turn_urls = [_validate_turn_uri(u.strip()) for u in urls_list if u.strip()]
            if not turn_urls or not isinstance(username, str) or not username or not isinstance(credential, str) or not credential:
                raise ValueError("Необходим корректный TURN URL, имя пользователя и пароль")
            validated.append({"urls": turn_urls, "username": username, "credential": credential})
        else:
            stun_urls = [_validate_stun_uri(u.strip()) for u in urls_list if u.strip()]
            for su in stun_urls:
                validated.append({"urls": [su]})

    exp_raw = payload.get("expires_at")
    exp_ts = float(exp_raw) if isinstance(exp_raw, (int, float)) and exp_raw > 0 else None

    with _RUNTIME_LOCK:
        _RUNTIME_ICE_SERVERS = validated
        _RUNTIME_EXPIRES_AT = exp_ts
    return [dict(item) for item in validated]


def clear_runtime_ice_config() -> None:
    global _RUNTIME_ICE_SERVERS, _RUNTIME_EXPIRES_AT
    with _RUNTIME_LOCK:
        _RUNTIME_ICE_SERVERS = []
        _RUNTIME_EXPIRES_AT = None


def runtime_ice_needs_refresh(margin_seconds: float = 300.0) -> bool:
    with _RUNTIME_LOCK:
        if not _RUNTIME_ICE_SERVERS:
            return True
        if _RUNTIME_EXPIRES_AT is None:
            return False
        return (time.time() + float(margin_seconds)) >= _RUNTIME_EXPIRES_AT


def _active_runtime_ice_servers() -> list[dict]:
    with _RUNTIME_LOCK:
        if not _RUNTIME_ICE_SERVERS:
            return []
        if _RUNTIME_EXPIRES_AT is not None and time.time() >= (_RUNTIME_EXPIRES_AT - 15.0):
            return []
        return [
            {
                "urls": list(s["urls"]),
                **({"username": s["username"], "credential": s["credential"]} if "username" in s else {}),
            }
            for s in _RUNTIME_ICE_SERVERS
        ]


def ice_relay_only(environ=None) -> bool:
    if environ is not None:
        raw = environ.get("MAX1M_ICE_RELAY_ONLY", "").strip().lower()
        if raw in ("", "0", "false", "no", "off"):
            return False
        if raw in ("1", "true", "yes", "on"):
            return True
        raise ValueError("Некорректное значение MAX1M_ICE_RELAY_ONLY")

    raw_env = os.environ.get("MAX1M_ICE_RELAY_ONLY", "").strip().lower()
    if raw_env in ("1", "true", "yes", "on"):
        return True
    if raw_env not in ("", "0", "false", "no", "off"):
        raise ValueError("Некорректное значение MAX1M_ICE_RELAY_ONLY")
    return get_ui_relay_only()


def filter_relay_sdp(sdp_text: str) -> str:
    """Keep only relay (`typ relay`) ICE candidate lines in an SDP blob."""
    if not isinstance(sdp_text, str):
        raise ValueError("Invalid SDP")
    lines = []
    for line in sdp_text.splitlines():
        if line.startswith("a=candidate:") and not _RELAY_CANDIDATE_RE.search(line):
            continue
        lines.append(line)
    suffix = "\r\n" if sdp_text.endswith("\r\n") else ("\n" if sdp_text.endswith("\n") else "")
    sep = "\r\n" if "\r\n" in sdp_text else "\n"
    return sep.join(lines) + (suffix if lines else "")


def ice_server_settings(environ=None):
    use_runtime = environ is None
    env = os.environ if environ is None else environ
    relay_only = ice_relay_only(environ)

    runtime_servers = _active_runtime_ice_servers() if use_runtime else []
    runtime_turns = [s for s in runtime_servers if "username" in s and "credential" in s]
    runtime_stuns = [s for s in runtime_servers if "username" not in s]

    configured_stun = env.get("MAX1M_STUN_URLS")
    if configured_stun is not None:
        stuns = [{"urls": [_validate_stun_uri(x.strip())]} for x in configured_stun.split(",") if x.strip()]
    elif runtime_stuns:
        stuns = runtime_stuns
    else:
        stuns = [] if relay_only else [{"urls": [_validate_stun_uri(x)]} for x in DEFAULT_STUN_SERVERS]

    # Do not contact STUN servers when relay-only mode is requested.
    servers = [] if relay_only else list(stuns)

    raw_turn = env.get("MAX1M_TURN_URLS", "").strip() or env.get("MAX1M_TURN_URL", "").strip()
    username = env.get("MAX1M_TURN_USERNAME", "")
    credential = env.get("MAX1M_TURN_PASSWORD", "")
    if raw_turn or username or credential:
        turn_urls = [_validate_turn_uri(x.strip()) for x in raw_turn.split(",") if x.strip()]
        if not turn_urls or not username or not credential:
            raise ValueError("Необходим корректный TURN URL, имя пользователя и пароль")
        servers.append({"urls": turn_urls, "username": username, "credential": credential})
    elif runtime_turns:
        servers.extend(runtime_turns)
    elif relay_only:
        raise ValueError("Для режима MAX1M_ICE_RELAY_ONLY необходим настроенный TURN сервер")

    return servers
