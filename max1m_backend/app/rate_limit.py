"""
Rate limiting для Max1m backend.

Вынесен в отдельный модуль, чтобы избежать циклического импорта:
main.py импортирует роутеры, роутеры импортируют limiter —
если limiter жил бы в main.py, получился бы цикл.
Здесь limiter создаётся без зависимостей от app, поэтому безопасен
для импорта из любого места.
"""

import ipaddress
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from .config import settings


def _parse_trusted_proxies(raw: str) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    if not raw:
        return networks
    for token in raw.split(","):
        cleaned = token.strip()
        if not cleaned:
            continue
        try:
            networks.append(ipaddress.ip_network(cleaned, strict=False))
        except ValueError:
            continue
    return networks


def _ip_in_networks(ip_str: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def resolve_client_ip(request: Request) -> str:
    """Resolve client IP for rate limiting, trusting X-Forwarded-For ONLY from TRUSTED_PROXY_IPS."""
    peer_ip = get_remote_address(request) or "127.0.0.1"
    trusted = _parse_trusted_proxies(getattr(settings, "TRUSTED_PROXY_IPS", ""))
    if not trusted or not _ip_in_networks(peer_ip, trusted):
        return peer_ip

    xff = request.headers.get("x-forwarded-for")
    if xff:
        hops = [part.strip() for part in xff.split(",") if part.strip()]
        # Walk right-to-left: return the rightmost valid IP that is NOT itself a trusted proxy.
        last_valid_ip = None
        for candidate in reversed(hops):
            try:
                parsed = str(ipaddress.ip_address(candidate))
            except ValueError:
                # Stop walking on a malformed hop so spoofed prefixes are never trusted.
                break
            last_valid_ip = parsed
            if not _ip_in_networks(parsed, trusted):
                return parsed
        if last_valid_ip is not None:
            return last_valid_ip

    x_real_ip = (request.headers.get("x-real-ip") or "").strip()
    if x_real_ip:
        try:
            return str(ipaddress.ip_address(x_real_ip))
        except ValueError:
            pass
    return peer_ip


# key_func=resolve_client_ip — лимитим по IP клиента (с безопасной поддержкой
# доверенного reverse proxy через TRUSTED_PROXY_IPS).
# default_limits — мягкая защита "по умолчанию" для эндпоинтов без явного лимита,
# чтобы забытое декоратором не осталось полностью открытым.
limiter = Limiter(key_func=resolve_client_ip, default_limits=["200/minute"])
