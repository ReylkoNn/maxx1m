"""
TLS SubjectPublicKeyInfo (SPKI) Pinning for HTTPS and WSS connections.

Protects desktop clients against rogue/compelled Certificate Authorities (MITM
TLS interception on ISP / DPI / corporate proxies):
- Verifies SHA-256(SubjectPublicKeyInfo DER) of the server's leaf X.509 certificate
  DURING the TLS handshake — strictly BEFORE any HTTP method, URL path, password
  payload, or WebSocket `Authorization: Bearer` token is written to the socket.
- Supports multiple pins per host (primary + backup key for seamless rotation).
- Merges environment policy (`MAX1M_TLS_SPKI_PINS`), authenticated per-profile
  `tls_pins.enc` (anti-downgrade), and pre-login `local_state.json` pins.
"""

import base64
import binascii
import hashlib
import os
import re
import socket
import ssl
import threading
import urllib.parse
from typing import Dict, Iterable, List, Optional, Set, Tuple

_HOST_RE = re.compile(r"^[a-z0-9._:\[\]-]{1,253}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_INSTALL_LOCK = threading.Lock()
_URLLIB3_HOOK_INSTALLED = False


def _read_der_tlv(buf: bytes, offset: int) -> Tuple[int, int, int, int]:
    """Return (tag, value_start, value_end, next_offset) for one ASN.1 DER element."""
    n = len(buf)
    if offset >= n:
        raise ValueError("Truncated ASN.1 DER")
    tag = buf[offset]
    pos = offset + 1
    if (tag & 0x1F) == 0x1F:
        # High-tag-number form
        while pos < n and (buf[pos] & 0x80):
            pos += 1
        if pos >= n:
            raise ValueError("Truncated ASN.1 tag")
        pos += 1
    if pos >= n:
        raise ValueError("Truncated ASN.1 length")
    first_len = buf[pos]
    pos += 1
    if (first_len & 0x80) == 0:
        length = first_len
    else:
        num_octets = first_len & 0x7F
        if num_octets == 0 or num_octets > 4 or pos + num_octets > n:
            raise ValueError("Invalid ASN.1 DER length")
        length = int.from_bytes(buf[pos : pos + num_octets], "big")
        pos += num_octets
    val_start = pos
    val_end = val_start + length
    if val_end > n:
        raise ValueError("ASN.1 element exceeds buffer")
    return tag, val_start, val_end, val_end


def _extract_spki_der_asn1(cert_der: bytes) -> bytes:
    """RFC 5280 ASN.1 DER walker extracting exact raw SubjectPublicKeyInfo TLV bytes."""
    if not isinstance(cert_der, (bytes, bytearray)) or len(cert_der) < 32:
        raise ValueError("Invalid X.509 DER certificate")
    raw = bytes(cert_der)
    outer_tag, outer_start, outer_end, _ = _read_der_tlv(raw, 0)
    if outer_tag != 0x30:
        raise ValueError("Certificate outer element is not SEQUENCE")
    tbs_tag, tbs_start, tbs_end, _ = _read_der_tlv(raw, outer_start)
    if tbs_tag != 0x30 or tbs_end > outer_end:
        raise ValueError("TBSCertificate is not SEQUENCE")

    cursor = tbs_start
    first_tag, _, _, next_cursor = _read_der_tlv(raw, cursor)
    if first_tag == 0xA0:
        # Explicit [0] version present (X.509 v2 / v3)
        cursor = next_cursor

    # Skip serialNumber, signature, issuer, validity, subject (5 elements)
    for _ in range(5):
        if cursor >= tbs_end:
            raise ValueError("Truncated TBSCertificate before SubjectPublicKeyInfo")
        _, _, _, cursor = _read_der_tlv(raw, cursor)

    if cursor >= tbs_end:
        raise ValueError("Missing SubjectPublicKeyInfo")
    spki_start = cursor
    spki_tag, _, _, spki_end = _read_der_tlv(raw, spki_start)
    if spki_tag != 0x30 or spki_end > tbs_end:
        raise ValueError("SubjectPublicKeyInfo is not SEQUENCE")
    return raw[spki_start:spki_end]


def extract_spki_der_from_cert_der(cert_der: bytes) -> bytes:
    """Extract SubjectPublicKeyInfo DER bytes from a DER-encoded X.509 certificate."""
    if not isinstance(cert_der, (bytes, bytearray)) or not cert_der:
        raise ValueError("Empty certificate DER")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        cert = x509.load_der_x509_certificate(bytes(cert_der))
        return cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except ImportError:
        return _extract_spki_der_asn1(bytes(cert_der))


def compute_spki_pin(cert_der: bytes) -> str:
    """Compute canonical RFC 7469 pin string `sha256/<base64>` from X.509 DER bytes."""
    spki_der = extract_spki_der_from_cert_der(cert_der)
    digest = hashlib.sha256(spki_der).digest()
    return "sha256/" + base64.b64encode(digest).decode("ascii")


def normalize_spki_pin(pin: str) -> str:
    """Validate and canonicalize an SPKI pin (`sha256/<b64>` or 64-char hex) to `sha256/<b64>`."""
    if not isinstance(pin, str):
        raise ValueError("Некорректный формат SPKI-отпечатка")
    s = pin.strip()
    if not s:
        raise ValueError("Пустой SPKI-отпечаток")
    if s.lower().startswith("sha256/"):
        b64_part = s[7:].strip()
        try:
            raw = base64.b64decode(b64_part, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Некорректный Base64 в SPKI-отпечатке") from exc
        if len(raw) != 32:
            raise ValueError("SPKI SHA-256 отпечаток должен иметь длину 32 байта")
        return "sha256/" + base64.b64encode(raw).decode("ascii")

    hex_cand = s[7:].strip() if s.lower().startswith("sha256:") else s
    hex_clean = hex_cand.replace(":", "")
    if _HEX64_RE.fullmatch(hex_clean):
        raw = bytes.fromhex(hex_clean)
        return "sha256/" + base64.b64encode(raw).decode("ascii")

    # Also allow raw 44-char canonical Base64 without prefix
    try:
        raw = base64.b64decode(s, validate=True)
        if len(raw) == 32 and base64.b64encode(raw).decode("ascii") == s:
            return "sha256/" + s
    except (binascii.Error, ValueError):
        pass
    raise ValueError("Ожидается формат sha256/<Base64> или 64 hex-символа")


def normalize_host(host_or_url: str) -> str:
    if not isinstance(host_or_url, str) or not host_or_url.strip():
        raise ValueError("Некорректный хост")
    raw = host_or_url.strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        host = (parsed.hostname or "").strip().lower()
    else:
        host = raw.strip().lower()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
    if not host or not _HOST_RE.fullmatch(host):
        raise ValueError("Некорректный хост для SPKI pinning")
    return host


def parse_env_spki_pins(raw_env: Optional[str] = None) -> Tuple[Set[str], Dict[str, Set[str]]]:
    """Parse MAX1M_TLS_SPKI_PINS into (wildcard_pins, {host: {pins}}). Fail-closed on syntax error."""
    text = os.environ.get("MAX1M_TLS_SPKI_PINS", "") if raw_env is None else raw_env
    if not isinstance(text, str) or not text.strip():
        return set(), {}

    wildcard_pins: Set[str] = set()
    by_host: Dict[str, Set[str]] = {}

    # If '=' is used for host mapping (`host=sha256/AAA=|sha256/BBB=;host2=...`),
    # distinguish `host=sha256/...` from Base64 trailing `=` padding!
    entries = [chunk.strip() for chunk in text.split(";") if chunk.strip()]
    for entry in entries:
        eq_pos = entry.find("=")
        has_host_prefix = False
        if eq_pos > 0:
            lhs = entry[:eq_pos].strip()
            # Base64 pins start with sha256/ or 64-hex, whereas hostnames do not contain '/'
            if "/" not in lhs and not _HEX64_RE.fullmatch(lhs.replace(":", "")):
                has_host_prefix = True
        if has_host_prefix:
            host_key = lhs.lower()
            rhs = entry[eq_pos + 1 :].strip()
            raw_pins = [p.strip() for p in re.split(r"[|,]", rhs) if p.strip()]
            if not raw_pins:
                raise ValueError("Пустой список пинов для хоста в MAX1M_TLS_SPKI_PINS")
            normalized = {normalize_spki_pin(p) for p in raw_pins}
            if host_key == "*":
                wildcard_pins.update(normalized)
            else:
                norm_h = normalize_host(host_key)
                by_host.setdefault(norm_h, set()).update(normalized)
        else:
            raw_pins = [p.strip() for p in entry.split(",") if p.strip()]
            for p in raw_pins:
                wildcard_pins.add(normalize_spki_pin(p))

    return wildcard_pins, by_host


def _load_persisted_host_pins(host: str) -> Set[str]:
    """Load persisted SPKI pins for `host`, giving authenticated `tls_pins.enc` anti-downgrade priority."""
    pins: Set[str] = set()
    try:
        from app.secure_storage import SecureStorage
        from app.state import state

        active_user = getattr(state, "username", None)
        if isinstance(active_user, str) and active_user:
            auth_map = SecureStorage.load_tls_pins(active_user)
            if host in auth_map and auth_map[host]:
                return {normalize_spki_pin(p) for p in auth_map[host]}

        local_state = SecureStorage.load_local_state()
        raw_map = local_state.get("tls_spki_pins")
        if isinstance(raw_map, dict):
            host_list = raw_map.get(host)
            if isinstance(host_list, list):
                for p in host_list:
                    pins.add(normalize_spki_pin(p))
    except Exception:
        # Never swallow corruption if authenticated tls_pins.enc explicitly failed!
        raise
    return pins


def resolve_spki_pins_for_host(host: str) -> Set[str]:
    """Return the required SPKI pin set for `host` (empty set if unpinned)."""
    norm_host = normalize_host(host)
    try:
        wildcard_env, host_env = parse_env_spki_pins()
    except ValueError as exc:
        raise ssl.SSLCertVerificationError(f"Некорректная конфигурация MAX1M_TLS_SPKI_PINS: {exc}") from exc

    combined: Set[str] = set()
    if wildcard_env:
        combined.update(wildcard_env)
    if norm_host in host_env:
        combined.update(host_env[norm_host])

    try:
        persisted = _load_persisted_host_pins(norm_host)
        combined.update(persisted)
    except Exception as exc:
        raise ssl.SSLCertVerificationError(f"Повреждено хранилище TLS SPKI пинов: {type(exc).__name__}") from exc

    return combined


def verify_cert_der_against_pins(cert_der: Optional[bytes], expected_pins: Iterable[str], host: str = "") -> str:
    pins = set(expected_pins)
    if not cert_der:
        raise ssl.SSLCertVerificationError(f"Сервер {host} не предоставил X.509 сертификат для SPKI проверки")
    try:
        actual_pin = compute_spki_pin(cert_der)
    except Exception as exc:
        raise ssl.SSLCertVerificationError(f"Не удалось извлечь SPKI ключ сертификата {host}: {exc}") from exc
    if pins and actual_pin not in pins:
        raise ssl.SSLCertVerificationError(
            f"TLS SPKI pin mismatch для {host}: получен {actual_pin}, соединение заблокировано (возможна MITM-подмена сертификата)"
        )
    return actual_pin


def verify_ssl_peer_for_host(ssl_obj_or_sock, host: str) -> Optional[str]:
    """Verify peer leaf cert SPKI against configured pins for `host`. Raises SSLCertVerificationError on mismatch."""
    expected = resolve_spki_pins_for_host(host)
    if not expected:
        return None
    if ssl_obj_or_sock is None or not hasattr(ssl_obj_or_sock, "getpeercert"):
        raise ssl.SSLCertVerificationError(f"Отсутствует TLS-сокет для проверки SPKI пина {host}")
    cert_der = ssl_obj_or_sock.getpeercert(binary_form=True)
    return verify_cert_der_against_pins(cert_der, expected, host=host)


def build_pinned_ssl_context(url_or_host: str, *, base_context: Optional[ssl.SSLContext] = None) -> Optional[ssl.SSLContext]:
    """
    Build an SSLContext that enforces SPKI pins INSIDE `do_handshake()` before any
    application data (HTTP headers, passwords, WS Bearer tokens) can leave the client.
    Returns None when scheme is not TLS or when no SPKI pins are configured for the host.
    """
    if "://" in url_or_host:
        parsed = urllib.parse.urlsplit(url_or_host.strip())
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("https", "wss"):
            return None
        host = normalize_host(parsed.hostname or "")
    else:
        host = normalize_host(url_or_host)

    expected_pins = frozenset(resolve_spki_pins_for_host(host))
    if not expected_pins:
        return None

    ctx = base_context if base_context is not None else ssl.create_default_context()

    class _PinnedSSLObject(ssl.SSLObject):
        def do_handshake(self):
            super().do_handshake()
            cert_der = self.getpeercert(binary_form=True)
            verify_cert_der_against_pins(cert_der, expected_pins, host=host)

    class _PinnedSSLSocket(ssl.SSLSocket):
        def do_handshake(self, *args, **kwargs):
            res = super().do_handshake(*args, **kwargs)
            cert_der = self.getpeercert(binary_form=True)
            verify_cert_der_against_pins(cert_der, expected_pins, host=host)
            return res

    ctx.sslobject_class = _PinnedSSLObject
    ctx.sslsocket_class = _PinnedSSLSocket
    return ctx


def install_urllib3_spki_enforcement() -> None:
    """
    Hook urllib3's HTTPSConnection.connect idempotently so EVERY real `requests` HTTPS
    call verifies SPKI pins immediately after TLS handshake and BEFORE sending any HTTP
    request line, headers, or body — without interfering with `requests.*` unit-test mocks.
    """
    global _URLLIB3_HOOK_INSTALLED
    if _URLLIB3_HOOK_INSTALLED:
        return
    with _INSTALL_LOCK:
        if _URLLIB3_HOOK_INSTALLED:
            return
        import urllib3.connection

        orig_connect = urllib3.connection.HTTPSConnection.connect

        def _pinned_https_connect(self):
            # Validate env/store syntax BEFORE even opening TCP/TLS!
            target_host = getattr(self, "host", "") or ""
            expected = resolve_spki_pins_for_host(target_host) if target_host else set()
            orig_connect(self)
            if expected:
                try:
                    cert_der = self.sock.getpeercert(binary_form=True) if self.sock is not None else None
                    verify_cert_der_against_pins(cert_der, expected, host=target_host)
                except BaseException:
                    try:
                        if self.sock is not None:
                            self.sock.close()
                    except Exception:
                        pass
                    self.sock = None
                    raise

        urllib3.connection.HTTPSConnection.connect = _pinned_https_connect
        _URLLIB3_HOOK_INSTALLED = True


def probe_server_spki_pin(server_url: str, timeout: float = 5.0) -> str:
    """Connect to `https://host[:port]` via TLS without sending any credentials and return its `sha256/<b64>` SPKI pin."""
    parsed = urllib.parse.urlsplit((server_url or "").strip())
    if (parsed.scheme or "").lower() != "https" or not parsed.hostname:
        raise ValueError("SPKI pinning поддерживается только для https:// серверов")
    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)
            if not cert_der:
                raise ValueError("Сервер не предоставил TLS-сертификат")
            return compute_spki_pin(cert_der)
