#!/usr/bin/env python3
"""
Standalone VPS utility to compute the server's X.509 SubjectPublicKeyInfo (SPKI)
SHA-256 pin and emit ready-to-share `max1m-join://` onboarding links for employees.

Uses ONLY Python 3.10+ standard library so it runs directly on any clean Linux VPS.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import socket
import ssl
import sys
import urllib.parse
from pathlib import Path
from typing import Iterable, List, Tuple

JOIN_SCHEME_PREFIX = "max1m-join://"
_INVITE_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,128}$")


def _read_der_tlv(buf: bytes, offset: int) -> Tuple[int, int, int, int]:
    n = len(buf)
    if offset >= n:
        raise ValueError("Truncated ASN.1 DER")
    tag = buf[offset]
    pos = offset + 1
    if (tag & 0x1F) == 0x1F:
        while pos < n and (buf[pos] & 0x80):
            pos += 1
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
    val_end = pos + length
    if val_end > n:
        raise ValueError("ASN.1 element exceeds buffer")
    return tag, pos, val_end, val_end


def extract_spki_pin_from_der(cert_der: bytes) -> str:
    outer_tag, outer_start, outer_end, _ = _read_der_tlv(cert_der, 0)
    if outer_tag != 0x30:
        raise ValueError("Certificate outer element is not SEQUENCE")
    tbs_tag, tbs_start, tbs_end, _ = _read_der_tlv(cert_der, outer_start)
    if tbs_tag != 0x30 or tbs_end > outer_end:
        raise ValueError("TBSCertificate is not SEQUENCE")
    cursor = tbs_start
    first_tag, _, _, next_cursor = _read_der_tlv(cert_der, cursor)
    if first_tag == 0xA0:
        cursor = next_cursor
    for _ in range(5):
        _, _, _, cursor = _read_der_tlv(cert_der, cursor)
    spki_start = cursor
    spki_tag, _, _, spki_end = _read_der_tlv(cert_der, cursor)
    if spki_tag != 0x30 or spki_end > tbs_end:
        raise ValueError("SubjectPublicKeyInfo is not SEQUENCE")
    digest = hashlib.sha256(cert_der[spki_start:spki_end]).digest()
    return "sha256/" + base64.b64encode(digest).decode("ascii")


def probe_live_spki_pin(server_url: str, timeout: float = 8.0) -> str:
    parsed = urllib.parse.urlsplit(server_url)
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        raise ValueError(f"Invalid server URL: {server_url!r}")
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)
    if not cert_der:
        raise RuntimeError("Peer did not present an X.509 certificate")
    return extract_spki_pin_from_der(cert_der)


def extract_spki_pin_from_pem_file(pem_path: Path) -> str:
    pem_text = pem_path.read_text(encoding="utf-8")
    cert_der = ssl.PEM_cert_to_DER_cert(pem_text)
    return extract_spki_pin_from_der(cert_der)


def build_join_string(
    server_url: str,
    pins: Iterable[str],
    *,
    invite_code: str = "",
    node_title: str = "",
) -> str:
    clean_url = server_url.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(clean_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("server_url must be https://<domain>[:port]")

    pin_list: List[str] = []
    for p in pins:
        p = p.strip()
        if not p:
            continue
        if not p.startswith("sha256/") or len(base64.b64decode(p[7:], validate=True)) != 32:
            raise ValueError(f"Invalid SPKI pin: {p}")
        if p not in pin_list:
            pin_list.append(p)
    if not pin_list:
        raise ValueError("At least one valid SPKI pin is required")

    clean_inv = invite_code.strip()
    if clean_inv and not _INVITE_RE.fullmatch(clean_inv):
        raise ValueError(f"Invalid invite_code: {clean_inv!r}")

    payload = {"v": 1, "s": clean_url, "p": pin_list[:4]}
    if clean_inv:
        payload["i"] = clean_inv
    if node_title.strip():
        payload["t"] = node_title.strip()[:64]

    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    b64u = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{JOIN_SCHEME_PREFIX}{b64u}"


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate Max1m 1-click onboarding link (max1m-join://)")
    ap.add_argument("--server", required=True, help="HTTPS URL of Max1m node, e.g. https://chat.company.ru")
    ap.add_argument("--pin", action="append", default=[], help="Explicit sha256/... SPKI pin (repeatable)")
    ap.add_argument("--cert-pem", type=Path, help="Read X.509 PEM certificate from file instead of live TLS probe")
    ap.add_argument("--invite", default="", help="Optional single-use invite code for employee registration")
    ap.add_argument("--title", default="", help="Optional node display title (e.g. 'Max1m Офис')")
    args = ap.parse_args(argv)

    pins: List[str] = list(args.pin)
    if args.cert_pem:
        pins.insert(0, extract_spki_pin_from_pem_file(args.cert_pem))
    if not pins:
        pins.append(probe_live_spki_pin(args.server))

    link = build_join_string(args.server, pins, invite_code=args.invite, node_title=args.title)
    print(link)
    return 0


if __name__ == "__main__":
    sys.exit(main())
