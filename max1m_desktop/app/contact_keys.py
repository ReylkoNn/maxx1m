"""Local fingerprint and key-change checks, independent of server claims."""
import base64
import hashlib


def fingerprint_public_key(public_key_b64: str) -> str:
    if not isinstance(public_key_b64, str):
        raise ValueError("Invalid Ed25519 public key")
    key = base64.b64decode(public_key_b64, validate=True)
    if len(key) != 32 or base64.b64encode(key).decode("ascii") != public_key_b64:
        raise ValueError("Invalid Ed25519 public key")
    digest = hashlib.sha256(key).hexdigest().upper()
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))


def safe_local_fingerprint(public_key_b64: str, fallback: str = "—") -> tuple[str, bool]:
    """Compute SHA-256 fingerprint locally when public_key_b64 is a canonical 32-byte Ed25519 key."""
    try:
        return fingerprint_public_key(public_key_b64), True
    except Exception:
        return fallback, False


def _decode_canonical_ed25519_pub(public_key_b64: str) -> bytes:
    if not isinstance(public_key_b64, str):
        raise ValueError("Invalid Ed25519 public key")
    key = base64.b64decode(public_key_b64, validate=True)
    if len(key) != 32 or base64.b64encode(key).decode("ascii") != public_key_b64:
        raise ValueError("Invalid Ed25519 public key")
    return key


def _compute_safety_half_30(key_bytes: bytes, iterations: int = 5200) -> str:
    """Signal-style iterated SHA-512 fingerprint half producing 30 decimal digits (6 x 5-digit groups)."""
    version_prefix = b"\x00\x01"
    acc = version_prefix + key_bytes
    for _ in range(max(1, int(iterations))):
        acc = hashlib.sha512(acc + key_bytes).digest()
    chunks = []
    for offset in range(0, 30, 5):
        val = int.from_bytes(acc[offset : offset + 5], "big") % 100000
        chunks.append(f"{val:05d}")
    return "".join(chunks)


def compute_safety_number(our_public_key_b64: str, peer_public_key_b64: str, *, iterations: int = 5200) -> str:
    """
    Compute a symmetric, order-independent 60-digit Safety Number for two Ed25519 keys.
    Both Alice (`compute_safety_number(alice_pk, bob_pk)`) and Bob
    (`compute_safety_number(bob_pk, alice_pk)`) obtain the exact same 60-digit string.
    """
    k1 = _decode_canonical_ed25519_pub(our_public_key_b64)
    k2 = _decode_canonical_ed25519_pub(peer_public_key_b64)
    first_k, second_k = (k1, k2) if k1 <= k2 else (k2, k1)
    return _compute_safety_half_30(first_k, iterations=iterations) + _compute_safety_half_30(
        second_k, iterations=iterations
    )


def format_safety_number_blocks(digits_60: str) -> str:
    """Format 60 decimal digits as 3 lines of 4 five-digit groups (`XXXXX XXXXX XXXXX XXXXX`)."""
    clean = "".join(ch for ch in (digits_60 or "") if ch.isdigit())
    if len(clean) != 60:
        raise ValueError("Expected 60-digit safety number")
    groups = [clean[i : i + 5] for i in range(0, 60, 5)]
    lines = [" ".join(groups[row : row + 4]) for row in range(0, 12, 4)]
    return "\n".join(lines)


def safe_safety_number_display(our_public_key_b64: str, peer_public_key_b64: str) -> str:
    """Return formatted 60-digit Safety Number blocks, or empty string if either key is unavailable."""
    try:
        digits = compute_safety_number(our_public_key_b64, peer_public_key_b64)
        return format_safety_number_blocks(digits)
    except Exception:
        return ""


def device_key_map(contact: dict) -> dict:
    devices = contact.get("devices")
    if not isinstance(devices, list) or not devices:
        raise ValueError("Contact has no devices")
    result = {}
    for device in devices:
        device_id = device.get("device_id")
        if not isinstance(device_id, str) or not device_id or device_id in result:
            raise ValueError("Invalid device identifier")
        key = device.get("public_key")
        fingerprint_public_key(key)
        result[device_id] = key
    return result


def same_contact_keys(existing: dict, incoming: dict) -> bool:
    if not existing.get("user_id") or existing.get("user_id") != incoming.get("user_id"):
        return False
    return device_key_map(existing) == device_key_map(incoming)


def newly_advertised_devices(existing: dict, incoming: dict, allies: dict, username: str) -> list:
    """Accept additions as *unverified candidates*, never a key replacement/removal."""
    if not existing.get("user_id") or existing.get("user_id") != incoming.get("user_id"):
        raise ValueError("Contact identity changed")
    old, new = device_key_map(existing), device_key_map(incoming)
    if any(new.get(device_id) != key for device_id, key in old.items()):
        raise ValueError("Existing keys or devices changed")
    used_elsewhere = {device.get("device_id") for name, contact in allies.items() if name != username
                      for device in contact.get("devices", [])}
    additions = []
    for device in incoming["devices"]:
        if device["device_id"] not in old:
            if device["device_id"] in used_elsewhere:
                raise ValueError("Device already belongs to another contact")
            additions.append({k: v for k, v in device.items() if k not in {"verified_fingerprint", "verified_scope"}})
    return additions
