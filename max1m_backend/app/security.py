import base64
import binascii
import hashlib
import re
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jose import jwt, JWTError
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError

from .config import ALLOWED_JWT_ALGORITHMS, settings

# Строгие параметры Argon2id (Оптимально для защиты от GPU-ферм)
# time_cost - итерации процессора
# memory_cost - потребление RAM (65536 = 64MB на 1 хеш)
# parallelism - количество потоков
# Fixed dummy hash has the same Argon2 cost as real passwords; it is not a credential.
DUMMY_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$iyMW8Z1GYEJPy5ZdCEaMlg$pSk9WVJ9FEF+fGeFjIPwc1qIZJUn006550hsrZ0q++s"
_COLON_FINGERPRINT_RE = re.compile(r"^[0-9A-F]{4}(?::[0-9A-F]{4}){7}$")


def _get_password_hasher() -> PasswordHasher:
    time_cost = max(int(getattr(settings, "ARGON2_TIME_COST", 3)), 2)
    memory_cost = max(int(getattr(settings, "ARGON2_MEMORY_COST", 65536)), 19456)
    parallelism = max(int(getattr(settings, "ARGON2_PARALLELISM", 4)), 1)
    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        salt_len=16,
    )


ph = _get_password_hasher()


def hash_password(password: str) -> str:
    """Генерирует криптостойкий хеш пароля с актуальными параметрами из settings."""
    return _get_password_hasher().hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Сравнивает пароль с хешем. Защищено от timing-атак."""
    try:
        return _get_password_hasher().verify(hashed_password, plain_password)
    except (VerificationError, InvalidHashError):
        return False


def check_needs_rehash(hashed_password: str) -> bool:
    """Проверяет, устарели ли параметры Argon2id сохранённого хеша относительно текущих settings."""
    try:
        return _get_password_hasher().check_needs_rehash(hashed_password)
    except (InvalidHashError, ValueError, TypeError):
        return False


def fingerprint_ed25519_public_key(public_key_b64: str) -> str:
    """Вычисляет канонический Max1m отпечаток SHA-256 (8 групп по 4 hex-символа) для 32-байтного ключа Ed25519."""
    if not isinstance(public_key_b64, str) or len(public_key_b64) != 44:
        raise ValueError("Invalid Ed25519 public key encoding")
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid Ed25519 public key encoding") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != public_key_b64:
        raise ValueError("Invalid Ed25519 public key encoding")
    Ed25519PublicKey.from_public_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest().upper()
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))


def validate_device_key_and_fingerprint(
    public_key: str,
    fingerprint: str,
    *,
    strict: bool = False,
) -> bool:
    """Проверяет соответствие публичного ключа Ed25519 и заявленного fingerprint.

    Даже при strict=False любой fingerprint в реальном каноническом формате
    XXXX:XXXX:...:XXXX обязан точно соответствовать SHA-256(public_key), что
    блокирует захват чужих отпечатков (fingerprint squatting) и подмену отпечатков.
    """
    if not isinstance(public_key, str) or not public_key or not isinstance(fingerprint, str) or not fingerprint:
        return False
    is_colon_fp = bool(_COLON_FINGERPRINT_RE.fullmatch(fingerprint))
    if strict or is_colon_fp:
        try:
            computed = fingerprint_ed25519_public_key(public_key)
        except ValueError:
            return False
        return computed == fingerprint
    return True


def coarsen_device_last_seen(
    now_utc: datetime | None = None,
    floor_dt: datetime | None = None,
) -> datetime | None:
    """Coarsens Device.last_seen to a coarse time bucket (default 1 hour) or freezes it when granularity <= 0."""
    granularity = int(getattr(settings, "LAST_SEEN_GRANULARITY_SECONDS", 3600))
    if floor_dt is not None and floor_dt.tzinfo is None:
        floor_utc = floor_dt.replace(tzinfo=timezone.utc)
    else:
        floor_utc = floor_dt
    if granularity <= 0:
        return floor_utc
    ts_now = now_utc if now_utc is not None else datetime.now(timezone.utc)
    if ts_now.tzinfo is None:
        ts_now = ts_now.replace(tzinfo=timezone.utc)
    if granularity > 1:
        bucket_epoch = (int(ts_now.timestamp()) // granularity) * granularity
        coarsened = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
    else:
        coarsened = ts_now
    if floor_utc is not None and coarsened < floor_utc:
        return floor_utc
    return coarsened


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Генерирует JWT токен для устройства.
    В 'data' мы будем передавать {'sub': user_id, 'device_id': device_id}.
    """
    if settings.ALGORITHM not in ALLOWED_JWT_ALGORITHMS:
        raise ValueError(f"Unsupported JWT algorithm: {settings.ALGORITHM!r}")
    to_encode = data.copy()
    if expires_delta is not None:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    # Токен подписывается ключом сервера.
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """Декодирует JWT только разрешённым симметричным алгоритмом HMAC."""
    if settings.ALGORITHM not in ALLOWED_JWT_ALGORITHMS:
        raise JWTError("Unsupported JWT algorithm")
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])