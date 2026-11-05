from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .config import settings

# Строгие параметры Argon2id (Оптимально для защиты от GPU-ферм)
# time_cost - итерации процессора
# memory_cost - потребление RAM (65536 = 64MB на 1 хеш)
# parallelism - количество потоков
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)


def hash_password(password: str) -> str:
    """Генерирует криптостойкий хеш пароля."""
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Сравнивает пароль с хешем. Защищено от timing-атак."""
    try:
        return ph.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Генерирует JWT токен для устройства.
    В 'data' мы будем передавать {'sub': user_id, 'device_id': device_id}.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    # Токен подписывается ключом сервера.
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt