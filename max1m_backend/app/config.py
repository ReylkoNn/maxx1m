import secrets
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # SECRET_KEY теперь обязателен и берется из .env
    # Если не задан — приложение упадет при старте
    SECRET_KEY: str

    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # Сессия живет 7 дней

    # Настройки для Argon2id (можно переопределить в .env)
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536
    ARGON2_PARALLELISM: int = 4

    # Rate Limiting
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "3/hour"
    RATE_LIMIT_UPLOAD: str = "30/hour"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Игнорируем лишние переменные


settings = Settings()


def validate_secret_key():
    weak_keys = [
        "d41d8cd98f00b204e9800998ecf8427e_CHANGE_ME",
        "CHANGE_ME",
        "your-secret-key-here",
        ""
    ]
    if settings.SECRET_KEY in weak_keys:
        raise ValueError(
            "SECRET_KEY is weak or default! "
            "Generate a strong key: python -c \"import secrets; print(secrets.token_hex(32))\""
        )