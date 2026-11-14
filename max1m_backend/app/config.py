import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # SECRET_KEY теперь обязателен и берется из .env
    # Если не задан — приложение упадет при старте
    SECRET_KEY: str

    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # Сессия живет 7 дней

    # Настройки для Argon2id (можно переопределить в .env)
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536
    ARGON2_PARALLELISM: int = 4

    # Rate Limiting & Device Quotas
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "3/hour"
    RATE_LIMIT_UPLOAD: str = "30/hour"
    RATE_LIMIT_MESSAGE_SEND: str = "240/minute"
    RATE_LIMIT_MESSAGE_SYNC: str = "240/minute"
    MAX_ACTIVE_DEVICES_PER_USER: int = 32
    MAX_TOTAL_DEVICES_PER_USER: int = 256
    MAX_INCOMPLETE_UPLOADS_PER_DEVICE: int = 200
    UPLOAD_RESERVATION_TTL_SECONDS: int = 86400
    MAX_CONCURRENT_UPLOADS_PER_PROCESS: int = 8
    MAX_STORED_FILES_PER_USER: int = 2000
    MAX_STORED_BYTES_PER_USER: int = 2 * 1024 * 1024 * 1024
    MAX_GRANTS_PER_FILE: int = 200
    UPLOADED_FILE_RETENTION_SECONDS: int = 30 * 86400
    ALLOW_LEGACY_WS_QUERY_TOKEN: bool = True
    TRUSTED_PROXY_IPS: str = ""
    ENABLE_API_DOCS: bool = False
    REQUIRE_VERIFIED_DEVICE_KEYS: bool = False
    # Anti-surveillance metadata coarsening for Device.last_seen (seconds; 3600 = 1 hour, 0 = freeze at created_at).
    LAST_SEEN_GRANULARITY_SECONDS: int = 3600

    # Reject new traffic at the limit; never evict undelivered messages.
    MAX_PENDING_PER_DEVICE: int = 1000
    MAX_PENDING_PER_SENDER: int = 200
    MAX_PENDING_BYTES_PER_DEVICE: int = 64 * 1024 * 1024
    MAX_MESSAGE_PAYLOAD_BYTES: int = 1024 * 1024
    DELIVERED_MESSAGE_RETENTION_SECONDS: int = 7 * 86400
    IDEMPOTENCY_TOMBSTONE_TTL_SECONDS: int = 90 * 86400
    ALLOW_DESTRUCTIVE_LEGACY_SYNC: bool = False

    # Legacy Sender Keys lack safe membership changes and forward secrecy.
    # Opt-in is intended only for controlled migrations, never secure groups.
    ALLOW_INSECURE_LEGACY_GROUPS: bool = False

    # Production X3DH PreKey API (mandatory Ed25519 signature verification & quotas).
    ENABLE_PREKEYS: bool = True
    # Research-only legacy API, preserved for backwards test compatibility.
    ENABLE_EXPERIMENTAL_PREKEYS: bool = False
    REQUIRE_SIGNED_PREKEY_VERIFICATION: bool = False

    # Self-hosted WebRTC ICE / coturn REST ephemeral HMAC-SHA1 configuration (VPN-free calls in RU).
    CALL_STUN_URLS: str = "stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302"
    CALL_TURN_URLS: str = ""
    CALL_TURN_SHARED_SECRET: str = ""
    CALL_TURN_CREDENTIAL_TTL_SECONDS: int = 3600
    CALL_FORCE_RELAY_RECOMMENDED: bool = False
    MAX_GROUP_VOICE_PEERS: int = 8


settings = Settings()


ALLOWED_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})


def validate_secret_key():
    weak_keys = {
        "d41d8cd98f00b204e9800998ecf8427e_CHANGE_ME",
        "CHANGE_ME",
        "your-secret-key-here",
        "",
    }
    cleaned = (settings.SECRET_KEY or "").strip()
    if cleaned in weak_keys or len(cleaned) < 32:
        raise ValueError(
            "SECRET_KEY is weak, default, or shorter than 32 characters! "
            "Generate a strong key: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    if settings.ALGORITHM not in ALLOWED_JWT_ALGORITHMS:
        raise ValueError(
            f"Unsupported JWT ALGORITHM={settings.ALGORITHM!r}; allowed: {sorted(ALLOWED_JWT_ALGORITHMS)}"
        )
    if (
        settings.ARGON2_TIME_COST < 2
        or settings.ARGON2_MEMORY_COST < 19456
        or settings.ARGON2_PARALLELISM < 1
    ):
        raise ValueError(
            "Unsafe Argon2id parameters: require ARGON2_TIME_COST>=2, ARGON2_MEMORY_COST>=19456, ARGON2_PARALLELISM>=1"
        )