import os
from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import event, text

from .models import Base


def _tighten_posix_mode(path: Path, mode: int) -> None:
    if os.name != "posix":
        return
    try:
        if path.exists() and not path.is_symlink():
            os.chmod(path, mode)
    except OSError:
        pass


# ============================================================================
# DATABASE PATH
# ============================================================================
# Путь к данным: MAX1M_DATA_DIR или ~/.max1m по умолчанию.
DATA_DIR = Path(os.environ.get("MAX1M_DATA_DIR", Path.home() / ".max1m"))
DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
_tighten_posix_mode(DATA_DIR, 0o700)

DB_PATH = DATA_DIR / "max1m_secure.db"

# SQLite async URL
SQLALCHEMY_DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH.as_posix()}"

# ============================================================================
# ENGINE
# ============================================================================
engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},  # нужно для SQLite
    echo=False,
)


@event.listens_for(engine.sync_engine, "connect")
def _configure_sqlite_connection(dbapi_connection, _connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA secure_delete=ON")
        cursor.execute("PRAGMA temp_store=MEMORY")
    finally:
        cursor.close()

# ============================================================================
# SESSION FACTORY
# ============================================================================
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ============================================================================
# DEPENDENCY
# ============================================================================
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# ============================================================================
# INIT MODELS
# ============================================================================
async def init_models():
    """Создаёт таблицы и недостающие колонки/индексы идемпотентно."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        dev_cols = [row[1] for row in (await conn.execute(text("PRAGMA table_info(devices)"))).fetchall()]
        if dev_cols and "session_version" not in dev_cols:
            await conn.execute(text("ALTER TABLE devices ADD COLUMN session_version INTEGER DEFAULT 0"))
        cols = [row[1] for row in (await conn.execute(text("PRAGMA table_info(messages)"))).fetchall()]
        if cols and "delivered_at" not in cols:
            await conn.execute(text("ALTER TABLE messages ADD COLUMN delivered_at DATETIME"))
        grp_cols = [row[1] for row in (await conn.execute(text("PRAGMA table_info(groups)"))).fetchall()]
        if grp_cols and "epoch" not in grp_cols:
            await conn.execute(text("ALTER TABLE groups ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1"))
        gmsg_cols = [row[1] for row in (await conn.execute(text("PRAGMA table_info(group_messages)"))).fetchall()]
        if gmsg_cols and "epoch" not in gmsg_cols:
            await conn.execute(text("ALTER TABLE group_messages ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1"))
        skd_cols = [row[1] for row in (await conn.execute(text("PRAGMA table_info(sender_key_distributions)"))).fetchall()]
        if skd_cols and "epoch" not in skd_cols:
            await conn.execute(text("ALTER TABLE sender_key_distributions ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_messages_pending_order ON messages (receiver_device_id, is_delivered, created_at, id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_messages_delivered_cleanup ON messages (is_delivered, delivered_at, created_at)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_group_deliveries_pending ON group_message_deliveries (device_id, is_delivered, message_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_file_records_owner_created ON file_records (owner_user_id, created_at)"))
    _tighten_posix_mode(DATA_DIR, 0o700)
    for suffix in ("", "-wal", "-shm", "-journal"):
        _tighten_posix_mode(Path(f"{DB_PATH}{suffix}"), 0o600)