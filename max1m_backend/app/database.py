import os
from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from .models import Base

# ============================================================================
# DATABASE PATH
# ============================================================================
# Путь к данным: MAX1M_DATA_DIR или ~/.max1m по умолчанию.
DATA_DIR = Path(os.environ.get("MAX1M_DATA_DIR", Path.home() / ".max1m"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

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
    """Создаёт таблицы, если их ещё нет."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)