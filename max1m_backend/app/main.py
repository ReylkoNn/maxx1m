import logging
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.database import init_models
from app.api import auth, messages, files, groups
from app.config import settings, validate_secret_key
from app.rate_limit import limiter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("max1m")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_secret_key()
    logger.info("Инициализация базы данных...")
    await init_models()
    logger.info("База данных готова.")
    yield
    logger.info("Отключение сервера Max1m...")


app = FastAPI(
    title="Max1m Secure Relay Node",
    description="Zero-Trust Backend for Max1m E2EE Messenger",
    version="0.3.0",  # security hardening: auth, CORS, rate limits, logging
    lifespan=lifespan
)

# ── Rate limit exceeded handler ────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Desktop-клиент использует Bearer-токен, не куки → credentials не нужны.
# allow_origins=["*"] допустимо для API, которое обслуживает native-клиент,
# не браузер.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Роутеры ───────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(messages.router)
app.include_router(files.router)
app.include_router(groups.router)


@app.get("/")
async def root():
    return {"status": "online", "node": "Max1m Relay"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False
    )
