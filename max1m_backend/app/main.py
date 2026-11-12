import asyncio
import logging
import uvicorn
from contextlib import asynccontextmanager, suppress
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.database import engine, init_models, AsyncSessionLocal
from app.api import auth, calls, messages, files, groups, prekeys
from app.config import settings, validate_secret_key
from app.rate_limit import limiter
from app.logging_security import install_uvicorn_token_filter
from app.body_limits import MessageBodyLimitMiddleware, GeneralBodyLimitMiddleware, UploadBodyLimitMiddleware, MESSAGE_PATHS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("max1m")
install_uvicorn_token_filter()
MAINTENANCE_INTERVAL_SECONDS = 1800.0


async def _run_storage_maintenance() -> None:
    sweep_result = files.sweep_orphaned_upload_staging(files.UPLOAD_DIR, min_age_seconds=300.0)
    if sweep_result.get("removed"):
        logger.info("Очищено осиротевших staging-файлов загрузок: %s", sweep_result["removed"])
    async with AsyncSessionLocal() as db:
        reap_result = await files.cleanup_stale_upload_reservations(db, upload_dir=files.UPLOAD_DIR)
        if reap_result.get("removed"):
            logger.info("Очищено устаревших броней загрузок без блоба: %s", reap_result["removed"])
        expired_files = await files.cleanup_expired_uploaded_files(db, upload_dir=files.UPLOAD_DIR)
        if expired_files.get("expired_records"):
            logger.info(
                "Очищено просроченных файлов: records=%s, blobs=%s",
                expired_files.get("expired_records", 0),
                expired_files.get("unlinked_blobs", 0),
            )
        compact_result = await messages.compact_delivered_messages(db)
        if compact_result.get("compacted") or compact_result.get("expired_tombstones"):
            logger.info(
                "Компакция доставленных сообщений: compacted=%s, expired_tombstones=%s",
                compact_result.get("compacted", 0),
                compact_result.get("expired_tombstones", 0),
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_secret_key()
    logger.info("Инициализация базы данных...")
    await init_models()
    await _run_storage_maintenance()

    async def _periodic_maintenance_loop():
        while True:
            await asyncio.sleep(MAINTENANCE_INTERVAL_SECONDS)
            try:
                await _run_storage_maintenance()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Ошибка фонового обслуживания хранилища")

    maintenance_task = asyncio.create_task(_periodic_maintenance_loop())
    logger.info("База данных готова.")
    try:
        yield
    finally:
        maintenance_task.cancel()
        with suppress(asyncio.CancelledError):
            await maintenance_task
        with suppress(Exception):
            await engine.dispose()
        logger.info("Отключение сервера Max1m...")


class SecurityHeadersMiddleware:
    """Attach anti-sniffing, anti-framing, and no-store cache headers to HTTP responses."""

    _DEFAULT_HEADERS = (
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
        (b"cache-control", b"no-store"),
    )

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                raw_headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in raw_headers}
                for key, value in self._DEFAULT_HEADERS:
                    if key not in present:
                        raw_headers.append((key, value))
                message = {**message, "headers": raw_headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


app = FastAPI(
    title="Max1m Secure Relay Node",
    description="Zero-Trust Backend for Max1m E2EE Messenger",
    version="0.3.0",  # security hardening: auth, CORS, rate limits, logging
    lifespan=lifespan,
    docs_url="/docs" if settings.ENABLE_API_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if settings.ENABLE_API_DOCS else None,
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

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MessageBodyLimitMiddleware)
app.add_middleware(GeneralBodyLimitMiddleware)
app.add_middleware(UploadBodyLimitMiddleware)


@app.exception_handler(RequestValidationError)
async def message_validation_error(request: Request, exc: RequestValidationError):
    if request.url.path in MESSAGE_PATHS:
        # Avoid reflecting arbitrary ciphertext (or invalid Unicode) in errors.
        return JSONResponse(status_code=422, content={"detail": "Invalid message request"})
    if request.url.path in {"/auth/register", "/auth/login", "/auth/change-password", "/auth/logout"}:
        # Pydantic errors can include the original password or invitation code.
        return JSONResponse(status_code=422, content={"detail": "Invalid authentication request"})
    return await request_validation_exception_handler(request, exc)

# ── Роутеры ───────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(messages.router)
app.include_router(files.router)
app.include_router(groups.router)
app.include_router(calls.router)
app.include_router(prekeys.router)
app.include_router(prekeys.prod_router)


@app.get("/")
async def root():
    return {"status": "online", "node": "Max1m Relay"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        ws_max_size=128 * 1024,
        reload=False
    )
