"""Reseller Panel — FastAPI app with full security hardening."""
import logging
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from database import init_db
from config import settings
from security import (
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
    SizeLimitMiddleware,
)
from routers import api_admin, api_webhook, api_delivery, admin_ui, storefront, landing

# ---------- Logging ----------
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("reseller-panel")
# Never log the SellAuth key or admin password
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

# ---------- Config validation ----------
warnings = settings.validate()
for w in warnings:
    logger.warning(f"CONFIG WARNING: {w}")

# ---------- App ----------
app = FastAPI(
    title="Reseller Panel",
    version="1.0.0",
    docs_url="/docs" if not settings.is_production else None,  # Hide docs in prod
    redoc_url=None,
    openapi_url="/openapi.json" if not settings.is_production else None,
)

# ---------- Middleware (order matters) ----------

# 1. Size limits — reject oversized requests first
app.add_middleware(SizeLimitMiddleware)

# 2. Rate limiting — protect against abuse
if settings.RATE_LIMIT_ENABLED:
    app.add_middleware(RateLimitMiddleware)

# 3. Security headers — on every response
app.add_middleware(SecurityHeadersMiddleware)

# 4. CORS — restrict cross-origin access
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins or ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=3600,
)

# ---------- Routers ----------
app.include_router(api_admin.router)
app.include_router(api_webhook.router)
app.include_router(api_delivery.router)
app.include_router(admin_ui.router)
app.include_router(storefront.router)
app.include_router(landing.router)

# Static assets (VOID theme css)
from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory="static"), name="static")


# ---------- Error handling — never leak internals ----------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all for unexpected errors. HTTPExceptions pass through to Starlette."""
    from fastapi import HTTPException as FastAPIHTTPException
    # Let Starlette handle HTTP exceptions (rate limits, 404s, etc.)
    if isinstance(exc, FastAPIHTTPException):
        raise exc
    logger.error(f"Unhandled error: {type(exc).__name__}", exc_info=settings.DEBUG)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(status_code=404, content={"detail": "Not found"})


@app.exception_handler(405)
async def method_not_allowed(request: Request, exc):
    return JSONResponse(status_code=405, content={"detail": "Method not allowed"})


# ---------- Health (public, minimal info) ----------

@app.get("/health")
def health():
    return {"status": "ok"}


# ---------- Startup ----------

@app.on_event("startup")
async def startup():
    init_db()
    w = settings.validate()
    if w:
        logger.warning(f"Startup warnings: {len(w)} issue(s)")
    logger.info("Reseller Panel started")

    # Start Discord bot in the background
    from discord_bot import start_bot
    import asyncio
    asyncio.create_task(start_bot())


@app.on_event("shutdown")
async def shutdown():
    from discord_bot import stop_bot
    await stop_bot()


if __name__ == "__main__":
    import os
    port = int(os.getenv("PORT", str(settings.PORT)))
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=port,
        reload=settings.DEBUG,
        log_level="warning",
        access_log=False,
    )
