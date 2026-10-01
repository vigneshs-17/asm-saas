"""Main FastAPI application entrypoint for ASM SaaS."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from asm.api.deps import get_current_auth_settings
from asm.api.routes import public_router, router
from asm.api.routes_orgs import router as orgs_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: validate auth configuration at startup."""
    settings = get_current_auth_settings()
    if not settings.is_configured:
        logger.warning(
            "SUPABASE_URL is not set! Authentication is not configured. "
            "All protected endpoints will return 503 'authentication not configured'."
        )
    yield


app = FastAPI(
    title="ASM SaaS API",
    description="Attack Surface Management REST API - Reconnaissance & Surface Monitoring",
    version="0.2.0",
    lifespan=lifespan,
)

app.include_router(public_router)
app.include_router(router)
app.include_router(orgs_router)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Ensure unhandled internal server errors never leak stack traces to clients."""
    logger.exception("Unhandled server exception processing request: %s", request.url)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error. Please consult system logs."},
    )
