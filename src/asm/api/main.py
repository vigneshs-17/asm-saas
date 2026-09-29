"""Main FastAPI application entrypoint for ASM SaaS."""

import logging

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from asm.api.routes import router

logger = logging.getLogger(__name__)

app = FastAPI(
    title="ASM SaaS API",
    description="Attack Surface Management REST API - Reconnaissance & Surface Monitoring",
    version="0.2.0",
)

app.include_router(router)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Ensure unhandled internal server errors never leak stack traces to clients."""
    logger.exception("Unhandled server exception processing request: %s", request.url)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error. Please consult system logs."},
    )
