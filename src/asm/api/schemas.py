"""Pydantic request and response schemas for the ASM SaaS REST API."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(..., description="Application health status (ok/error)")
    database: str = Field(..., description="Database connection status (connected/disconnected)")


class DomainCreate(BaseModel):
    """Request payload for creating a new monitored domain."""

    name: str = Field(..., description="Target domain name (e.g. example.com)")
    authorized: bool = Field(
        ...,
        description="Explicit authorization confirmation (must be true)",
    )
    authorization_note: str | None = Field(
        default=None,
        description="Optional documentation or scope reference regarding authorization",
    )


class DomainRead(BaseModel):
    """Response schema for a monitored domain record."""

    id: int
    name: str
    authorized: bool
    authorization_note: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
