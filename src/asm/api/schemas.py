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


class ScanStageRead(BaseModel):
    """Response schema for a single pipeline stage execution status."""

    stage: str
    status: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None
    error: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanRunRead(BaseModel):
    """Response schema for a scan run execution."""

    id: int
    domain_id: int
    status: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    attempts: int = 0
    max_attempts: int = 3

    model_config = ConfigDict(from_attributes=True)


class ScanRunDetail(ScanRunRead):
    """Detailed response schema for a scan run including stage progress."""

    stages: list[ScanStageRead] = []

    model_config = ConfigDict(from_attributes=True)


class ActiveScanConflict(BaseModel):
    """Error schema returned when a scan is already active for a target domain."""

    detail: str
    active_scan_id: int
