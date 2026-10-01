"""REST API routes for ASM SaaS."""

import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from asm.api.schemas import (
    ActiveScanConflict,
    DomainCreate,
    DomainRead,
    DomainScheduleUpdate,
    HealthResponse,
    ScanChangeRead,
    ScanRunDetail,
    ScanRunRead,
)
from asm.db.models import Domain, ScanChange, ScanResult, ScanRun
from asm.db.scans import enqueue_scan
from asm.db.session import get_db
from asm.validators import DomainValidationError, normalize_domain, validate_domain

logger = logging.getLogger(__name__)

router = APIRouter()

DbSession = Annotated[Session, Depends(get_db)]


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
    responses={
        200: {"description": "Service is healthy and database is connected"},
        503: {"description": "Database connection failed"},
    },
)
def health_check(db: DbSession) -> HealthResponse:
    """Verify application health and database reachability."""
    try:
        db.execute(text("SELECT 1"))
        return HealthResponse(status="ok", database="connected")
    except Exception:
        logger.exception("Database health check ping failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "error", "database": "disconnected"},
        ) from None


@router.post(
    "/domains",
    response_model=DomainRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new domain for scanning",
    responses={
        201: {"description": "Domain registered successfully"},
        409: {"description": "Domain already exists"},
        422: {"description": "Validation error or authorization missing"},
    },
)
def create_domain(payload: DomainCreate, db: DbSession) -> Domain:
    """Register a new domain, enforcing syntax validation and authorization gates."""
    if not payload.authorized:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scanning requires explicit authorization. 'authorized' must be set to true.",
        )

    try:
        validated_name = validate_domain(payload.name)
    except DomainValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid domain: {err}",
        ) from err

    normalized = normalize_domain(validated_name)

    existing = db.scalar(select(Domain).where(Domain.name == normalized))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Domain '{normalized}' already exists.",
        )

    domain = Domain(
        name=normalized,
        authorized=True,
        authorization_note=payload.authorization_note,
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain


@router.get(
    "/domains",
    response_model=list[DomainRead],
    summary="List all registered domains",
)
def list_domains(db: DbSession) -> Sequence[Domain]:
    """Retrieve all monitored domains ordered by ID."""
    return db.scalars(select(Domain).order_by(Domain.id.asc())).all()


@router.get(
    "/domains/{id}",
    response_model=DomainRead,
    summary="Get domain details by ID",
    responses={
        200: {"description": "Domain details returned"},
        404: {"description": "Domain ID not found"},
    },
)
def get_domain(id: int, db: DbSession) -> Domain:
    """Retrieve details for a single domain by primary key ID."""
    domain = db.get(Domain, id)
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain with ID {id} not found.",
        )
    return domain


@router.post(
    "/domains/{id}/scans",
    response_model=ScanRunRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a multi-stage scan run for a domain",
    responses={
        200: {
            "description": "Idempotent request returning existing scan run",
            "model": ScanRunRead,
        },
        202: {"description": "Scan run queued successfully", "model": ScanRunRead},
        404: {"description": "Domain ID not found"},
        409: {"description": "Active scan already in progress", "model": ActiveScanConflict},
        422: {"description": "Domain is not authorized for scanning"},
    },
)
def queue_scan(
    id: int,
    db: DbSession,
    response: Response,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> Any:
    """Queue a scan run for an authorized domain with atomic idempotency and concurrency guards."""
    # (a) 404 if no domain
    domain = db.get(Domain, id)
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain with ID {id} not found.",
        )

    # (b) Reject if not authorized
    if not domain.authorized:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Domain '{domain.name}' is not authorized for active scanning.",
        )

    # (c) Idempotency-Key matches an existing run for this domain -> 200 with that run
    if idempotency_key:
        existing_idempotent = db.scalar(
            select(ScanRun).where(
                ScanRun.domain_id == id,
                ScanRun.idempotency_key == idempotency_key,
            )
        )
        if existing_idempotent:
            response.status_code = status.HTTP_200_OK
            return existing_idempotent

    # (d) Otherwise insert -> 202, or 409 if the active-scan index blocks it
    try:
        scan_run = enqueue_scan(db, id, trigger="manual", idempotency_key=idempotency_key)
        db.commit()
    except IntegrityError:
        db.rollback()
        # Re-check idempotency key in case of race
        if idempotency_key:
            existing_idempotent = db.scalar(
                select(ScanRun).where(
                    ScanRun.domain_id == id,
                    ScanRun.idempotency_key == idempotency_key,
                )
            )
            if existing_idempotent:
                response.status_code = status.HTTP_200_OK
                return existing_idempotent

        # Active scan conflict
        active_id = db.scalar(
            select(ScanRun.id).where(
                ScanRun.domain_id == id,
                ScanRun.status.in_(["queued", "running"]),
            )
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "detail": "An active scan run is already in progress for this domain.",
                "active_scan_id": active_id or 0,
            },
        )

    db.refresh(scan_run)
    return scan_run


@router.get(
    "/scans/{scan_id}",
    response_model=ScanRunDetail,
    summary="Get scan run details and stage progress",
    responses={
        200: {"description": "Scan run details returned"},
        404: {"description": "Scan run ID not found"},
    },
)
def get_scan(scan_id: int, db: DbSession) -> ScanRun:
    """Retrieve execution status, retry count, and per-stage progress for a scan run."""
    scan = db.get(ScanRun, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan run with ID {scan_id} not found.",
        )
    return scan


@router.get(
    "/domains/{id}/scans",
    response_model=list[ScanRunRead],
    summary="List historical scan runs for a domain",
    responses={
        200: {"description": "List of scan runs returned"},
        404: {"description": "Domain ID not found"},
    },
)
def list_domain_scans(
    id: int,
    db: DbSession,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: int = 20,
    offset: int = 0,
) -> Sequence[ScanRun]:
    """Retrieve historical scan runs for a domain with optional status filtering and pagination."""
    domain = db.get(Domain, id)
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain with ID {id} not found.",
        )

    query = select(ScanRun).where(ScanRun.domain_id == id)
    if status_filter:
        query = query.where(ScanRun.status == status_filter)
    query = query.order_by(ScanRun.id.desc()).offset(offset).limit(min(limit, 100))
    return db.scalars(query).all()


@router.get(
    "/scans/{scan_id}/results/{stage}",
    summary="Get raw JSON artifact report for a specific pipeline stage",
    responses={
        200: {"description": "Stage artifact report returned"},
        404: {"description": "Scan run or stage result not found"},
    },
)
def get_scan_stage_result(scan_id: int, stage: str, db: DbSession) -> dict[str, Any]:
    """Retrieve the JSONB artifact report produced by a specific pipeline stage."""
    scan = db.get(ScanRun, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan run with ID {scan_id} not found.",
        )

    res = db.scalar(
        select(ScanResult).where(
            ScanResult.scan_run_id == scan_id,
            ScanResult.stage == stage,
        )
    )
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No artifact report found for stage '{stage}' in scan run {scan_id}.",
        )
    return res.report


@router.get(
    "/domains/{id}/changes",
    response_model=list[ScanChangeRead],
    summary="List attack surface changes detected for a domain",
    responses={
        200: {"description": "List of detected changes returned"},
        404: {"description": "Domain ID not found"},
    },
)
def list_domain_changes(
    id: int,
    db: DbSession,
    change_type: Annotated[str | None, Query(description="Filter by change_type")] = None,
    severity: Annotated[str | None, Query(description="Filter by severity")] = None,
    category: Annotated[str | None, Query(description="Filter by category")] = None,
    since: Annotated[
        str | None,
        Query(description="Filter changes observed on or after timestamp (ISO-8601)"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Sequence[ScanChange]:
    """Retrieve historical attack surface changes for a domain, newest first."""
    domain = db.get(Domain, id)
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain with ID {id} not found.",
        )

    stmt = select(ScanChange).where(ScanChange.domain_id == id)
    if change_type:
        stmt = stmt.where(ScanChange.change_type == change_type)
    if severity:
        stmt = stmt.where(ScanChange.severity == severity)
    if category:
        stmt = stmt.where(ScanChange.category == category)
    if since:
        # Robustly handle unencoded '+' decoded as ' ' in query strings
        try:
            since_dt = datetime.fromisoformat(since.replace(" ", "+"))
        except ValueError as err:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid ISO-8601 datetime format for 'since': {since}",
            ) from err
        stmt = stmt.where(ScanChange.observed_at >= since_dt)

    stmt = (
        stmt.order_by(ScanChange.observed_at.desc(), ScanChange.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return db.scalars(stmt).all()


@router.get(
    "/scans/{id}/changes",
    response_model=list[ScanChangeRead],
    summary="List attack surface changes detected in a scan run",
    responses={
        200: {"description": "List of scan changes returned"},
        404: {"description": "Scan run ID not found"},
    },
)
def get_scan_changes(id: int, db: DbSession) -> Sequence[ScanChange]:
    """Retrieve attack surface changes detected specifically in a scan run."""
    scan = db.get(ScanRun, id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan run with ID {id} not found.",
        )

    stmt = select(ScanChange).where(ScanChange.scan_run_id == id).order_by(ScanChange.id.asc())
    return db.scalars(stmt).all()


@router.put(
    "/domains/{id}/schedule",
    response_model=DomainRead,
    summary="Configure recurring scan schedule for a domain",
    responses={
        200: {"description": "Schedule updated successfully"},
        404: {"description": "Domain not found"},
        422: {"description": "Validation error or domain not authorized"},
    },
)
def update_domain_schedule(
    id: int,
    payload: DomainScheduleUpdate,
    db: DbSession,
) -> Domain:
    """Configure or disable automated periodic scanning for an authorized domain."""
    domain = db.get(Domain, id)
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain with ID {id} not found.",
        )

    if payload.interval_hours is None:
        # Disable schedule
        domain.scan_interval_hours = None
        domain.next_scan_at = None
    else:
        # Must be authorized to enable schedule
        if not domain.authorized:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Domain '{domain.name}' is not authorized for scanning.",
            )

        if domain.scan_interval_hours is None:
            # Enabling from null: sets next_scan_at = now()
            domain.scan_interval_hours = payload.interval_hours
            domain.next_scan_at = func.now()
        else:
            # Changing an existing interval: sets next_scan_at = now() + new interval
            domain.scan_interval_hours = payload.interval_hours
            domain.next_scan_at = func.now() + text("interval '1 hour' * :h").bindparams(
                h=payload.interval_hours
            )

    db.commit()
    db.refresh(domain)
    return domain


