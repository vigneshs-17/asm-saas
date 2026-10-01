"""REST API routes for ASM SaaS (multi-tenant scoped)."""

import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from asm.api.deps import (
    DbSession,
    get_current_user,
    get_domain_for_org,
    get_scan_for_org,
    require_org_role,
)
from asm.api.schemas import (
    ActiveScanConflict,
    AlertNotificationRead,
    DomainAlertsUpdate,
    DomainCreate,
    DomainRead,
    DomainScheduleUpdate,
    HealthResponse,
    ScanChangeRead,
    ScanRunDetail,
    ScanRunRead,
)
from asm.db.models import (
    AlertNotification,
    Domain,
    Membership,
    Organization,
    ScanChange,
    ScanResult,
    ScanRun,
)
from asm.db.scans import enqueue_scan
from asm.validators import DomainValidationError, normalize_domain, validate_domain

logger = logging.getLogger(__name__)

public_router = APIRouter()
router = APIRouter(prefix="/orgs/{org_id}", dependencies=[Depends(get_current_user)])


@public_router.get(
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
    summary="Register a new domain for scanning within an organization",
    responses={
        201: {"description": "Domain registered successfully"},
        403: {"description": "Insufficient organization permissions (admin required)"},
        404: {"description": "Organization not found (or non-member)"},
        409: {"description": "Domain already exists in this organization"},
        422: {"description": "Validation error or authorization missing"},
    },
)
def create_domain(
    org_id: int,
    payload: DomainCreate,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> Domain:
    """Register a new domain within an organization, enforcing per-org uniqueness."""
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

    existing = db.scalar(
        select(Domain).where(
            Domain.org_id == org_id,
            Domain.name == normalized,
        )
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Domain '{normalized}' already exists.",
        )

    domain = Domain(
        org_id=org_id,
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
    summary="List all registered domains in an organization",
    responses={
        200: {"description": "List of organization domains returned"},
        404: {"description": "Organization not found (or non-member)"},
    },
)
def list_domains(
    org_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> Sequence[Domain]:
    """Retrieve all monitored domains for this organization ordered by ID."""
    return db.scalars(
        select(Domain).where(Domain.org_id == org_id).order_by(Domain.id.asc())
    ).all()


@router.get(
    "/domains/{domain_id}",
    response_model=DomainRead,
    summary="Get domain details by ID within an organization",
    responses={
        200: {"description": "Domain details returned"},
        404: {"description": "Organization or Domain ID not found"},
    },
)
def get_domain(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> Domain:
    """Retrieve details for a single domain by ID scoped to organization."""
    return get_domain_for_org(db, org_id, domain_id)


@router.post(
    "/domains/{domain_id}/scans",
    response_model=ScanRunRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a multi-stage scan run for a domain",
    responses={
        200: {
            "description": "Idempotent request returning existing scan run",
            "model": ScanRunRead,
        },
        202: {"description": "Scan run queued successfully", "model": ScanRunRead},
        403: {"description": "Insufficient organization permissions (admin required)"},
        404: {"description": "Organization or Domain ID not found"},
        409: {"description": "Active scan already in progress", "model": ActiveScanConflict},
        422: {"description": "Domain is not authorized for scanning"},
    },
)
def queue_scan(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
    response: Response,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> Any:
    """Queue a scan run for an authorized domain with atomic idempotency and concurrency guards."""
    domain = get_domain_for_org(db, org_id, domain_id)

    if not domain.authorized:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Domain '{domain.name}' is not authorized for active scanning.",
        )

    if idempotency_key:
        existing_idempotent = db.scalar(
            select(ScanRun).where(
                ScanRun.domain_id == domain.id,
                ScanRun.idempotency_key == idempotency_key,
            )
        )
        if existing_idempotent:
            response.status_code = status.HTTP_200_OK
            return existing_idempotent

    try:
        scan_run = enqueue_scan(db, domain.id, trigger="manual", idempotency_key=idempotency_key)
        db.commit()
    except IntegrityError:
        db.rollback()
        if idempotency_key:
            existing_idempotent = db.scalar(
                select(ScanRun).where(
                    ScanRun.domain_id == domain.id,
                    ScanRun.idempotency_key == idempotency_key,
                )
            )
            if existing_idempotent:
                response.status_code = status.HTTP_200_OK
                return existing_idempotent

        active_id = db.scalar(
            select(ScanRun.id).where(
                ScanRun.domain_id == domain.id,
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
    "/domains/{domain_id}/scans",
    response_model=list[ScanRunRead],
    summary="List historical scan runs for a domain",
    responses={
        200: {"description": "List of scan runs returned"},
        404: {"description": "Organization or Domain ID not found"},
    },
)
def list_domain_scans(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: int = 20,
    offset: int = 0,
) -> Sequence[ScanRun]:
    """Retrieve historical scan runs for a domain with optional status filtering and pagination."""
    domain = get_domain_for_org(db, org_id, domain_id)

    query = select(ScanRun).where(ScanRun.domain_id == domain.id)
    if status_filter:
        query = query.where(ScanRun.status == status_filter)
    query = query.order_by(ScanRun.id.desc()).offset(offset).limit(min(limit, 100))
    return db.scalars(query).all()


@router.get(
    "/scans",
    response_model=list[ScanRunRead],
    summary="List all historical scan runs across all domains in an organization",
    responses={
        200: {"description": "List of organization scan runs returned"},
        404: {"description": "Organization not found (or non-member)"},
    },
)
def list_org_scans(
    org_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: int = 20,
    offset: int = 0,
) -> Sequence[ScanRun]:
    """Retrieve all historical scan runs across all domains in this organization."""
    query = (
        select(ScanRun)
        .join(Domain, ScanRun.domain_id == Domain.id)
        .where(Domain.org_id == org_id)
    )
    if status_filter:
        query = query.where(ScanRun.status == status_filter)
    query = query.order_by(ScanRun.id.desc()).offset(offset).limit(min(limit, 100))
    return db.scalars(query).all()


@router.get(
    "/scans/{scan_id}",
    response_model=ScanRunDetail,
    summary="Get scan run details and stage progress",
    responses={
        200: {"description": "Scan run details returned"},
        404: {"description": "Organization or Scan run ID not found"},
    },
)
def get_scan(
    org_id: int,
    scan_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> ScanRun:
    """Retrieve execution status, retry count, and per-stage progress for a scan run."""
    return get_scan_for_org(db, org_id, scan_id)


@router.get(
    "/scans/{scan_id}/results/{stage}",
    summary="Get raw JSON artifact report for a specific pipeline stage",
    responses={
        200: {"description": "Stage artifact report returned"},
        404: {"description": "Organization, scan run, or stage result not found"},
    },
)
def get_scan_stage_result(
    org_id: int,
    scan_id: int,
    stage: str,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> dict[str, Any]:
    """Retrieve the JSONB artifact report produced by a specific pipeline stage."""
    scan = get_scan_for_org(db, org_id, scan_id)

    res = db.scalar(
        select(ScanResult).where(
            ScanResult.scan_run_id == scan.id,
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
    "/scans/{scan_id}/changes",
    response_model=list[ScanChangeRead],
    summary="List attack surface changes detected in a scan run",
    responses={
        200: {"description": "List of scan changes returned"},
        404: {"description": "Organization or Scan run ID not found"},
    },
)
def get_scan_changes(
    org_id: int,
    scan_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> Sequence[ScanChange]:
    """Retrieve attack surface changes detected specifically in a scan run."""
    scan = get_scan_for_org(db, org_id, scan_id)
    stmt = select(ScanChange).where(ScanChange.scan_run_id == scan.id).order_by(ScanChange.id.asc())
    return db.scalars(stmt).all()


@router.get(
    "/domains/{domain_id}/changes",
    response_model=list[ScanChangeRead],
    summary="List attack surface changes detected for a domain",
    responses={
        200: {"description": "List of detected changes returned"},
        404: {"description": "Organization or Domain ID not found"},
    },
)
def list_domain_changes(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
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
    domain = get_domain_for_org(db, org_id, domain_id)

    stmt = select(ScanChange).where(ScanChange.domain_id == domain.id)
    if change_type:
        stmt = stmt.where(ScanChange.change_type == change_type)
    if severity:
        stmt = stmt.where(ScanChange.severity == severity)
    if category:
        stmt = stmt.where(ScanChange.category == category)
    if since:
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


@router.put(
    "/domains/{domain_id}/schedule",
    response_model=DomainRead,
    summary="Configure recurring scan schedule for a domain",
    responses={
        200: {"description": "Schedule updated successfully"},
        403: {"description": "Insufficient organization permissions (admin required)"},
        404: {"description": "Organization or Domain not found"},
        422: {"description": "Validation error or domain not authorized"},
    },
)
def update_domain_schedule(
    org_id: int,
    domain_id: int,
    payload: DomainScheduleUpdate,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> Domain:
    """Configure or disable automated periodic scanning for an authorized domain."""
    domain = get_domain_for_org(db, org_id, domain_id)

    if payload.interval_hours is None:
        domain.scan_interval_hours = None
        domain.next_scan_at = None
    else:
        if not domain.authorized:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Domain '{domain.name}' is not authorized for scanning.",
            )

        if domain.scan_interval_hours is None:
            domain.scan_interval_hours = payload.interval_hours
            domain.next_scan_at = func.now()
        else:
            domain.scan_interval_hours = payload.interval_hours
            domain.next_scan_at = func.now() + text("interval '1 hour' * :h").bindparams(
                h=payload.interval_hours
            )

    db.commit()
    db.refresh(domain)
    return domain


@router.put(
    "/domains/{domain_id}/alerts",
    response_model=DomainRead,
    summary="Configure attack surface change email alerts for a domain",
    responses={
        200: {"description": "Alert settings updated successfully"},
        403: {"description": "Insufficient organization permissions (admin required)"},
        404: {"description": "Organization or Domain not found"},
        422: {"description": "Domain not authorized or validation error"},
    },
)
def update_domain_alerts(
    org_id: int,
    domain_id: int,
    payload: DomainAlertsUpdate,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> Domain:
    """Configure or disable automated email alerts for detected attack surface exposures."""
    domain = get_domain_for_org(db, org_id, domain_id)

    if not domain.authorized:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Domain '{domain.name}' is not authorized.",
        )

    domain.alerts_enabled = payload.alerts_enabled
    domain.alert_emails = [str(email) for email in payload.alert_emails]
    domain.alert_min_severity = payload.alert_min_severity

    db.commit()
    db.refresh(domain)
    return domain


@router.get(
    "/domains/{domain_id}/alert-notifications",
    response_model=list[AlertNotificationRead],
    summary="List alert notifications for a domain",
    responses={
        200: {"description": "List of alert notifications returned"},
        404: {"description": "Organization or Domain not found"},
    },
)
def list_domain_alert_notifications(
    org_id: int,
    domain_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
) -> Sequence[AlertNotification]:
    """Retrieve historical alert notifications for a domain with optional status filtering."""
    domain = get_domain_for_org(db, org_id, domain_id)

    query = select(AlertNotification).where(AlertNotification.domain_id == domain.id)
    if status_filter:
        query = query.where(AlertNotification.status == status_filter)
    query = (
        query.order_by(AlertNotification.created_at.desc(), AlertNotification.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return db.scalars(query).all()
