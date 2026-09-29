"""REST API routes for ASM SaaS."""

import logging
from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from asm.api.schemas import DomainCreate, DomainRead, HealthResponse
from asm.db.models import Domain
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
    # Enforce mandatory authorization gate
    if not payload.authorized:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scanning requires explicit authorization. 'authorized' must be set to true.",
        )

    # Validate target domain syntax against RFC compliance
    try:
        validated_name = validate_domain(payload.name)
    except DomainValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid domain: {err}",
        ) from err

    normalized = normalize_domain(validated_name)

    # Check for duplicates
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
