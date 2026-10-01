"""SQLAlchemy 2.0 declarative models for ASM SaaS."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    """Return the current datetime in UTC timezone."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""

    pass


class Domain(Base):
    """Registered domain monitored by the ASM platform."""

    __tablename__ = "domains"
    __table_args__ = (
        CheckConstraint(
            "scan_interval_hours IS NULL OR "
            "(scan_interval_hours >= 6 AND scan_interval_hours <= 720)",
            name="ck_domains_scan_interval_hours",
        ),
        CheckConstraint(
            "alert_min_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name="ck_domains_alert_min_severity",
        ),
        CheckConstraint(
            "alerts_enabled = false OR "
            "(jsonb_typeof(alert_emails) = 'array' AND "
            "jsonb_array_length(alert_emails) >= 1 AND "
            "jsonb_array_length(alert_emails) <= 5)",
            name="ck_domains_alert_emails_count",
        ),
        Index(
            "ix_domains_schedule_due",
            "next_scan_at",
            postgresql_where=text("authorized = true AND scan_interval_hours IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    # Fail-safe default is False; explicit authorization is strictly required
    authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_interval_hours: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    next_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None, index=True
    )
    alerts_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    alert_emails: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    alert_min_severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    # Relationships
    scan_runs: Mapped[list["ScanRun"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
        order_by="ScanRun.id.desc()",
    )
    changes: Mapped[list["ScanChange"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
        order_by="ScanChange.id.desc()",
    )
    alert_notifications: Mapped[list["AlertNotification"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
        order_by="AlertNotification.id.desc()",
    )


class ScanRun(Base):
    """Represents a scheduled or active multi-stage scan execution for a domain."""

    __tablename__ = "scan_runs"
    __table_args__ = (
        Index(
            "uq_scan_runs_active_domain",
            "domain_id",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
        Index(
            "uq_scan_runs_domain_idempotency",
            "domain_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
        Index(
            "ix_scan_runs_claimable",
            "created_at",
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Status lifecycle: queued -> running -> succeeded / failed
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    trigger: Mapped[str] = mapped_column(
        String(20), default="manual", server_default="manual", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Worker claiming & fencing
    claim_token: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    claimed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Relationships
    domain: Mapped["Domain"] = relationship(back_populates="scan_runs")
    results: Mapped[list["ScanResult"]] = relationship(
        back_populates="scan_run",
        cascade="all, delete-orphan",
        order_by="ScanResult.id.asc()",
    )
    stages: Mapped[list["ScanStage"]] = relationship(
        back_populates="scan_run",
        cascade="all, delete-orphan",
        order_by="ScanStage.id.asc()",
    )
    change_detection: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    changes: Mapped[list["ScanChange"]] = relationship(
        back_populates="scan_run",
        cascade="all, delete-orphan",
        foreign_keys="[ScanChange.scan_run_id]",
        order_by="ScanChange.id.asc()",
    )
    alert_notifications: Mapped[list["AlertNotification"]] = relationship(
        back_populates="scan_run",
        cascade="all, delete-orphan",
        order_by="AlertNotification.id.asc()",
    )


class ScanStage(Base):
    """Execution status and duration tracking for a single pipeline stage."""

    __tablename__ = "scan_stages"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "stage", name="uq_scan_stages_run_stage"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Stage name: discover / probe / portscan / inspect / score
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    # Stage status: pending / running / succeeded / failed / skipped
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    scan_run: Mapped["ScanRun"] = relationship(back_populates="stages")


class ScanResult(Base):
    """Artifact report produced by a single scan pipeline stage."""

    __tablename__ = "scan_results"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "stage", name="uq_scan_results_run_stage"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Pipeline stage: discover / probe / portscan / inspect / score
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    report: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    # Relationships
    scan_run: Mapped["ScanRun"] = relationship(back_populates="results")


class ScanChange(Base):
    """Structured change detected between two consecutive succeeded scans of a domain."""

    __tablename__ = "scan_changes"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "change_type",
            "asset",
            "detail",
            name="uq_scan_changes_run_type_asset_detail",
        ),
        Index("ix_scan_changes_domain_observed", "domain_id", text("observed_at DESC")),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    baseline_scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    change_type: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    asset: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    detail: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    evidence: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    new_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    # Relationships
    domain: Mapped["Domain"] = relationship(back_populates="changes")
    scan_run: Mapped["ScanRun"] = relationship(
        foreign_keys=[scan_run_id],
        back_populates="changes",
    )
    baseline_scan_run: Mapped["ScanRun"] = relationship(
        foreign_keys=[baseline_scan_run_id],
    )


class AlertNotification(Base):
    """Transactional outbox record for scan change email alerts."""

    __tablename__ = "alert_notifications"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "recipient",
            name="uq_alert_notifications_run_recipient",
        ),
        Index(
            "ix_alert_notifications_due",
            "next_attempt_at",
            postgresql_where=text("status = 'pending'"),
        ),
        Index("ix_alert_notifications_domain_created", "domain_id", text("created_at DESC")),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    recipient: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="pending", nullable=False, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    last_error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    # Relationships
    domain: Mapped["Domain"] = relationship(back_populates="alert_notifications")
    scan_run: Mapped["ScanRun"] = relationship(back_populates="alert_notifications")

