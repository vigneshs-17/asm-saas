"""SQLAlchemy 2.0 declarative models for ASM SaaS."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
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

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    # Fail-safe default is False; explicit authorization is strictly required
    authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_note: Mapped[str | None] = mapped_column(Text, nullable=True)
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


class ScanRun(Base):
    """Represents a scheduled or active multi-stage scan execution for a domain."""

    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Status lifecycle: queued -> running -> succeeded / failed
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    domain: Mapped["Domain"] = relationship(back_populates="scan_runs")
    results: Mapped[list["ScanResult"]] = relationship(
        back_populates="scan_run",
        cascade="all, delete-orphan",
        order_by="ScanResult.id.asc()",
    )


class ScanResult(Base):
    """Artifact report produced by a single scan pipeline stage."""

    __tablename__ = "scan_results"

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
