"""scan jobs lifecycle

Revision ID: 0002_scan_jobs_lifecycle
Revises: 0001_initial_schema
Create Date: 2026-09-30 08:00:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002_scan_jobs_lifecycle"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add worker claiming, fencing, retry, and idempotency columns to scan_runs
    op.add_column(
        "scan_runs",
        sa.Column("claim_token", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column("scan_runs", sa.Column("claimed_by", sa.String(length=128), nullable=True))
    op.add_column("scan_runs", sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "scan_runs",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scan_runs",
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column(
        "scan_runs",
        sa.Column("max_attempts", sa.Integer(), server_default=sa.text("3"), nullable=False),
    )
    op.add_column(
        "scan_runs",
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scan_runs",
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
    )

    # 2. Add partial unique and performance indexes on scan_runs
    op.create_index(
        "uq_scan_runs_active_domain",
        "scan_runs",
        ["domain_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    op.create_index(
        "uq_scan_runs_domain_idempotency",
        "scan_runs",
        ["domain_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.create_index(
        "ix_scan_runs_claimable",
        "scan_runs",
        ["created_at"],
        unique=False,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )

    # 3. Create scan_stages table for per-stage tracking
    op.create_table(
        "scan_stages",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_run_id", sa.Integer(), nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="pending", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_run_id", "stage", name="uq_scan_stages_run_stage"),
    )
    op.create_index(
        op.f("ix_scan_stages_scan_run_id"),
        "scan_stages",
        ["scan_run_id"],
        unique=False,
    )

    # 4. Add unique constraint to scan_results to prevent duplicate stage artifact writes
    op.create_unique_constraint(
        "uq_scan_results_run_stage", "scan_results", ["scan_run_id", "stage"]
    )


def downgrade() -> None:
    # 4. Drop unique constraint on scan_results
    op.drop_constraint("uq_scan_results_run_stage", "scan_results", type_="unique")

    # 3. Drop scan_stages table
    op.drop_index(op.f("ix_scan_stages_scan_run_id"), table_name="scan_stages")
    op.drop_table("scan_stages")

    # 2. Drop partial indexes on scan_runs
    op.drop_index("ix_scan_runs_claimable", table_name="scan_runs")
    op.drop_index("uq_scan_runs_domain_idempotency", table_name="scan_runs")
    op.drop_index("uq_scan_runs_active_domain", table_name="scan_runs")

    # 1. Drop added columns on scan_runs
    op.drop_column("scan_runs", "idempotency_key")
    op.drop_column("scan_runs", "next_attempt_at")
    op.drop_column("scan_runs", "max_attempts")
    op.drop_column("scan_runs", "attempts")
    op.drop_column("scan_runs", "lease_expires_at")
    op.drop_column("scan_runs", "claimed_at")
    op.drop_column("scan_runs", "claimed_by")
    op.drop_column("scan_runs", "claim_token")
