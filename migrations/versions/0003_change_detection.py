"""change detection

Revision ID: 0003_change_detection
Revises: 0002_scan_jobs_lifecycle
Create Date: 2026-10-01 08:00:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0003_change_detection"
down_revision: str | None = "0002_scan_jobs_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add change_detection JSONB column to scan_runs
    op.add_column(
        "scan_runs",
        sa.Column("change_detection", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    # 2. Create scan_changes table
    op.create_table(
        "scan_changes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("scan_run_id", sa.Integer(), nullable=False),
        sa.Column("baseline_scan_run_id", sa.Integer(), nullable=False),
        sa.Column("change_type", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("asset", sa.String(length=255), nullable=False),
        sa.Column("detail", sa.String(length=128), server_default="", nullable=False),
        sa.Column("evidence", sa.String(length=64), nullable=False),
        sa.Column("previous_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("new_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["baseline_scan_run_id"],
            ["scan_runs.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_run_id",
            "change_type",
            "asset",
            "detail",
            name="uq_scan_changes_run_type_asset_detail",
        ),
    )
    op.create_index(op.f("ix_scan_changes_asset"), "scan_changes", ["asset"], unique=False)
    op.create_index(
        op.f("ix_scan_changes_baseline_scan_run_id"),
        "scan_changes",
        ["baseline_scan_run_id"],
        unique=False,
    )
    op.create_index(op.f("ix_scan_changes_category"), "scan_changes", ["category"], unique=False)
    op.create_index(op.f("ix_scan_changes_domain_id"), "scan_changes", ["domain_id"], unique=False)
    op.create_index(
        "ix_scan_changes_domain_observed",
        "scan_changes",
        ["domain_id", sa.text("observed_at DESC")],
        unique=False,
    )
    op.create_index(
        op.f("ix_scan_changes_scan_run_id"),
        "scan_changes",
        ["scan_run_id"],
        unique=False,
    )
    op.create_index(op.f("ix_scan_changes_severity"), "scan_changes", ["severity"], unique=False)


def downgrade() -> None:
    # 2. Drop scan_changes table and indexes
    op.drop_index(op.f("ix_scan_changes_severity"), table_name="scan_changes")
    op.drop_index(op.f("ix_scan_changes_scan_run_id"), table_name="scan_changes")
    op.drop_index("ix_scan_changes_domain_observed", table_name="scan_changes")
    op.drop_index(op.f("ix_scan_changes_domain_id"), table_name="scan_changes")
    op.drop_index(op.f("ix_scan_changes_category"), table_name="scan_changes")
    op.drop_index(op.f("ix_scan_changes_baseline_scan_run_id"), table_name="scan_changes")
    op.drop_index(op.f("ix_scan_changes_asset"), table_name="scan_changes")
    op.drop_table("scan_changes")

    # 1. Drop change_detection column from scan_runs
    op.drop_column("scan_runs", "change_detection")
