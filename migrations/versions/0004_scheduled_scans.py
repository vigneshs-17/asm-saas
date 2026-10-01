"""scheduled scans

Revision ID: 0004_scheduled_scans
Revises: 0003_change_detection
Create Date: 2026-10-01 09:30:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_scheduled_scans"
down_revision: str | None = "0003_change_detection"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add scan_interval_hours and next_scan_at columns to domains
    op.add_column("domains", sa.Column("scan_interval_hours", sa.Integer(), nullable=True))
    op.add_column("domains", sa.Column("next_scan_at", sa.DateTime(timezone=True), nullable=True))

    # 2. Add check constraint on scan_interval_hours (null or between 6 and 720)
    op.create_check_constraint(
        "ck_domains_scan_interval_hours",
        "domains",
        "scan_interval_hours IS NULL OR (scan_interval_hours >= 6 AND scan_interval_hours <= 720)",
    )

    # 3. Create indexes on domains
    op.create_index("ix_domains_next_scan_at", "domains", ["next_scan_at"], unique=False)
    op.create_index(
        "ix_domains_schedule_due",
        "domains",
        ["next_scan_at"],
        unique=False,
        postgresql_where=sa.text("authorized = true AND scan_interval_hours IS NOT NULL"),
    )

    # 4. Add trigger column to scan_runs
    op.add_column(
        "scan_runs",
        sa.Column("trigger", sa.String(length=20), server_default="manual", nullable=False),
    )


def downgrade() -> None:
    # 1. Drop trigger column from scan_runs
    op.drop_column("scan_runs", "trigger")

    # 2. Drop indexes from domains
    op.drop_index(
        "ix_domains_schedule_due",
        table_name="domains",
        postgresql_where=sa.text("authorized = true AND scan_interval_hours IS NOT NULL"),
    )
    op.drop_index("ix_domains_next_scan_at", table_name="domains")

    # 3. Drop check constraint from domains
    op.drop_constraint("ck_domains_scan_interval_hours", "domains", type_="check")

    # 4. Drop columns from domains
    op.drop_column("domains", "next_scan_at")
    op.drop_column("domains", "scan_interval_hours")
