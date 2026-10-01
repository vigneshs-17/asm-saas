"""alert notifications outbox

Revision ID: 0005_alert_notifications
Revises: 0004_scheduled_scans
Create Date: 2026-10-01 10:00:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0005_alert_notifications"
down_revision: str | None = "0004_scheduled_scans"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add alert settings columns to domains
    op.add_column(
        "domains",
        sa.Column("alerts_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.add_column(
        "domains",
        sa.Column(
            "alert_emails",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "domains",
        sa.Column(
            "alert_min_severity",
            sa.String(length=16),
            server_default="MEDIUM",
            nullable=False,
        ),
    )

    # 2. Add check constraints on domains
    op.create_check_constraint(
        "ck_domains_alert_min_severity",
        "domains",
        "alert_min_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
    )
    op.create_check_constraint(
        "ck_domains_alert_emails_count",
        "domains",
        "alerts_enabled = false OR (jsonb_typeof(alert_emails) = 'array' AND "
        "jsonb_array_length(alert_emails) >= 1 AND jsonb_array_length(alert_emails) <= 5)",
    )

    # 3. Create alert_notifications table
    op.create_table(
        "alert_notifications",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("scan_run_id", sa.Integer(), nullable=False),
        sa.Column("recipient", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default=sa.text("5"), nullable=False),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_error", sa.String(length=300), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_run_id", "recipient", name="uq_alert_notifications_run_recipient"
        ),
    )

    # 4. Create indexes on alert_notifications
    op.create_index(
        "ix_alert_notifications_domain_id", "alert_notifications", ["domain_id"], unique=False
    )
    op.create_index(
        "ix_alert_notifications_scan_run_id", "alert_notifications", ["scan_run_id"], unique=False
    )
    op.create_index(
        "ix_alert_notifications_status", "alert_notifications", ["status"], unique=False
    )
    op.create_index(
        "ix_alert_notifications_next_attempt_at",
        "alert_notifications",
        ["next_attempt_at"],
        unique=False,
    )
    op.create_index(
        "ix_alert_notifications_due",
        "alert_notifications",
        ["next_attempt_at"],
        unique=False,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_alert_notifications_domain_created",
        "alert_notifications",
        ["domain_id", sa.text("created_at DESC")],
        unique=False,
    )


def downgrade() -> None:
    # 1. Drop indexes and table alert_notifications
    op.drop_index("ix_alert_notifications_domain_created", table_name="alert_notifications")
    op.drop_index(
        "ix_alert_notifications_due",
        table_name="alert_notifications",
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.drop_index("ix_alert_notifications_next_attempt_at", table_name="alert_notifications")
    op.drop_index("ix_alert_notifications_status", table_name="alert_notifications")
    op.drop_index("ix_alert_notifications_scan_run_id", table_name="alert_notifications")
    op.drop_index("ix_alert_notifications_domain_id", table_name="alert_notifications")
    op.drop_table("alert_notifications")

    # 2. Drop check constraints and columns on domains
    op.drop_constraint("ck_domains_alert_emails_count", "domains", type_="check")
    op.drop_constraint("ck_domains_alert_min_severity", "domains", type_="check")
    op.drop_column("domains", "alert_min_severity")
    op.drop_column("domains", "alert_emails")
    op.drop_column("domains", "alerts_enabled")
