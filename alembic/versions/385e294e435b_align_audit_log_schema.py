"""align audit log schema

Revision ID: 385e294e435b
Revises: 7e4d79ec6196
Create Date: 2026-08-21 18:51:27.243911

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "385e294e435b"
down_revision: Union[str, Sequence[str], None] = "7e4d79ec6196"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Align the audit_logs database schema with the AuditLog model."""

    # Preserve existing audit data by renaming the old columns.
    op.alter_column(
        "audit_logs",
        "event_type",
        new_column_name="action",
        existing_type=sa.String(length=100),
        existing_nullable=False,
    )

    op.alter_column(
        "audit_logs",
        "description",
        new_column_name="details",
        existing_type=sa.Text(),
        existing_nullable=True,
    )

    # Add resource information supported by the new AuditLog model.
    op.add_column(
        "audit_logs",
        sa.Column(
            "resource_type",
            sa.String(length=100),
            nullable=True,
        ),
    )

    op.add_column(
        "audit_logs",
        sa.Column(
            "resource_id",
            sa.Integer(),
            nullable=True,
        ),
    )

    # Replace the old event_type index with the new action index.
    op.drop_index(
        op.f("ix_audit_logs_event_type"),
        table_name="audit_logs",
    )

    op.create_index(
        op.f("ix_audit_logs_action"),
        "audit_logs",
        ["action"],
        unique=False,
    )

    op.create_index(
        op.f("ix_audit_logs_resource_id"),
        "audit_logs",
        ["resource_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_audit_logs_resource_type"),
        "audit_logs",
        ["resource_type"],
        unique=False,
    )

def downgrade() -> None:
    """Restore the previous audit_logs schema."""

    op.drop_index(
        op.f("ix_audit_logs_resource_type"),
        table_name="audit_logs",
    )

    op.drop_index(
        op.f("ix_audit_logs_resource_id"),
        table_name="audit_logs",
    )

    op.drop_index(
        op.f("ix_audit_logs_action"),
        table_name="audit_logs",
    )

    op.alter_column(
        "audit_logs",
        "action",
        new_column_name="event_type",
        existing_type=sa.String(length=100),
        existing_nullable=False,
    )

    op.alter_column(
        "audit_logs",
        "details",
        new_column_name="description",
        existing_type=sa.Text(),
        existing_nullable=True,
    )

    op.create_index(
        op.f("ix_audit_logs_event_type"),
        "audit_logs",
        ["event_type"],
        unique=False,
    )

    op.drop_column(
        "audit_logs",
        "resource_id",
    )

    op.drop_column(
        "audit_logs",
        "resource_type",
    )