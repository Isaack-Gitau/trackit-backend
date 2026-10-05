"""Add subject user to audit logs.

Revision ID: a1c7e9f42b31
Revises: 9d088f18d8a8
Create Date: 2026-10-02
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a1c7e9f42b31"
down_revision: Union[str, Sequence[str], None] = "9d088f18d8a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the affected/subject user association to audit logs."""

    op.add_column(
        "audit_logs",
        sa.Column(
            "subject_user_id",
            sa.Integer(),
            nullable=True,
        ),
    )

    op.create_index(
        op.f("ix_audit_logs_subject_user_id"),
        "audit_logs",
        ["subject_user_id"],
        unique=False,
    )

    op.create_foreign_key(
        "fk_audit_logs_subject_user_id_users",
        "audit_logs",
        "users",
        ["subject_user_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    """Remove the audit log subject user association."""

    op.drop_constraint(
        "fk_audit_logs_subject_user_id_users",
        "audit_logs",
        type_="foreignkey",
    )

    op.drop_index(
        op.f("ix_audit_logs_subject_user_id"),
        table_name="audit_logs",
    )

    op.drop_column(
        "audit_logs",
        "subject_user_id",
    )
