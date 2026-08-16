"""
Add PostgreSQL server default to audit_logs.success.

Revision ID: e5ffd92b15cb
Revises: cce39e14edf7
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "e5ffd92b15cb"
down_revision = "cce39e14edf7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Add a PostgreSQL-level TRUE default to audit_logs.success.
    """

    op.execute(
        """
        ALTER TABLE audit_logs
        ALTER COLUMN success
        SET DEFAULT TRUE
        """
    )


def downgrade() -> None:
    """
    Remove the PostgreSQL-level default from audit_logs.success.
    """

    op.execute(
        """
        ALTER TABLE audit_logs
        ALTER COLUMN success
        DROP DEFAULT
        """
    )