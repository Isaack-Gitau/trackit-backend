"""Add claim integrity constraints

Revision ID: 9d088f18d8a8
Revises: c0b602c5a77c
Create Date: 2026-09-13
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "9d088f18d8a8"
down_revision: Union[str, Sequence[str], None] = "c0b602c5a77c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add database-level claim integrity constraints."""

    op.create_index(
        "uq_claims_active_claimant_item",
        "claims",
        ["claimant_id", "item_id"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('pending', 'approved')"
        ),
    )

    op.create_index(
        "uq_claims_approved_item",
        "claims",
        ["item_id"],
        unique=True,
        postgresql_where=sa.text(
            "status = 'approved'"
        ),
    )


def downgrade() -> None:
    """Remove database-level claim integrity constraints."""

    op.drop_index(
        "uq_claims_approved_item",
        table_name="claims",
    )

    op.drop_index(
        "uq_claims_active_claimant_item",
        table_name="claims",
    )
