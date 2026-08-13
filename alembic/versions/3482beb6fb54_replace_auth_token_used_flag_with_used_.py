"""replace auth token used flag with used timestamp

Revision ID: 3482beb6fb54
Revises: 9f037f3ed448
Create Date: 2026-08-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "3482beb6fb54"
down_revision: Union[str, Sequence[str], None] = "9f037f3ed448"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade database schema."""

    # Add the new timestamp column.
    op.add_column(
        "auth_tokens",
        sa.Column(
            "used_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # Preserve the state of any tokens that were already marked as used.
    op.execute(
        """
        UPDATE auth_tokens
        SET used_at = NOW()
        WHERE used = TRUE
        """
    )

    # Remove the old boolean column.
    op.drop_column("auth_tokens", "used")


def downgrade() -> None:
    """Downgrade database schema."""

    # Re-create the old boolean column.
    op.add_column(
        "auth_tokens",
        sa.Column(
            "used",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    # Restore used=True for tokens that had a used_at timestamp.
    op.execute(
        """
        UPDATE auth_tokens
        SET used = TRUE
        WHERE used_at IS NOT NULL
        """
    )

    # Remove the timestamp column.
    op.drop_column("auth_tokens", "used_at")