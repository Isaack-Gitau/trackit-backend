
"""add notifications

Revision ID: 20467d589245
Revises: b1112f9a92b9
Create Date: 2026-08-26 01:10:37.641005

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# ============================================================================
# REVISION IDENTIFIERS
# ============================================================================

revision: str = "20467d589245"
down_revision: Union[str, Sequence[str], None] = "b1112f9a92b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ============================================================================
# UPGRADE
# ============================================================================


def upgrade() -> None:
    """
    Create the notifications table.

    Notifications belong to users and are automatically deleted
    when their associated user is deleted.

    The table supports:
    - notification type
    - notification title
    - notification message
    - read/unread state
    - creation timestamp
    """

    op.create_table(
        "notifications",
        sa.Column(
            "id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "type",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "title",
            sa.String(length=200),
            nullable=False,
        ),
        sa.Column(
            "message",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "is_read",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # ------------------------------------------------------------------------
    # INDEXES
    # ------------------------------------------------------------------------

    # Useful for chronological notification queries.
    op.create_index(
        "ix_notifications_created_at",
        "notifications",
        ["created_at"],
        unique=False,
    )

    # Useful for filtering unread/read notifications.
    op.create_index(
        "ix_notifications_is_read",
        "notifications",
        ["is_read"],
        unique=False,
    )

    # Useful for filtering notifications by event type.
    op.create_index(
        "ix_notifications_type",
        "notifications",
        ["type"],
        unique=False,
    )

    # Useful for retrieving notifications belonging to a user.
    op.create_index(
        "ix_notifications_user_id",
        "notifications",
        ["user_id"],
        unique=False,
    )

    # Optimized for the user's notification inbox:
    #
    # WHERE user_id = ?
    #   AND is_read = false
    # ORDER BY created_at DESC
    #
    op.create_index(
        "ix_notifications_user_read_created",
        "notifications",
        ["user_id", "is_read", "created_at"],
        unique=False,
    )


# ============================================================================
# DOWNGRADE
# ============================================================================


def downgrade() -> None:
    """
    Remove the notifications table and all associated indexes.
    """

    # Drop indexes before dropping the table.
    op.drop_index(
        "ix_notifications_user_read_created",
        table_name="notifications",
    )

    op.drop_index(
        "ix_notifications_user_id",
        table_name="notifications",
    )

    op.drop_index(
        "ix_notifications_type",
        table_name="notifications",
    )

    op.drop_index(
        "ix_notifications_is_read",
        table_name="notifications",
    )

    op.drop_index(
        "ix_notifications_created_at",
        table_name="notifications",
    )

    # Drop the notifications table.
    op.drop_table("notifications")

