"""
add notification context fields

Revision ID: fb3cc032d7aa
Revises: 20467d589245
Create Date: 2026-08-31 01:19:57.181814

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# ============================================================================
# REVISION IDENTIFIERS
# ============================================================================

revision: str = "fb3cc032d7aa"
down_revision: Union[str, Sequence[str], None] = "20467d589245"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ============================================================================
# UPGRADE
# ============================================================================


def upgrade() -> None:
    """
    Add contextual information to notifications.

    New fields:

    - category:
        Broad notification grouping such as claim, item, account,
        security, or system.

    - priority:
        Notification importance: low, normal, high, or urgent.

    - entity_type:
        Optional type of application object associated with the
        notification, such as claim or item.

    - entity_id:
        Optional ID of the associated application object.

    - read_at:
        Timestamp recording when the notification was marked as read.

    Existing notification records are preserved.

    Existing notification types are mapped to appropriate categories
    and priorities before category and priority are made non-null.
    """

    # ------------------------------------------------------------------------
    # CATEGORY
    # ------------------------------------------------------------------------

    op.add_column(
        "notifications",
        sa.Column(
            "category",
            sa.String(length=30),
            server_default=sa.text("'system'"),
            nullable=False,
        ),
    )

    # ------------------------------------------------------------------------
    # PRIORITY
    # ------------------------------------------------------------------------

    op.add_column(
        "notifications",
        sa.Column(
            "priority",
            sa.String(length=20),
            server_default=sa.text("'normal'"),
            nullable=False,
        ),
    )

    # ------------------------------------------------------------------------
    # RELATED ENTITY
    # ------------------------------------------------------------------------

    op.add_column(
        "notifications",
        sa.Column(
            "entity_type",
            sa.String(length=50),
            nullable=True,
        ),
    )

    op.add_column(
        "notifications",
        sa.Column(
            "entity_id",
            sa.Integer(),
            nullable=True,
        ),
    )

    # ------------------------------------------------------------------------
    # READ TIMESTAMP
    # ------------------------------------------------------------------------

    op.add_column(
        "notifications",
        sa.Column(
            "read_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # ------------------------------------------------------------------------
    # BACKFILL EXISTING NOTIFICATIONS
    # ------------------------------------------------------------------------

    # Claim notifications.
    op.execute(
        """
        UPDATE notifications
        SET
            category = 'claim'
        WHERE type IN (
            'claim_created',
            'claim_approved',
            'claim_rejected',
            'claim_withdrawn'
        )
        """
    )

    # Item notifications.
    op.execute(
        """
        UPDATE notifications
        SET
            category = 'item'
        WHERE type IN (
            'item_approved',
            'item_rejected'
        )
        """
    )

    # Claim creation is a normal event.
    op.execute(
        """
        UPDATE notifications
        SET
            priority = 'normal'
        WHERE type = 'claim_created'
        """
    )

    # Claim approval is important to the claimant.
    op.execute(
        """
        UPDATE notifications
        SET
            priority = 'high'
        WHERE type = 'claim_approved'
        """
    )

    # Claim rejection is important to the claimant.
    op.execute(
        """
        UPDATE notifications
        SET
            priority = 'high'
        WHERE type = 'claim_rejected'
        """
    )

    # Claim withdrawal is a normal lifecycle event.
    op.execute(
        """
        UPDATE notifications
        SET
            priority = 'normal'
        WHERE type = 'claim_withdrawn'
        """
    )

    # Item moderation decisions are important to the item owner.
    op.execute(
        """
        UPDATE notifications
        SET
            priority = 'high'
        WHERE type IN (
            'item_approved',
            'item_rejected'
        )
        """
    )

    # ------------------------------------------------------------------------
    # BACKFILL RELATED ENTITY INFORMATION
    # ------------------------------------------------------------------------

    # Existing claim notifications refer to a claim, but the original
    # notification implementation did not store the claim ID.
    #
    # Therefore entity_id intentionally remains NULL for historical
    # notifications. New claim notifications will populate it once
    # Notification 2.0 service integration is implemented.
    #
    # The same applies to historical item notifications.

    # ------------------------------------------------------------------------
    # INDEXES
    # ------------------------------------------------------------------------

    op.create_index(
        "ix_notifications_category",
        "notifications",
        ["category"],
        unique=False,
    )

    op.create_index(
        "ix_notifications_priority",
        "notifications",
        ["priority"],
        unique=False,
    )

    op.create_index(
        "ix_notifications_entity",
        "notifications",
        ["entity_type", "entity_id"],
        unique=False,
    )

    # Useful when retrieving unread notifications and checking read time.
    op.create_index(
        "ix_notifications_read_at",
        "notifications",
        ["read_at"],
        unique=False,
    )


# ============================================================================
# DOWNGRADE
# ============================================================================


def downgrade() -> None:
    """
    Remove notification context fields and their indexes.

    Existing notification records are preserved, but the contextual
    fields introduced by this migration are removed.
    """

    # Drop indexes before dropping their associated columns.

    op.drop_index(
        "ix_notifications_read_at",
        table_name="notifications",
    )

    op.drop_index(
        "ix_notifications_entity",
        table_name="notifications",
    )

    op.drop_index(
        "ix_notifications_priority",
        table_name="notifications",
    )

    op.drop_index(
        "ix_notifications_category",
        table_name="notifications",
    )

    # Drop contextual columns.

    op.drop_column(
        "notifications",
        "read_at",
    )

    op.drop_column(
        "notifications",
        "entity_id",
    )

    op.drop_column(
        "notifications",
        "entity_type",
    )

    op.drop_column(
        "notifications",
        "priority",
    )

    op.drop_column(
        "notifications",
        "category",
    )