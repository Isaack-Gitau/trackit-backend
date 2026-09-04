"""create comments table

Revision ID: 7b6e1c4d9a21
Revises: c5255806686f
Create Date: 2026-09-04 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7b6e1c4d9a21"
down_revision: Union[str, Sequence[str], None] = "c5255806686f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the comments table and its integrity constraints."""

    op.create_table(
        "comments",
        sa.Column(
            "id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "item_id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "content",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "char_length(trim(content)) > 0",
            name="ck_comments_content_not_blank",
        ),
        sa.CheckConstraint(
            "char_length(content) <= 2000",
            name="ck_comments_content_max_length",
        ),
        sa.ForeignKeyConstraint(
            ["item_id"],
            ["items.id"],
            name="fk_comments_item_id_items",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_comments_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_comments_id",
        "comments",
        ["id"],
        unique=False,
    )

    op.create_index(
        "ix_comments_item_id",
        "comments",
        ["item_id"],
        unique=False,
    )

    op.create_index(
        "ix_comments_user_id",
        "comments",
        ["user_id"],
        unique=False,
    )

    op.create_index(
        "ix_comments_item_created_at",
        "comments",
        ["item_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the comments table."""

    op.drop_index(
        "ix_comments_item_created_at",
        table_name="comments",
    )

    op.drop_index(
        "ix_comments_user_id",
        table_name="comments",
    )

    op.drop_index(
        "ix_comments_item_id",
        table_name="comments",
    )

    op.drop_index(
        "ix_comments_id",
        table_name="comments",
    )

    op.drop_table("comments")