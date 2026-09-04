"""
TRACKIT Item Database Model.

Represents a lost or found item posted by a user.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Item(Base):
    """
    TRACKIT lost/found item.

    Items move through a server-controlled moderation lifecycle:

    pending  -> approved
    pending  -> rejected
    approved -> pending   (after a substantive owner edit)
    rejected -> pending   (after a corrective owner edit)
    approved -> claimed
    """

    __tablename__ = "items"

    # ========================================================================
    # Primary Key
    # ========================================================================

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    # ========================================================================
    # Ownership
    # ========================================================================

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # Item Information
    # ========================================================================

    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    category: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    location: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # ========================================================================
    # Media
    # ========================================================================

    image: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # ========================================================================
    # Moderation Lifecycle
    # ========================================================================

    status: Mapped[str] = mapped_column(
        String(30),
        default="pending",
        server_default="pending",
        nullable=False,
    )

    rejection_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ========================================================================
    # Timestamps
    # ========================================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # ========================================================================
    # Relationships
    # ========================================================================

    owner = relationship(
        "User",
        foreign_keys=[user_id],
        back_populates="items",
    )

    reviewer = relationship(
        "User",
        foreign_keys=[reviewed_by],
        back_populates="reviewed_items",
    )

    claims = relationship(
        "Claim",
        back_populates="item",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    reports = relationship(
        "Report",
        back_populates="item",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    matches_as_lost = relationship(
        "Match",
        foreign_keys="Match.lost_item_id",
        back_populates="lost_item",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    matches_as_found = relationship(
        "Match",
        foreign_keys="Match.found_item_id",
        back_populates="found_item",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )