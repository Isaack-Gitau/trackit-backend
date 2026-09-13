"""
TRACKIT Claim Database Model.

Represents a user's claim against a FOUND item.

Security principles:

- claimant_id is determined from the authenticated user.
- reviewer identity is controlled by the server.
- Claim status is controlled by the service layer.
- Raw authentication credentials are never stored here.
- Rejection reasons are retained for accountability.
- Review history survives reviewer-account deletion through
  ON DELETE SET NULL.
"""

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Claim(Base):
    """
    TRACKIT lost-and-found claim.

    A claim represents a user's assertion that a FOUND item
    belongs to them.

    Lifecycle:

        pending
            ├── approved
            ├── rejected
            └── withdrawn
    """

    __tablename__ = "claims"

    # ========================================================================
    # Primary Key
    # ========================================================================

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    # ========================================================================
    # Item Being Claimed
    # ========================================================================

    item_id: Mapped[int] = mapped_column(
        ForeignKey(
            "items.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # Claimant
    # ========================================================================

    claimant_id: Mapped[int] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # Claim Information
    # ========================================================================

    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # ========================================================================
    # Claim Status
    # ========================================================================

    status: Mapped[str] = mapped_column(
        String(30),
        default="pending",
        server_default="pending",
        nullable=False,
        index=True,
    )

    # ========================================================================
    # Administrative Review
    # ========================================================================

    rejection_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
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

    item = relationship(
        "Item",
        back_populates="claims",
    )

    claimant = relationship(
        "User",
        foreign_keys=[claimant_id],
        back_populates="claims",
    )

    reviewer = relationship(
        "User",
        foreign_keys=[reviewed_by],
        back_populates="reviewed_claims",
    )

    # ========================================================================
    # Database Indexes
    # ========================================================================

    __table_args__ = (
        Index(
            "ix_claims_item_status",
            "item_id",
            "status",
        ),
        Index(
            "ix_claims_claimant_status",
            "claimant_id",
            "status",
        ),
        Index(
            "uq_claims_active_claimant_item",
            "claimant_id",
            "item_id",
            unique=True,
            postgresql_where=text(
                "status IN ('pending', 'approved')"
            ),
        ),
        Index(
            "uq_claims_approved_item",
            "item_id",
            unique=True,
            postgresql_where=text(
                "status = 'approved'"
            ),
        ),
    )
