"""
TRACKIT Report Database Model.

Represents a user's report against an item.

Security principles:

- Reporter identity comes from the authenticated user.
- Report status is controlled by the service layer.
- Reviewer identity is controlled by the server.
- Users cannot directly set review fields.
- Reports remain available for administrative accountability.
"""

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Report(Base):
    """
    TRACKIT item report.

    Lifecycle:

        pending
            ↓
        reviewed
            ↓
        resolved
    """

    __tablename__ = "reports"

    # ========================================================================
    # Primary Key
    # ========================================================================

    id: Mapped[int] = mapped_column(
        primary_key=True,
    )

    # ========================================================================
    # Reported Item
    # ========================================================================

    item_id: Mapped[int] = mapped_column(
        ForeignKey(
            "items.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    # ========================================================================
    # Reporter
    # ========================================================================

    reporter_id: Mapped[int] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    # ========================================================================
    # Report Information
    # ========================================================================

    reason: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # ========================================================================
    # Report Status
    # ========================================================================

    status: Mapped[str] = mapped_column(
        String(30),
        default="pending",
        server_default="pending",
        nullable=False,
    )

    # ========================================================================
    # Administrative Review
    # ========================================================================

    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    resolution_note: Mapped[str | None] = mapped_column(
        Text,
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
        back_populates="reports",
    )

    reporter = relationship(
        "User",
        foreign_keys=[reporter_id],
        back_populates="reports",
    )

    reviewer = relationship(
        "User",
        foreign_keys=[reviewed_by],
        back_populates="reviewed_reports",
    )

    # ========================================================================
    # Database Indexes
    # ========================================================================

    __table_args__ = (
        Index(
            "ix_reports_item_status",
            "item_id",
            "status",
        ),
        Index(
            "ix_reports_reporter_status",
            "reporter_id",
            "status",
        ),
    )