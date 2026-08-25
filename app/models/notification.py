"""
TRACKIT Notification Database Model.

Stores in-app notifications delivered to authenticated users.

Notifications are persistent application records and are separate
from security audit logs.

Security principles:

- Notifications belong to exactly one user.
- Notification ownership is enforced through user_id.
- Notification content must never contain passwords, JWTs,
  authentication tokens, or other secrets.
- Read state is controlled by the notification owner.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Notification(Base):
    """
    Persistent in-app notification.

    A notification represents an event that should be surfaced
    to a specific TRACKIT user.
    """

    __tablename__ = "notifications"

    # ========================================================================
    # Primary Key
    # ========================================================================

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    # ========================================================================
    # Recipient
    # ========================================================================

    user_id: Mapped[int] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # Notification Type
    # ========================================================================

    type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # Notification Content
    # ========================================================================

    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # ========================================================================
    # Read State
    # ========================================================================

    is_read: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        nullable=False,
        index=True,
    )

    # ========================================================================
    # Timestamp
    # ========================================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # Relationships
    # ========================================================================

    user = relationship(
        "User",
        back_populates="notifications",
    )

    # ========================================================================
    # Database Indexes
    # ========================================================================

    __table_args__ = (
        Index(
            "ix_notifications_user_read_created",
            "user_id",
            "is_read",
            "created_at",
        ),
    )