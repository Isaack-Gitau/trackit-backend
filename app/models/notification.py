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
- Notification context contains only non-sensitive application metadata.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
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
    # PRIMARY KEY
    # ========================================================================

    id: Mapped[int] = mapped_column(
        primary_key=True,
    )

    # ========================================================================
    # RECIPIENT
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
    # NOTIFICATION TYPE
    # ========================================================================

    type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # NOTIFICATION CATEGORY
    # ========================================================================

    category: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="system",
        server_default="system",
        index=True,
    )

    # ========================================================================
    # NOTIFICATION PRIORITY
    # ========================================================================

    priority: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="normal",
        server_default="normal",
        index=True,
    )

    # ========================================================================
    # RELATED ENTITY
    # ========================================================================

    entity_type: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    entity_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    # ========================================================================
    # NOTIFICATION CONTENT
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
    # READ STATE
    # ========================================================================

    is_read: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        nullable=False,
        index=True,
    )

    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # ========================================================================
    # TIMESTAMP
    # ========================================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # RELATIONSHIPS
    # ========================================================================

    user = relationship(
        "User",
        back_populates="notifications",
    )

    # ========================================================================
    # DATABASE INDEXES
    # ========================================================================

    __table_args__ = (
        Index(
            "ix_notifications_user_read_created",
            "user_id",
            "is_read",
            "created_at",
        ),
        Index(
            "ix_notifications_entity",
            "entity_type",
            "entity_id",
        ),
    )
