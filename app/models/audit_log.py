"""
TRACKIT Audit Log Model.

Stores security and application audit events.

Security principles:

- Never store passwords.
- Never store password hashes.
- Never store JWTs.
- Never store verification tokens.
- Never store password-reset tokens.
- Store only information necessary for security auditing.
"""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class AuditLog(Base):
    """
    TRACKIT security and application audit event.
    """

    __tablename__ = "audit_logs"

    # ========================================================================
    # Primary Key
    # ========================================================================

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    # ========================================================================
    # Event Information
    # ========================================================================

    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    # Keep existing application code working:
    #
    # event_type -> database column "action"
    event_type = synonym("action")

    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )

    details: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Keep existing application code working:
    #
    # description -> database column "details"
    description = synonym("details")

    resource_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )

    resource_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )

    # ========================================================================
    # User Association
    # ========================================================================

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    user: Mapped["User | None"] = relationship(
        "User",
        back_populates="audit_logs",
    )

    # ========================================================================
    # Request Information
    # ========================================================================

    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    user_agent: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # ========================================================================
    # Timestamp
    # ========================================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
