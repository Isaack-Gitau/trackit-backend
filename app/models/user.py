"""
TRACKIT User Database Model.

Defines the User entity used by the authentication,
authorization, and lost-and-found modules.

Security principles:
- Passwords are stored only as Argon2 hashes.
- Authentication tokens are never stored on the User model.
- Short-lived verification/reset tokens are stored in auth_tokens.
- token_version supports JWT invalidation.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.audit_log import AuditLog


class User(Base):
    """
    TRACKIT application user.

    A user may:
    - own lost/found item posts
    - authenticate using username or email
    - verify their email address
    - reset their password
    - have a role controlling authorization
    """

    __tablename__ = "users"

    # ========================================================================
    # Primary Key
    # ========================================================================

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    # ========================================================================
    # Identity
    # ========================================================================

    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        index=True,
        nullable=False,
    )

    first_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    last_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    # ========================================================================
    # Authentication
    # ========================================================================

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # ========================================================================
    # Authorization
    # ========================================================================

    role: Mapped[str] = mapped_column(
        String(30),
        default="user",
        server_default="user",
        nullable=False,
    )

    # ========================================================================
    # Account Status
    # ========================================================================

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default="true",
        nullable=False,
    )

    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        nullable=False,
    )

    # ========================================================================
    # Security Auditing
    # ========================================================================

    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    """
    JWT security version.

    Incrementing this value invalidates previously issued
    JWT access tokens when token validation checks the version.
    """

    token_version: Mapped[int] = mapped_column(
        default=0,
        server_default="0",
        nullable=False,
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

    items = relationship(
        "Item",
        back_populates="owner",
        cascade="all, delete-orphan",
    )

    auth_tokens = relationship(
        "AuthToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="user",
    )

    claims = relationship(
        "Claim",
        foreign_keys="Claim.claimant_id",
        back_populates="claimant",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    reviewed_claims = relationship(
        "Claim",
        foreign_keys="Claim.reviewed_by",
        back_populates="reviewer",
        passive_deletes=True,
    )

    reports = relationship(
        "Report",
        foreign_keys="Report.reporter_id",
        back_populates="reporter",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    reviewed_reports = relationship(
        "Report",
        foreign_keys="Report.reviewed_by",
        back_populates="reviewer",
        passive_deletes=True,
    )

    notifications = relationship(
        "Notification",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

