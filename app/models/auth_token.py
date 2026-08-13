"""
TRACKIT Authentication Token Model.

Stores hashed, short-lived authentication tokens used for
email verification and password reset operations.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AuthToken(Base):
    """
    Authentication token stored securely in the database.

    The raw token is NEVER stored.

    Only a SHA-256 hash is persisted.

    A token is considered:

    - unused when used_at IS NULL
    - consumed when used_at contains a timestamp
    - expired when expires_at is in the past
    """

    __tablename__ = "auth_tokens"

    # ------------------------------------------------------------------
    # Primary Key
    # ------------------------------------------------------------------

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    # ------------------------------------------------------------------
    # User Relationship
    # ------------------------------------------------------------------

    user_id: Mapped[int] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # ------------------------------------------------------------------
    # Token Data
    # ------------------------------------------------------------------

    token_hash: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
    )

    token_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    # ------------------------------------------------------------------
    # Expiration
    # ------------------------------------------------------------------

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # ------------------------------------------------------------------
    # Consumption
    # ------------------------------------------------------------------

    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # ------------------------------------------------------------------
    # Timestamp
    # ------------------------------------------------------------------

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # ------------------------------------------------------------------
    # Relationship
    # ------------------------------------------------------------------

    user = relationship(
        "User",
        back_populates="auth_tokens",
    )