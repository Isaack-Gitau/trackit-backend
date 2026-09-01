"""
TRACKIT Match Database Model.

Represents a potential match between a LOST item and a FOUND item.

Matching is informational and does not automatically create or modify
claims. Claims remain a separate user/admin workflow.
"""

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Match(Base):
    """
    Potential relationship between one LOST item and one FOUND item.

    A match stores both the overall score and the individual scoring
    components so that the result can be explained and tested.

    Match lifecycle is intentionally separate from Claim lifecycle.
    """

    __tablename__ = "matches"

    # ========================================================================
    # Primary Key
    # ========================================================================

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    # ========================================================================
    # Lost Item
    # ========================================================================

    lost_item_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey(
            "items.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # Found Item
    # ========================================================================

    found_item_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey(
            "items.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # Overall Match Score
    # ========================================================================

    score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    # ========================================================================
    # Match Classification
    # ========================================================================

    match_level: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    # ========================================================================
    # Individual Scores
    # ========================================================================

    category_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    title_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    description_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    location_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    time_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    # ========================================================================
    # Explanation
    # ========================================================================

    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # ========================================================================
    # User Dismissal
    # ========================================================================

    is_dismissed: Mapped[bool] = mapped_column(
        default=False,
        server_default="false",
        nullable=False,
        index=True,
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

    lost_item = relationship(
        "Item",
        foreign_keys=[lost_item_id],
        back_populates="matches_as_lost",
    )

    found_item = relationship(
        "Item",
        foreign_keys=[found_item_id],
        back_populates="matches_as_found",
    )

    # ========================================================================
    # Database Constraints / Indexes
    # ========================================================================

    __table_args__ = (
        UniqueConstraint(
            "lost_item_id",
            "found_item_id",
            name="uq_matches_lost_found",
        ),
        Index(
            "ix_matches_lost_score",
            "lost_item_id",
            "score",
        ),
        Index(
            "ix_matches_found_score",
            "found_item_id",
            "score",
        ),
    )
