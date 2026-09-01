"""
TRACKIT Match Repository.

Database access layer for potential matches between LOST and FOUND items.

Business rules, authorization, matching calculations, and notification
decisions belong in the service layer.

This module is responsible only for querying and persisting Match records.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.match import Match


# ============================================================================
# CREATE
# ============================================================================


def create_match(
    db: Session,
    *,
    lost_item_id: int,
    found_item_id: int,
    score: int,
    match_level: str,
    category_score: int,
    title_score: int,
    description_score: int,
    location_score: int,
    time_score: int,
    reason: str,
) -> Match:
    """
    Create and persist a new match.

    The repository does not calculate the match score or decide whether
    the match should exist. Those decisions belong to the service layer.

    The database unique constraint on (lost_item_id, found_item_id)
    prevents duplicate match records.
    """

    match = Match(
        lost_item_id=lost_item_id,
        found_item_id=found_item_id,
        score=score,
        match_level=match_level,
        category_score=category_score,
        title_score=title_score,
        description_score=description_score,
        location_score=location_score,
        time_score=time_score,
        reason=reason,
    )

    db.add(match)
    db.flush()

    return match


# ============================================================================
# READ — SINGLE MATCH
# ============================================================================


def get_match_by_id(
    db: Session,
    match_id: int,
) -> Match | None:
    """
    Retrieve a match by its primary key.
    """

    return db.scalar(
        select(Match).where(Match.id == match_id)
    )


# ============================================================================
# READ — ITEM PAIR
# ============================================================================


def get_match_by_item_pair(
    db: Session,
    *,
    lost_item_id: int,
    found_item_id: int,
) -> Match | None:
    """
    Retrieve the match associated with a specific LOST/FOUND item pair.

    Returns None when no match exists.
    """

    statement = (
        select(Match)
        .where(
            Match.lost_item_id == lost_item_id,
            Match.found_item_id == found_item_id,
        )
    )

    return db.scalar(statement)


# ============================================================================
# READ — LOST ITEM
# ============================================================================


def get_matches_by_lost_item(
    db: Session,
    *,
    lost_item_id: int,
    include_dismissed: bool = False,
) -> list[Match]:
    """
    Retrieve matches associated with a LOST item.

    Results are returned highest score first and then newest first.

    By default, dismissed matches are excluded.
    """

    statement = select(Match).where(
        Match.lost_item_id == lost_item_id
    )

    if not include_dismissed:
        statement = statement.where(
            Match.is_dismissed.is_(False)
        )

    statement = statement.order_by(
        Match.score.desc(),
        Match.created_at.desc(),
    )

    return list(db.scalars(statement).all())


# ============================================================================
# READ — FOUND ITEM
# ============================================================================


def get_matches_by_found_item(
    db: Session,
    *,
    found_item_id: int,
    include_dismissed: bool = False,
) -> list[Match]:
    """
    Retrieve matches associated with a FOUND item.

    Results are returned highest score first and then newest first.

    By default, dismissed matches are excluded.
    """

    statement = select(Match).where(
        Match.found_item_id == found_item_id
    )

    if not include_dismissed:
        statement = statement.where(
            Match.is_dismissed.is_(False)
        )

    statement = statement.order_by(
        Match.score.desc(),
        Match.created_at.desc(),
    )

    return list(db.scalars(statement).all())


# ============================================================================
# READ — USER'S MATCHES
# ============================================================================


def get_matches_by_user_items(
    db: Session,
    *,
    user_id: int,
    include_dismissed: bool = False,
) -> list[Match]:
    """
    Retrieve matches involving items owned by a specific user.

    A match belongs to a user when the user owns either:

        - the LOST item, or
        - the FOUND item.

    The repository uses a subquery rather than loading the user's items
    into Python first.

    Authorization is still the responsibility of the service layer.
    """

    from app.models.item import Item

    owned_item_ids = select(Item.id).where(
        Item.user_id == user_id
    )

    statement = select(Match).where(
        (
            Match.lost_item_id.in_(owned_item_ids)
            | Match.found_item_id.in_(owned_item_ids)
        )
    )

    if not include_dismissed:
        statement = statement.where(
            Match.is_dismissed.is_(False)
        )

    statement = statement.order_by(
        Match.score.desc(),
        Match.created_at.desc(),
    )

    return list(db.scalars(statement).all())


# ============================================================================
# READ — STRONG MATCHES
# ============================================================================


def get_strong_matches(
    db: Session,
    *,
    minimum_score: int = 80,
    include_dismissed: bool = False,
) -> list[Match]:
    """
    Retrieve matches at or above the supplied score threshold.

    Intended primarily for service-level workflows that need to inspect
    strong potential matches.

    The default threshold corresponds to the V1 STRONG match level.
    """

    statement = select(Match).where(
        Match.score >= minimum_score
    )

    if not include_dismissed:
        statement = statement.where(
            Match.is_dismissed.is_(False)
        )

    statement = statement.order_by(
        Match.score.desc(),
        Match.created_at.desc(),
    )

    return list(db.scalars(statement).all())


# ============================================================================
# UPDATE — DISMISS
# ============================================================================


def set_match_dismissed(
    db: Session,
    match: Match,
    *,
    dismissed: bool,
) -> Match:
    """
    Set the dismissed state of a match.

    Authorization and any business rules around dismissal must be
    handled by the service layer.
    """

    match.is_dismissed = dismissed

    db.flush()

    return match


# ============================================================================
# UPDATE — MATCH
# ============================================================================


def update_match(
    db: Session,
    match: Match,
    *,
    score: int | None = None,
    match_level: str | None = None,
    category_score: int | None = None,
    title_score: int | None = None,
    description_score: int | None = None,
    location_score: int | None = None,
    time_score: int | None = None,
    reason: str | None = None,
) -> Match:
    """
    Update supplied match fields.

    Matching decisions and validation must be performed by the
    service layer before this function is called.
    """

    if score is not None:
        match.score = score

    if match_level is not None:
        match.match_level = match_level

    if category_score is not None:
        match.category_score = category_score

    if title_score is not None:
        match.title_score = title_score

    if description_score is not None:
        match.description_score = description_score

    if location_score is not None:
        match.location_score = location_score

    if time_score is not None:
        match.time_score = time_score

    if reason is not None:
        match.reason = reason

    db.flush()

    return match