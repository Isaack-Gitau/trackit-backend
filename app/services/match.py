"""
TRACKIT Match Service.

Application/business logic for potential LOST/FOUND matches.

Architecture:

    Item
      ↓
    Matching Service
      ↓
    MatchResult
      ↓
    Match Repository
      ↓
    PostgreSQL

Responsibilities:

- validate LOST/FOUND item pairing
- calculate deterministic match scores
- decide whether a match should be persisted
- create new matches when the score reaches the possible threshold
- update existing matches when item information changes
- preserve dismissed state during recalculation
- enforce ownership for user-scoped match access

This service intentionally does NOT:

- create claims
- approve or reject claims
- send notifications
- create audit logs

Those responsibilities belong to their respective application workflows.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.item import Item
from app.models.match import Match
from app.repositories.matches import (
    create_match as repository_create_match,
    get_match_by_id as repository_get_match_by_id,
    get_match_by_item_pair as repository_get_match_by_item_pair,
    get_matches_by_found_item as repository_get_matches_by_found_item,
    get_matches_by_lost_item as repository_get_matches_by_lost_item,
    get_matches_by_user_items as repository_get_matches_by_user_items,
    set_match_dismissed as repository_set_match_dismissed,
    update_match as repository_update_match,
)
from app.services.matching import (
    MATCH_THRESHOLD_POSSIBLE,
    MatchResult,
    calculate_match,
)


# ============================================================================
# VALIDATION
# ============================================================================


def _validate_items_for_matching(
    first_item: Item,
    second_item: Item,
) -> tuple[Item, Item]:
    """
    Validate two items and return them in LOST/FOUND order.

    Returns:

        (lost_item, found_item)

    Raises:
        ValueError:
            When either item has an invalid type or both items have
            the same type.
    """

    valid_types = {"lost", "found"}

    if first_item.type not in valid_types:
        raise ValueError(
            "First item must have type 'lost' or 'found'."
        )

    if second_item.type not in valid_types:
        raise ValueError(
            "Second item must have type 'lost' or 'found'."
        )

    if first_item.type == second_item.type:
        raise ValueError(
            "Matching requires one lost item and one found item."
        )

    if first_item.type == "lost":
        return first_item, second_item

    return second_item, first_item


def _validate_item_ids(
    lost_item: Item,
    found_item: Item,
) -> None:
    """
    Ensure both items have database identifiers.

    Match records require persisted Item IDs. The service therefore
    rejects transient Item instances before attempting persistence.
    """

    if lost_item.id is None:
        raise ValueError(
            "The LOST item must be persisted before matching."
        )

    if found_item.id is None:
        raise ValueError(
            "The FOUND item must be persisted before matching."
        )


# ============================================================================
# CALCULATION
# ============================================================================


def calculate_item_match(
    first_item: Item,
    second_item: Item,
) -> MatchResult:
    """
    Calculate a deterministic match between two items.

    This is the service-layer entry point for matching calculation.

    The underlying scoring implementation remains in matching.py.
    No database changes are performed.
    """

    lost_item, found_item = _validate_items_for_matching(
        first_item,
        second_item,
    )

    return calculate_match(
        lost_item,
        found_item,
    )


# ============================================================================
# CREATE / UPDATE
# ============================================================================


def save_match(
    db: Session,
    first_item: Item,
    second_item: Item,
) -> Match | None:
    """
    Calculate and persist a match for two LOST/FOUND items.

    Behavior:

    - score < 60:
        - do not create a new match
        - if a match already exists, update its scoring information

    - score >= 60:
        - create a new match if none exists
        - otherwise update the existing match

    Existing dismissed state is preserved during recalculation.

    Returns:

        Match instance when a persisted match exists.
        None when the pair scores below the possible threshold and
        no previous match exists.

    Raises:
        ValueError:
            When the items cannot be matched or are not persisted.
    """

    lost_item, found_item = _validate_items_for_matching(
        first_item,
        second_item,
    )

    _validate_item_ids(
        lost_item,
        found_item,
    )

    result = calculate_match(
        lost_item,
        found_item,
    )

    existing_match = repository_get_match_by_item_pair(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    if existing_match is None:
        if result.score < MATCH_THRESHOLD_POSSIBLE:
            return None

        return repository_create_match(
            db,
            lost_item_id=lost_item.id,
            found_item_id=found_item.id,
            score=result.score,
            match_level=result.match_level,
            category_score=result.category_score,
            title_score=result.title_score,
            description_score=result.description_score,
            location_score=result.location_score,
            time_score=result.time_score,
            reason=result.reason,
        )

    return repository_update_match(
        db,
        existing_match,
        score=result.score,
        match_level=result.match_level,
        category_score=result.category_score,
        title_score=result.title_score,
        description_score=result.description_score,
        location_score=result.location_score,
        time_score=result.time_score,
        reason=result.reason,
    )


def create_or_update_match(
    db: Session,
    first_item: Item,
    second_item: Item,
) -> Match | None:
    """
    Backward-friendly alias for save_match().

    The explicit name makes the intended orchestration behavior clear
    to callers that do not need to distinguish creation from updating.
    """

    return save_match(
        db,
        first_item,
        second_item,
    )


# ============================================================================
# READ — SINGLE MATCH
# ============================================================================


def get_match(
    db: Session,
    *,
    match_id: int,
) -> Match | None:
    """
    Retrieve a match by ID.

    Authorization is intentionally not performed here because this
    repository-style lookup is useful to higher-level workflows that
    may apply different authorization rules.
    """

    return repository_get_match_by_id(
        db,
        match_id,
    )


def get_user_match(
    db: Session,
    *,
    match_id: int,
    user_id: int,
) -> Match | None:
    """
    Retrieve a match only when the user owns either participating item.

    Returns None when:

    - the match does not exist
    - the user owns neither the LOST nor FOUND item

    This creates the service-level authorization boundary for
    user-scoped match access.
    """

    match = repository_get_match_by_id(
        db,
        match_id,
    )

    if match is None:
        return None

    if match.lost_item.user_id == user_id:
        return match

    if match.found_item.user_id == user_id:
        return match

    return None


# ============================================================================
# READ — ITEM MATCHES
# ============================================================================


def get_lost_item_matches(
    db: Session,
    *,
    lost_item: Item,
    user_id: int,
    include_dismissed: bool = False,
) -> list[Match]:
    """
    Retrieve matches for a LOST item when the requesting user owns it.
    """

    if lost_item.user_id != user_id:
        raise PermissionError(
            "You are not authorized to view matches for this item."
        )

    if lost_item.id is None:
        raise ValueError(
            "The LOST item must be persisted before retrieving matches."
        )

    return repository_get_matches_by_lost_item(
        db,
        lost_item_id=lost_item.id,
        include_dismissed=include_dismissed,
    )


def get_found_item_matches(
    db: Session,
    *,
    found_item: Item,
    user_id: int,
    include_dismissed: bool = False,
) -> list[Match]:
    """
    Retrieve matches for a FOUND item when the requesting user owns it.
    """

    if found_item.user_id != user_id:
        raise PermissionError(
            "You are not authorized to view matches for this item."
        )

    if found_item.id is None:
        raise ValueError(
            "The FOUND item must be persisted before retrieving matches."
        )

    return repository_get_matches_by_found_item(
        db,
        found_item_id=found_item.id,
        include_dismissed=include_dismissed,
    )


# ============================================================================
# READ — USER MATCHES
# ============================================================================


def list_user_matches(
    db: Session,
    *,
    user_id: int,
    include_dismissed: bool = False,
) -> list[Match]:
    """
    Retrieve all matches involving items owned by the user.

    The repository performs the ownership filtering at the SQL level.
    """

    return repository_get_matches_by_user_items(
        db,
        user_id=user_id,
        include_dismissed=include_dismissed,
    )


# ============================================================================
# DISMISS / RESTORE
# ============================================================================


def dismiss_match(
    db: Session,
    *,
    match: Match,
    user_id: int,
) -> Match:
    """
    Dismiss a match.

    Only a user who owns either participating item may dismiss it.
    """

    _require_match_ownership(
        match,
        user_id=user_id,
    )

    return repository_set_match_dismissed(
        db,
        match,
        dismissed=True,
    )


def restore_match(
    db: Session,
    *,
    match: Match,
    user_id: int,
) -> Match:
    """
    Restore a previously dismissed match.

    Only a user who owns either participating item may restore it.
    """

    _require_match_ownership(
        match,
        user_id=user_id,
    )

    return repository_set_match_dismissed(
        db,
        match,
        dismissed=False,
    )


# ============================================================================
# INTERNAL AUTHORIZATION
# ============================================================================


def _require_match_ownership(
    match: Match,
    *,
    user_id: int,
) -> None:
    """
    Require ownership of at least one item participating in the match.
    """

    if match.lost_item.user_id == user_id:
        return

    if match.found_item.user_id == user_id:
        return

    raise PermissionError(
        "You are not authorized to modify this match."
    )

