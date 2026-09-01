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
- generate matches for newly approved items
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
from app.repositories.items import (
    get_approved_items_by_type,
)
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
    Validate and normalize a pair of items.

    Returns:
        tuple[Item, Item]:
            (lost_item, found_item)
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
    Ensure both items have already been persisted.
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
    Calculate a deterministic match result for two items.

    Item order does not matter. The service normalizes the pair
    into LOST and FOUND before delegating to the matching engine.
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
# CREATE / UPDATE SINGLE MATCH
# ============================================================================


def save_match(
    db: Session,
    first_item: Item,
    second_item: Item,
) -> Match | None:
    """
    Calculate and persist a match between two LOST/FOUND items.

    Behavior:

    - New matches are only persisted when score >= 60.
    - Existing matches are recalculated and updated regardless
      of whether their new score is below 60.
    - Existing dismissed state is preserved because this function
      does not modify is_dismissed.
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
    Backwards-compatible application-level alias for save_match().
    """

    return save_match(
        db,
        first_item,
        second_item,
    )


# ============================================================================
# GENERATE MATCHES FOR APPROVED ITEM
# ============================================================================


def generate_matches_for_item(
    db: Session,
    *,
    item: Item,
) -> list[Match]:
    """
    Generate potential matches for an approved item.

    The item must already be approved.

    Matching direction:

        APPROVED LOST
            ↓
        approved FOUND candidates

        APPROVED FOUND
            ↓
        approved LOST candidates

    Only candidates that reach the possible-match threshold are
    returned as persisted Match records.

    Existing matches are recalculated through save_match().
    """

    if item.id is None:
        raise ValueError(
            "The item must be persisted before generating matches."
        )

    if item.status != "approved":
        raise ValueError(
            "Only approved items can generate matches."
        )

    if item.type == "lost":
        opposite_type = "found"
    elif item.type == "found":
        opposite_type = "lost"
    else:
        raise ValueError(
            "Item type must be 'lost' or 'found'."
        )

    candidate_items = get_approved_items_by_type(
        db,
        item_type=opposite_type,
    )

    matches: list[Match] = []

    for candidate in candidate_items:
        if candidate.id == item.id:
            continue

        match = save_match(
            db,
            item,
            candidate,
        )

        if match is not None:
            matches.append(match)

    return matches


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
    Retrieve a match only when the authenticated user owns
    either participating item.

    Returns None for inaccessible matches so callers can expose
    them as HTTP 404 without revealing another user's data.
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
# READ — LOST ITEM MATCHES
# ============================================================================


def get_lost_item_matches(
    db: Session,
    *,
    lost_item: Item,
    user_id: int,
    include_dismissed: bool = False,
) -> list[Match]:
    """
    Retrieve matches for an owned LOST item.
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


# ============================================================================
# READ — FOUND ITEM MATCHES
# ============================================================================


def get_found_item_matches(
    db: Session,
    *,
    found_item: Item,
    user_id: int,
    include_dismissed: bool = False,
) -> list[Match]:
    """
    Retrieve matches for an owned FOUND item.
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
    Retrieve matches involving the authenticated user's items.
    """

    return repository_get_matches_by_user_items(
        db,
        user_id=user_id,
        include_dismissed=include_dismissed,
    )


# ============================================================================
# DISMISS
# ============================================================================


def dismiss_match(
    db: Session,
    *,
    match: Match,
    user_id: int,
) -> Match:
    """
    Dismiss a match when the user owns either participating item.
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


# ============================================================================
# RESTORE
# ============================================================================


def restore_match(
    db: Session,
    *,
    match: Match,
    user_id: int,
) -> Match:
    """
    Restore a dismissed match when the user owns either
    participating item.
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
# OWNERSHIP
# ============================================================================


def _require_match_ownership(
    match: Match,
    *,
    user_id: int,
) -> None:
    """
    Require the user to own either item participating in the match.
    """

    if match.lost_item.user_id == user_id:
        return

    if match.found_item.user_id == user_id:
        return

    raise PermissionError(
        "You are not authorized to modify this match."
    )