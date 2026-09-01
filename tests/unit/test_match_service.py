"""
TRACKIT Match Service Tests.

Tests the application/business layer responsible for:

- validating LOST/FOUND pairs
- calculating matches through the matching service
- creating possible/strong matches
- refusing to create weak matches
- updating existing matches
- preserving dismissed state
- enforcing item ownership
- retrieving user-owned matches
- dismissing and restoring matches

Architecture under test:

    Item
      ↓
    Match Service
      ↓
    Matching Service
      ↓
    Match Repository
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.item import Item
from app.models.match import Match
from app.models.user import User
from app.services.match import (
    calculate_item_match,
    create_or_update_match,
    dismiss_match,
    get_found_item_matches,
    get_lost_item_matches,
    get_match,
    get_user_match,
    list_user_matches,
    restore_match,
    save_match,
)


# ============================================================================
# TEST HELPERS
# ============================================================================


def create_test_user(
    db,
    *,
    user_id: int,
):
    """
    Create a minimal valid User.
    """

    user = db.get(User, user_id)

    if user is not None:
        return user

    user = User(
        id=user_id,
        username=f"matchserviceuser{user_id}",
        first_name="Match",
        last_name="Service",
        email=f"matchserviceuser{user_id}@trackit.test",
        password_hash="test-password-hash",
        role="user",
        is_active=True,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    return user


def create_test_item(
    db,
    *,
    user_id: int,
    item_type: str,
    title: str,
    description: str = "Black laptop with silver logo.",
    category: str = "Electronics",
    location: str = "Main Library",
    created_at: datetime | None = None,
):
    """
    Create a persisted Item for service testing.
    """

    create_test_user(
        db,
        user_id=user_id,
    )

    if created_at is None:
        created_at = datetime.now(timezone.utc)

    item = Item(
        user_id=user_id,
        title=title,
        description=description,
        type=item_type,
        category=category,
        location=location,
        status="approved",
        created_at=created_at,
    )

    db.add(item)
    db.flush()

    return item


def create_matching_pair(
    db,
    *,
    lost_user_id: int = 1,
    found_user_id: int = 2,
    lost_title: str = "Black Dell Laptop",
    found_title: str = "Black Dell Laptop",
    lost_description: str = "Black Dell laptop with silver logo.",
    found_description: str = "Black Dell laptop with silver logo.",
    lost_category: str = "Electronics",
    found_category: str = "Electronics",
    lost_location: str = "Main Library",
    found_location: str = "Main Library",
    time_difference: timedelta = timedelta(hours=1),
):
    """
    Create a LOST/FOUND pair with controllable matching data.
    """

    base_time = datetime.now(timezone.utc)

    lost_item = create_test_item(
        db,
        user_id=lost_user_id,
        item_type="lost",
        title=lost_title,
        description=lost_description,
        category=lost_category,
        location=lost_location,
        created_at=base_time,
    )

    found_item = create_test_item(
        db,
        user_id=found_user_id,
        item_type="found",
        title=found_title,
        description=found_description,
        category=found_category,
        location=found_location,
        created_at=base_time + time_difference,
    )

    return lost_item, found_item


# ============================================================================
# CALCULATION
# ============================================================================


def test_calculate_item_match_returns_result(db):
    """
    The service should expose deterministic matching calculation.
    """

    lost_item, found_item = create_matching_pair(db)

    result = calculate_item_match(
        lost_item,
        found_item,
    )

    assert result.score >= 60
    assert result.match_level in {"possible", "strong"}
    assert result.category_score == 25
    assert result.reason


def test_calculate_item_match_accepts_found_then_lost(db):
    """
    Matching should normalize item order regardless of argument order.
    """

    lost_item, found_item = create_matching_pair(db)

    first_result = calculate_item_match(
        lost_item,
        found_item,
    )

    second_result = calculate_item_match(
        found_item,
        lost_item,
    )

    assert second_result == first_result


def test_calculate_item_match_rejects_same_type(db):
    """
    Two LOST items cannot be matched.
    """

    lost_one = create_test_item(
        db,
        user_id=1,
        item_type="lost",
        title="Lost Laptop One",
    )

    lost_two = create_test_item(
        db,
        user_id=2,
        item_type="lost",
        title="Lost Laptop Two",
    )

    with pytest.raises(
        ValueError,
        match="Matching requires one lost item and one found item",
    ):
        calculate_item_match(
            lost_one,
            lost_two,
        )


def test_calculate_item_match_rejects_invalid_type(db):
    """
    Items with unsupported types cannot be matched.
    """

    invalid_item = create_test_item(
        db,
        user_id=1,
        item_type="other",
        title="Invalid Item",
    )

    found_item = create_test_item(
        db,
        user_id=2,
        item_type="found",
        title="Found Item",
    )

    with pytest.raises(
        ValueError,
        match="First item must have type",
    ):
        calculate_item_match(
            invalid_item,
            found_item,
        )


# ============================================================================
# CREATE
# ============================================================================


def test_save_match_creates_possible_match(db):
    """
    A score of 60 or higher should create a persisted match.
    """

    lost_item, found_item = create_matching_pair(db)

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None
    assert match.id is not None
    assert match.lost_item_id == lost_item.id
    assert match.found_item_id == found_item.id
    assert match.score >= 60


def test_save_match_creates_strong_match_when_score_reaches_threshold(db):
    """
    Highly similar items should produce a strong persisted match.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_title="Black Dell Latitude Laptop",
        found_title="Black Dell Latitude Laptop",
        lost_description="Black Dell Latitude laptop with silver logo.",
        found_description="Black Dell Latitude laptop with silver logo.",
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None
    assert match.score >= 80
    assert match.match_level == "strong"


def test_save_match_does_not_create_weak_match(db):
    """
    A score below the possible threshold should not create a new record.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_title="Laptop",
        found_title="Bicycle",
        lost_description="A black laptop.",
        found_description="A red bicycle.",
        lost_category="Electronics",
        found_category="Sports",
        lost_location="Main Library",
        found_location="City Stadium",
        time_difference=timedelta(days=365),
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is None


def test_save_match_stores_all_score_components(db):
    """
    Persisted matches should contain the complete scoring breakdown.
    """

    lost_item, found_item = create_matching_pair(db)

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    assert match.category_score >= 0
    assert match.title_score >= 0
    assert match.description_score >= 0
    assert match.location_score >= 0
    assert match.time_score >= 0

    assert (
        match.score
        == match.category_score
        + match.title_score
        + match.description_score
        + match.location_score
        + match.time_score
    )


# ============================================================================
# UPDATE
# ============================================================================


def test_save_match_updates_existing_match(db):
    """
    Recalculating an existing pair should update the stored match.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_title="Laptop",
        found_title="Laptop",
    )

    first_match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert first_match is not None

    original_id = first_match.id
    original_score = first_match.score

    found_item.title = "Black Dell Latitude Laptop"
    found_item.description = "Black Dell Latitude laptop with silver logo."
    db.flush()

    updated_match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert updated_match is not None
    assert updated_match.id == original_id
    assert updated_match.score != original_score


def test_save_match_does_not_create_duplicate_pair(db):
    """
    Recalculating the same pair must reuse the existing Match record.
    """

    lost_item, found_item = create_matching_pair(db)

    first_match = save_match(
        db,
        lost_item,
        found_item,
    )

    second_match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert first_match is not None
    assert second_match is not None
    assert second_match.id == first_match.id


def test_save_match_updates_existing_match_even_if_score_falls_below_threshold(
    db,
):
    """
    Existing matches are retained when recalculation drops below 60.

    This preserves match history rather than deleting a previously
    surfaced relationship.
    """

    lost_item, found_item = create_matching_pair(db)

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    match_id = match.id

    lost_item.title = "Completely Different Object"
    lost_item.description = "Unrelated description."
    lost_item.category = "Sports"
    lost_item.location = "City Stadium"
    lost_item.created_at = datetime.now(timezone.utc) - timedelta(days=365)

    found_item.title = "Another Unrelated Object"
    found_item.description = "Something completely different."
    found_item.category = "Books"
    found_item.location = "Airport"
    found_item.created_at = datetime.now(timezone.utc)

    db.flush()

    updated = save_match(
        db,
        lost_item,
        found_item,
    )

    assert updated is not None
    assert updated.id == match_id
    assert updated.score < 60
    assert updated.match_level == "none"


# ============================================================================
# DISMISSAL
# ============================================================================


def test_dismiss_match(db):
    """
    An owner of either participating item may dismiss a match.
    """

    lost_item, found_item = create_matching_pair(db)

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    result = dismiss_match(
        db,
        match=match,
        user_id=lost_item.user_id,
    )

    assert result.is_dismissed is True


def test_found_item_owner_can_dismiss_match(db):
    """
    The FOUND item owner may also dismiss a match.
    """

    lost_item, found_item = create_matching_pair(db)

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    result = dismiss_match(
        db,
        match=match,
        user_id=found_item.user_id,
    )

    assert result.is_dismissed is True


def test_unrelated_user_cannot_dismiss_match(db):
    """
    A user who owns neither item cannot dismiss the match.
    """

    lost_item, found_item = create_matching_pair(db)

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    with pytest.raises(
        PermissionError,
        match="not authorized to modify this match",
    ):
        dismiss_match(
            db,
            match=match,
            user_id=999,
        )


def test_restore_match(db):
    """
    A dismissed match can be restored by an owner.
    """

    lost_item, found_item = create_matching_pair(db)

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    dismiss_match(
        db,
        match=match,
        user_id=lost_item.user_id,
    )

    result = restore_match(
        db,
        match=match,
        user_id=lost_item.user_id,
    )

    assert result.is_dismissed is False


def test_dismissed_state_is_preserved_during_recalculation(db):
    """
    Recalculating a match must not automatically resurface a dismissed match.
    """

    lost_item, found_item = create_matching_pair(db)

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    dismiss_match(
        db,
        match=match,
        user_id=lost_item.user_id,
    )

    found_item.title = "Updated Black Dell Laptop"
    db.flush()

    updated = save_match(
        db,
        lost_item,
        found_item,
    )

    assert updated is not None
    assert updated.id == match.id
    assert updated.is_dismissed is True


# ============================================================================
# READ — SINGLE MATCH
# ============================================================================


def test_get_match(db):
    """
    A persisted match should be retrievable by ID.
    """

    lost_item, found_item = create_matching_pair(db)

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    result = get_match(
        db,
        match_id=match.id,
    )

    assert result is not None
    assert result.id == match.id


def test_get_match_returns_none_for_missing_match(db):
    """
    Missing match IDs should return None.
    """

    result = get_match(
        db,
        match_id=999999,
    )

    assert result is None


def test_get_user_match_allows_lost_item_owner(db):
    """
    LOST item owners can retrieve their matches.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    result = get_user_match(
        db,
        match_id=match.id,
        user_id=10,
    )

    assert result is not None
    assert result.id == match.id


def test_get_user_match_allows_found_item_owner(db):
    """
    FOUND item owners can retrieve their matches.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    result = get_user_match(
        db,
        match_id=match.id,
        user_id=20,
    )

    assert result is not None
    assert result.id == match.id


def test_get_user_match_denies_unrelated_user(db):
    """
    Users who own neither item cannot retrieve the match.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    result = get_user_match(
        db,
        match_id=match.id,
        user_id=30,
    )

    assert result is None


# ============================================================================
# READ — ITEM MATCHES
# ============================================================================


def test_get_lost_item_matches_requires_ownership(db):
    """
    A user must own the LOST item to retrieve its matches.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    results = get_lost_item_matches(
        db,
        lost_item=lost_item,
        user_id=10,
    )

    assert len(results) == 1
    assert results[0].id == match.id


def test_get_lost_item_matches_rejects_non_owner(db):
    """
    A non-owner cannot retrieve LOST item matches.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    with pytest.raises(
        PermissionError,
        match="not authorized to view matches",
    ):
        get_lost_item_matches(
            db,
            lost_item=lost_item,
            user_id=30,
        )


def test_get_found_item_matches_requires_ownership(db):
    """
    A user must own the FOUND item to retrieve its matches.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    results = get_found_item_matches(
        db,
        found_item=found_item,
        user_id=20,
    )

    assert len(results) == 1
    assert results[0].id == match.id


def test_get_found_item_matches_rejects_non_owner(db):
    """
    A non-owner cannot retrieve FOUND item matches.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    with pytest.raises(
        PermissionError,
        match="not authorized to view matches",
    ):
        get_found_item_matches(
            db,
            found_item=found_item,
            user_id=30,
        )


# ============================================================================
# READ — USER MATCHES
# ============================================================================


def test_list_user_matches_returns_owned_matches(db):
    """
    Users should receive matches involving their items.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    results = list_user_matches(
        db,
        user_id=10,
    )

    assert len(results) == 1
    assert results[0].id == match.id


def test_list_user_matches_does_not_return_unrelated_matches(db):
    """
    Users should not receive matches involving other users' items.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    results = list_user_matches(
        db,
        user_id=30,
    )

    assert results == []


def test_list_user_matches_excludes_dismissed_by_default(db):
    """
    Dismissed matches should be excluded by default.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    dismiss_match(
        db,
        match=match,
        user_id=10,
    )

    results = list_user_matches(
        db,
        user_id=10,
    )

    assert results == []


def test_list_user_matches_can_include_dismissed(db):
    """
    Dismissed matches can be explicitly requested.
    """

    lost_item, found_item = create_matching_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = save_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None

    dismiss_match(
        db,
        match=match,
        user_id=10,
    )

    results = list_user_matches(
        db,
        user_id=10,
        include_dismissed=True,
    )

    assert len(results) == 1
    assert results[0].id == match.id


# ============================================================================
# TRANSIENT ITEM VALIDATION
# ============================================================================


def test_save_match_rejects_transient_items(db):
    """
    Matching persistence requires both items to have database IDs.
    """

    lost_item = Item(
        user_id=1,
        title="Lost Laptop",
        description="Black laptop.",
        type="lost",
        category="Electronics",
        location="Main Library",
        status="approved",
    )

    found_item = Item(
        user_id=2,
        title="Found Laptop",
        description="Black laptop.",
        type="found",
        category="Electronics",
        location="Main Library",
        status="approved",
    )

    with pytest.raises(
        ValueError,
        match="must be persisted before matching",
    ):
        save_match(
            db,
            lost_item,
            found_item,
        )


# ============================================================================
# ALIAS
# ============================================================================


def test_create_or_update_match_alias(db):
    """
    create_or_update_match should behave exactly like save_match.
    """

    lost_item, found_item = create_matching_pair(db)

    match = create_or_update_match(
        db,
        lost_item,
        found_item,
    )

    assert match is not None
    assert match.id is not None

