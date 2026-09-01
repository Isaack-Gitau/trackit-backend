"""
TRACKIT Match Repository Tests.

Tests the database access layer for potential LOST/FOUND matches.

Coverage:
- match creation
- match retrieval by ID
- match retrieval by LOST/FOUND pair
- LOST item match listing
- FOUND item match listing
- dismissed match filtering
- user-owned match listing
- strong match filtering
- dismissing and restoring matches
- updating match scoring information

Architecture under test:

    Repository
       ↓
    SQLAlchemy Model
       ↓
    PostgreSQL
"""

from datetime import datetime, timedelta, timezone

from app.models.item import Item
from app.models.user import User

from app.repositories.matches import (
    create_match,
    get_match_by_id,
    get_match_by_item_pair,
    get_matches_by_found_item,
    get_matches_by_lost_item,
    get_matches_by_user_items,
    get_strong_matches,
    set_match_dismissed,
    update_match,
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
    Create a minimal valid User required by Item.user_id.
    """

    user = db.get(User, user_id)

    if user is not None:
        return user

    user = User(
        id=user_id,
        username=f"matchuser{user_id}",
        first_name="Match",
        last_name="User",
        email=f"matchuser{user_id}@trackit.test",
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
    created_at: datetime,
):
    """
    Create a minimal Item for repository testing.

    Items are created directly because these tests focus on the
    Match repository rather than item business logic.
    """

    create_test_user(
        db,
        user_id=user_id,
    )

    item = Item(
        user_id=user_id,
        title=title,
        description="Repository test item description.",
        type=item_type,
        category="Electronics",
        location="Main Library",
        status="approved",
        created_at=created_at,
    )

    db.add(item)
    db.flush()

    return item


def create_test_match(
    db,
    *,
    lost_item_id: int,
    found_item_id: int,
    score: int = 85,
    match_level: str = "strong",
    is_dismissed: bool = False,
):
    """
    Create a Match directly through the repository.
    """

    match = create_match(
        db,
        lost_item_id=lost_item_id,
        found_item_id=found_item_id,
        score=score,
        match_level=match_level,
        category_score=25,
        title_score=18,
        description_score=25,
        location_score=12,
        time_score=5,
        reason="exact category match; strong title similarity.",
    )

    if is_dismissed:
        match.is_dismissed = True
        db.flush()

    return match


def create_test_item_pair(
    db,
    *,
    lost_user_id: int = 1,
    found_user_id: int = 2,
    lost_title: str = "Lost Laptop",
    found_title: str = "Found Laptop",
    created_at: datetime | None = None,
):
    """
    Create one LOST item and one FOUND item.
    """

    if created_at is None:
        created_at = datetime.now(timezone.utc)

    lost_item = create_test_item(
        db,
        user_id=lost_user_id,
        item_type="lost",
        title=lost_title,
        created_at=created_at,
    )

    found_item = create_test_item(
        db,
        user_id=found_user_id,
        item_type="found",
        title=found_title,
        created_at=created_at + timedelta(hours=1),
    )

    return lost_item, found_item


# ============================================================================
# CREATE
# ============================================================================


def test_create_match(db):
    """
    A match should be persisted with all scoring components.
    """

    lost_item, found_item = create_test_item_pair(db)

    match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    assert match.id is not None
    assert match.lost_item_id == lost_item.id
    assert match.found_item_id == found_item.id
    assert match.score == 85
    assert match.match_level == "strong"
    assert match.category_score == 25
    assert match.title_score == 18
    assert match.description_score == 25
    assert match.location_score == 12
    assert match.time_score == 5
    assert match.reason.startswith("exact category")
    assert match.is_dismissed is False


# ============================================================================
# READ — SINGLE MATCH
# ============================================================================


def test_get_match_by_id(db):
    """
    An existing match should be retrievable by ID.
    """

    lost_item, found_item = create_test_item_pair(db)

    match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    result = get_match_by_id(
        db,
        match_id=match.id,
    )

    assert result is not None
    assert result.id == match.id
    assert result.lost_item_id == lost_item.id
    assert result.found_item_id == found_item.id


def test_get_nonexistent_match_returns_none(db):
    """
    A nonexistent match ID should return None.
    """

    result = get_match_by_id(
        db,
        match_id=999999,
    )

    assert result is None


# ============================================================================
# READ — ITEM PAIR
# ============================================================================


def test_get_match_by_item_pair(db):
    """
    A match should be retrievable using its LOST/FOUND item pair.
    """

    lost_item, found_item = create_test_item_pair(db)

    match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    result = get_match_by_item_pair(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    assert result is not None
    assert result.id == match.id


def test_get_match_by_nonexistent_item_pair_returns_none(db):
    """
    A nonexistent LOST/FOUND pair should return None.
    """

    result = get_match_by_item_pair(
        db,
        lost_item_id=999998,
        found_item_id=999999,
    )

    assert result is None


# ============================================================================
# READ — LOST ITEM
# ============================================================================


def test_get_matches_by_lost_item_returns_matches_highest_score_first(db):
    """
    Matches for a LOST item should be ordered by score descending.
    """

    lost_item, found_item_one = create_test_item_pair(
        db,
        found_user_id=2,
        found_title="Found Laptop One",
    )

    _, found_item_two = create_test_item_pair(
        db,
        lost_user_id=lost_item.user_id,
        found_user_id=3,
        found_title="Found Laptop Two",
    )

    match_low = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item_one.id,
        score=65,
        match_level="possible",
    )

    match_high = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item_two.id,
        score=90,
        match_level="strong",
    )

    results = get_matches_by_lost_item(
        db,
        lost_item_id=lost_item.id,
    )

    assert [match.id for match in results] == [
        match_high.id,
        match_low.id,
    ]


def test_get_matches_by_lost_item_excludes_dismissed_by_default(db):
    """
    Dismissed matches should not appear in the default LOST item listing.
    """

    lost_item, found_item_one = create_test_item_pair(
        db,
        found_user_id=2,
    )

    _, found_item_two = create_test_item_pair(
        db,
        lost_user_id=lost_item.user_id,
        found_user_id=3,
    )

    active_match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item_one.id,
        score=90,
        match_level="strong",
    )

    dismissed_match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item_two.id,
        score=95,
        match_level="strong",
        is_dismissed=True,
    )

    results = get_matches_by_lost_item(
        db,
        lost_item_id=lost_item.id,
    )

    assert [match.id for match in results] == [active_match.id]
    assert dismissed_match.id not in [match.id for match in results]


def test_get_matches_by_lost_item_can_include_dismissed(db):
    """
    Dismissed matches should be returned when explicitly requested.
    """

    lost_item, found_item = create_test_item_pair(db)

    dismissed_match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        score=85,
        match_level="strong",
        is_dismissed=True,
    )

    results = get_matches_by_lost_item(
        db,
        lost_item_id=lost_item.id,
        include_dismissed=True,
    )

    assert len(results) == 1
    assert results[0].id == dismissed_match.id


# ============================================================================
# READ — FOUND ITEM
# ============================================================================


def test_get_matches_by_found_item(db):
    """
    Matches for a FOUND item should be retrievable.
    """

    lost_item_one, found_item = create_test_item_pair(
        db,
        lost_user_id=1,
    )

    lost_item_two, _ = create_test_item_pair(
        db,
        lost_user_id=3,
        found_user_id=found_item.user_id,
    )

    match_one = create_test_match(
        db,
        lost_item_id=lost_item_one.id,
        found_item_id=found_item.id,
        score=70,
        match_level="possible",
    )

    match_two = create_test_match(
        db,
        lost_item_id=lost_item_two.id,
        found_item_id=found_item.id,
        score=90,
        match_level="strong",
    )

    results = get_matches_by_found_item(
        db,
        found_item_id=found_item.id,
    )

    assert [match.id for match in results] == [
        match_two.id,
        match_one.id,
    ]


def test_get_matches_by_found_item_excludes_dismissed_by_default(db):
    """
    Dismissed matches should not appear in the default FOUND item listing.
    """

    lost_item_one, found_item = create_test_item_pair(
        db,
        lost_user_id=1,
    )

    lost_item_two, _ = create_test_item_pair(
        db,
        lost_user_id=3,
        found_user_id=found_item.user_id,
    )

    active_match = create_test_match(
        db,
        lost_item_id=lost_item_one.id,
        found_item_id=found_item.id,
        score=85,
        match_level="strong",
    )

    dismissed_match = create_test_match(
        db,
        lost_item_id=lost_item_two.id,
        found_item_id=found_item.id,
        score=95,
        match_level="strong",
        is_dismissed=True,
    )

    results = get_matches_by_found_item(
        db,
        found_item_id=found_item.id,
    )

    assert [match.id for match in results] == [active_match.id]
    assert dismissed_match.id not in [match.id for match in results]


# ============================================================================
# READ — USER ITEMS
# ============================================================================


def test_get_matches_by_user_items_returns_matches_for_owned_lost_item(db):
    """
    A user should receive matches when they own the LOST item.
    """

    lost_item, found_item = create_test_item_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    results = get_matches_by_user_items(
        db,
        user_id=10,
    )

    assert len(results) == 1
    assert results[0].id == match.id


def test_get_matches_by_user_items_returns_matches_for_owned_found_item(db):
    """
    A user should receive matches when they own the FOUND item.
    """

    lost_item, found_item = create_test_item_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    results = get_matches_by_user_items(
        db,
        user_id=20,
    )

    assert len(results) == 1
    assert results[0].id == match.id


def test_get_matches_by_user_items_does_not_return_unrelated_matches(db):
    """
    A user should not receive matches involving items they do not own.
    """

    lost_item, found_item = create_test_item_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    results = get_matches_by_user_items(
        db,
        user_id=30,
    )

    assert results == []
    assert match.id is not None


def test_get_matches_by_user_items_excludes_dismissed_by_default(db):
    """
    Dismissed matches should not appear in a user's default listing.
    """

    lost_item, found_item = create_test_item_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    active_match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        score=80,
        match_level="strong",
    )

    dismissed_lost, dismissed_found = create_test_item_pair(
        db,
        lost_user_id=10,
        found_user_id=40,
    )

    dismissed_match = create_test_match(
        db,
        lost_item_id=dismissed_lost.id,
        found_item_id=dismissed_found.id,
        score=95,
        match_level="strong",
        is_dismissed=True,
    )

    results = get_matches_by_user_items(
        db,
        user_id=10,
    )

    assert active_match.id in [match.id for match in results]
    assert dismissed_match.id not in [match.id for match in results]


def test_get_matches_by_user_items_can_include_dismissed(db):
    """
    A user should be able to retrieve dismissed matches when requested.
    """

    lost_item, found_item = create_test_item_pair(
        db,
        lost_user_id=10,
        found_user_id=20,
    )

    dismissed_match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        score=95,
        match_level="strong",
        is_dismissed=True,
    )

    results = get_matches_by_user_items(
        db,
        user_id=10,
        include_dismissed=True,
    )

    assert len(results) == 1
    assert results[0].id == dismissed_match.id


# ============================================================================
# READ — STRONG MATCHES
# ============================================================================


def test_get_strong_matches_returns_matches_above_threshold(db):
    """
    Strong-match queries should return matches at or above the threshold.
    """

    lost_item_one, found_item_one = create_test_item_pair(
        db,
        lost_user_id=1,
        found_user_id=2,
    )

    lost_item_two, found_item_two = create_test_item_pair(
        db,
        lost_user_id=3,
        found_user_id=4,
    )

    possible_match = create_test_match(
        db,
        lost_item_id=lost_item_one.id,
        found_item_id=found_item_one.id,
        score=79,
        match_level="possible",
    )

    strong_match = create_test_match(
        db,
        lost_item_id=lost_item_two.id,
        found_item_id=found_item_two.id,
        score=80,
        match_level="strong",
    )

    results = get_strong_matches(
        db,
        minimum_score=80,
    )

    assert strong_match.id in [match.id for match in results]
    assert possible_match.id not in [match.id for match in results]


def test_get_strong_matches_excludes_dismissed_by_default(db):
    """
    Dismissed strong matches should be excluded by default.
    """

    lost_item, found_item = create_test_item_pair(db)

    dismissed_match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        score=95,
        match_level="strong",
        is_dismissed=True,
    )

    results = get_strong_matches(
        db,
        minimum_score=80,
    )

    assert dismissed_match.id not in [match.id for match in results]


def test_get_strong_matches_can_include_dismissed(db):
    """
    Dismissed strong matches should be returned when requested.
    """

    lost_item, found_item = create_test_item_pair(db)

    dismissed_match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        score=95,
        match_level="strong",
        is_dismissed=True,
    )

    results = get_strong_matches(
        db,
        minimum_score=80,
        include_dismissed=True,
    )

    assert len(results) == 1
    assert results[0].id == dismissed_match.id


# ============================================================================
# UPDATE — DISMISS
# ============================================================================


def test_set_match_dismissed(db):
    """
    A match should be dismissible without deleting the record.
    """

    lost_item, found_item = create_test_item_pair(db)

    match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    result = set_match_dismissed(
        db,
        match,
        dismissed=True,
    )

    assert result.id == match.id
    assert result.is_dismissed is True

    stored = get_match_by_id(
        db,
        match_id=match.id,
    )

    assert stored is not None
    assert stored.is_dismissed is True


def test_set_match_dismissed_can_restore_match(db):
    """
    A dismissed match should be restorable.
    """

    lost_item, found_item = create_test_item_pair(db)

    match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        is_dismissed=True,
    )

    result = set_match_dismissed(
        db,
        match,
        dismissed=False,
    )

    assert result.id == match.id
    assert result.is_dismissed is False


# ============================================================================
# UPDATE — MATCH
# ============================================================================


def test_update_match(db):
    """
    Match scoring information should be updateable.
    """

    lost_item, found_item = create_test_item_pair(db)

    match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        score=65,
        match_level="possible",
    )

    result = update_match(
        db,
        match,
        score=92,
        match_level="strong",
        category_score=25,
        title_score=20,
        description_score=28,
        location_score=14,
        time_score=5,
        reason="exact category match; strong title similarity.",
    )

    assert result.id == match.id
    assert result.score == 92
    assert result.match_level == "strong"
    assert result.category_score == 25
    assert result.title_score == 20
    assert result.description_score == 28
    assert result.location_score == 14
    assert result.time_score == 5
    assert result.reason.startswith("exact category")


def test_update_match_only_changes_supplied_fields(db):
    """
    Updating one field should not overwrite unrelated fields.
    """

    lost_item, found_item = create_test_item_pair(db)

    match = create_test_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        score=85,
        match_level="strong",
    )

    original_reason = match.reason
    original_title_score = match.title_score

    result = update_match(
        db,
        match,
        score=90,
    )

    assert result.score == 90
    assert result.match_level == "strong"
    assert result.reason == original_reason
    assert result.title_score == original_title_score