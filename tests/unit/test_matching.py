"""
TRACKIT Matching Service Unit Tests.

Tests the deterministic V1 matching algorithm independently from
the database, repositories, API, and notification layers.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.item import Item
from app.services.matching import (
    CATEGORY_MAX_SCORE,
    DESCRIPTION_MAX_SCORE,
    LOCATION_MAX_SCORE,
    MATCH_LEVEL_NONE,
    MATCH_LEVEL_POSSIBLE,
    MATCH_LEVEL_STRONG,
    MAX_MATCH_SCORE,
    TIME_MAX_SCORE,
    TITLE_MAX_SCORE,
    calculate_match,
    classify_match,
    normalize_text,
    score_category,
    score_description,
    score_location,
    score_time,
    score_title,
    token_similarity,
)


# ============================================================================
# TEST ITEM FACTORY
# ============================================================================


def make_item(
    *,
    item_type: str = "lost",
    title: str = "Black leather wallet",
    description: str = (
        "Black leather wallet with several cards and a small photo."
    ),
    category: str = "wallet",
    location: str = "Nairobi CBD",
    created_at: datetime | None = None,
) -> Item:
    """
    Create an Item model instance for unit testing.

    The matcher only reads item attributes and does not require
    the item to be persisted in the database.
    """

    if created_at is None:
        created_at = datetime(
            2026,
            1,
            10,
            12,
            0,
            tzinfo=timezone.utc,
        )

    return Item(
        id=1,
        user_id=1,
        type=item_type,
        title=title,
        description=description,
        category=category,
        location=location,
        created_at=created_at,
    )


# ============================================================================
# TEXT NORMALIZATION
# ============================================================================


def test_normalize_text_lowercases_and_removes_punctuation():
    result = normalize_text(
        "  Black-Leather WALLET!!!  "
    )

    assert result == "black leather wallet"


def test_normalize_text_collapses_whitespace():
    result = normalize_text(
        "black     leather\nwallet\t"
    )

    assert result == "black leather wallet"


def test_token_similarity_returns_one_for_identical_text():
    similarity = token_similarity(
        "Black leather wallet",
        "black leather wallet",
    )

    assert similarity == 1.0


def test_token_similarity_returns_zero_for_no_overlap():
    similarity = token_similarity(
        "black leather wallet",
        "red plastic bottle",
    )

    assert similarity == 0.0


def test_token_similarity_uses_jaccard_token_overlap():
    similarity = token_similarity(
        "black leather wallet",
        "black leather bag",
    )

    # Shared tokens: black, leather = 2
    # Union: black, leather, wallet, bag = 4
    assert similarity == 0.5


def test_token_similarity_handles_empty_text():
    assert token_similarity("", "wallet") == 0.0
    assert token_similarity("wallet", "") == 0.0
    assert token_similarity("", "") == 0.0


# ============================================================================
# CATEGORY SCORING
# ============================================================================


def test_exact_category_match_gets_full_score():
    lost_item = make_item(
        item_type="lost",
        category="Wallet",
    )

    found_item = make_item(
        item_type="found",
        category="wallet",
    )

    assert score_category(
        lost_item,
        found_item,
    ) == CATEGORY_MAX_SCORE


def test_different_categories_get_zero_score():
    lost_item = make_item(
        item_type="lost",
        category="wallet",
    )

    found_item = make_item(
        item_type="found",
        category="phone",
    )

    assert score_category(
        lost_item,
        found_item,
    ) == 0


# ============================================================================
# TITLE SCORING
# ============================================================================


def test_identical_titles_get_full_title_score():
    lost_item = make_item(
        item_type="lost",
        title="Black leather wallet",
    )

    found_item = make_item(
        item_type="found",
        title="Black leather wallet",
    )

    assert score_title(
        lost_item,
        found_item,
    ) == TITLE_MAX_SCORE


def test_partial_title_similarity_gets_partial_score():
    lost_item = make_item(
        item_type="lost",
        title="Black leather wallet",
    )

    found_item = make_item(
        item_type="found",
        title="Black leather bag",
    )

    score = score_title(
        lost_item,
        found_item,
    )

    assert 0 < score < TITLE_MAX_SCORE


# ============================================================================
# DESCRIPTION SCORING
# ============================================================================


def test_identical_descriptions_get_full_description_score():
    description = (
        "Black leather wallet with several cards and a small photo."
    )

    lost_item = make_item(
        item_type="lost",
        description=description,
    )

    found_item = make_item(
        item_type="found",
        description=description,
    )

    assert score_description(
        lost_item,
        found_item,
    ) == DESCRIPTION_MAX_SCORE


def test_completely_different_descriptions_get_zero_score():
    lost_item = make_item(
        item_type="lost",
        description=(
            "Silver bicycle parked beside a large tree near the river."
        ),
    )

    found_item = make_item(
        item_type="found",
        description=(
            "Orange backpack containing notebooks pencils and textbooks."
        ),
    )

    assert score_description(
        lost_item,
        found_item,
    ) == 0


# ============================================================================
# LOCATION SCORING
# ============================================================================


def test_identical_locations_get_full_location_score():
    lost_item = make_item(
        item_type="lost",
        location="Nairobi CBD",
    )

    found_item = make_item(
        item_type="found",
        location="Nairobi CBD",
    )

    assert score_location(
        lost_item,
        found_item,
    ) == LOCATION_MAX_SCORE


def test_partial_location_similarity_gets_partial_score():
    lost_item = make_item(
        item_type="lost",
        location="Nairobi CBD",
    )

    found_item = make_item(
        item_type="found",
        location="Nairobi CBD bus station",
    )

    score = score_location(
        lost_item,
        found_item,
    )

    assert 0 < score < LOCATION_MAX_SCORE


def test_completely_different_locations_get_zero_score():
    lost_item = make_item(
        item_type="lost",
        location="Nairobi CBD",
    )

    found_item = make_item(
        item_type="found",
        location="Mombasa Beach",
    )

    assert score_location(
        lost_item,
        found_item,
    ) == 0


# ============================================================================
# TIME SCORING
# ============================================================================


def test_items_reported_same_time_get_full_time_score():
    created_at = datetime(
        2026,
        1,
        10,
        12,
        0,
        tzinfo=timezone.utc,
    )

    lost_item = make_item(
        item_type="lost",
        created_at=created_at,
    )

    found_item = make_item(
        item_type="found",
        created_at=created_at,
    )

    assert score_time(
        lost_item,
        found_item,
    ) == TIME_MAX_SCORE


@pytest.mark.parametrize(
    ("days_apart", "expected_score"),
    [
        (1, 10),
        (3, 8),
        (7, 6),
        (31, 0),
    ],
)
def test_time_score_boundaries(
    days_apart,
    expected_score,
):
    base_time = datetime(
        2026,
        1,
        10,
        12,
        0,
        tzinfo=timezone.utc,
    )

    lost_item = make_item(
        item_type="lost",
        created_at=base_time,
    )

    found_item = make_item(
        item_type="found",
        created_at=base_time + timedelta(days=days_apart),
    )

    assert score_time(
        lost_item,
        found_item,
    ) == expected_score


def test_time_score_is_symmetric():
    base_time = datetime(
        2026,
        1,
        10,
        12,
        0,
        tzinfo=timezone.utc,
    )

    later_time = base_time + timedelta(days=5)

    lost_item = make_item(
        item_type="lost",
        created_at=base_time,
    )

    found_item = make_item(
        item_type="found",
        created_at=later_time,
    )

    forward_score = score_time(
        lost_item,
        found_item,
    )

    reverse_score = score_time(
        found_item,
        lost_item,
    )

    assert forward_score == reverse_score


# ============================================================================
# MATCH CLASSIFICATION
# ============================================================================


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0, MATCH_LEVEL_NONE),
        (59, MATCH_LEVEL_NONE),
        (60, MATCH_LEVEL_POSSIBLE),
        (79, MATCH_LEVEL_POSSIBLE),
        (80, MATCH_LEVEL_STRONG),
        (100, MATCH_LEVEL_STRONG),
    ],
)
def test_classify_match_boundaries(
    score,
    expected_level,
):
    assert classify_match(score) == expected_level


# ============================================================================
# COMPLETE MATCHING
# ============================================================================


def test_exact_lost_and_found_items_produce_strong_match():
    created_at = datetime(
        2026,
        1,
        10,
        12,
        0,
        tzinfo=timezone.utc,
    )

    lost_item = make_item(
        item_type="lost",
        title="Black leather wallet",
        description=(
            "Black leather wallet with several cards and a small photo."
        ),
        category="wallet",
        location="Nairobi CBD",
        created_at=created_at,
    )

    found_item = make_item(
        item_type="found",
        title="Black leather wallet",
        description=(
            "Black leather wallet with several cards and a small photo."
        ),
        category="wallet",
        location="Nairobi CBD",
        created_at=created_at,
    )

    result = calculate_match(
        lost_item,
        found_item,
    )

    assert result.score == MAX_MATCH_SCORE
    assert result.score == 100
    assert result.match_level == MATCH_LEVEL_STRONG

    assert result.category_score == CATEGORY_MAX_SCORE
    assert result.title_score == TITLE_MAX_SCORE
    assert result.description_score == DESCRIPTION_MAX_SCORE
    assert result.location_score == LOCATION_MAX_SCORE
    assert result.time_score == TIME_MAX_SCORE

    assert "exact category match" in result.reason
    assert "strong title similarity" in result.reason
    assert "strong description similarity" in result.reason
    assert "matching location" in result.reason
    assert "items reported close together in time" in result.reason


def test_partial_similarity_produces_possible_match():
    base_time = datetime(
        2026,
        1,
        10,
        12,
        0,
        tzinfo=timezone.utc,
    )

    lost_item = make_item(
        item_type="lost",
        title="Black leather wallet",
        description=(
            "Black leather wallet containing bank cards and a photo."
        ),
        category="wallet",
        location="Nairobi CBD",
        created_at=base_time,
    )

    found_item = make_item(
        item_type="found",
        title="Black leather bag",
        description=(
            "Black leather wallet containing some cards."
        ),
        category="wallet",
        location="Nairobi CBD",
        created_at=base_time + timedelta(days=3),
    )

    result = calculate_match(
        lost_item,
        found_item,
    )

    assert 0 < result.score < 100
    assert result.match_level == MATCH_LEVEL_POSSIBLE


def test_match_is_independent_of_argument_order():
    lost_item = make_item(
        item_type="lost",
        title="Black leather wallet",
        category="wallet",
        location="Nairobi CBD",
    )

    found_item = make_item(
        item_type="found",
        title="Black leather wallet",
        category="wallet",
        location="Nairobi CBD",
    )

    first_result = calculate_match(
        lost_item,
        found_item,
    )

    second_result = calculate_match(
        found_item,
        lost_item,
    )

    assert first_result == second_result


# ============================================================================
# INVALID MATCH PAIRS
# ============================================================================


@pytest.mark.parametrize(
    "item_type",
    [
        "lost",
        "found",
    ],
)
def test_same_item_types_cannot_be_matched(item_type):
    first_item = make_item(
        item_type=item_type,
    )

    second_item = make_item(
        item_type=item_type,
    )

    with pytest.raises(
        ValueError,
        match="Matching requires one lost item and one found item",
    ):
        calculate_match(
            first_item,
            second_item,
        )


def test_invalid_first_item_type_is_rejected():
    first_item = make_item(
        item_type="unknown",
    )

    second_item = make_item(
        item_type="found",
    )

    with pytest.raises(
        ValueError,
        match="First item must have type 'lost' or 'found'",
    ):
        calculate_match(
            first_item,
            second_item,
        )


def test_invalid_second_item_type_is_rejected():
    first_item = make_item(
        item_type="lost",
    )

    second_item = make_item(
        item_type="unknown",
    )

    with pytest.raises(
        ValueError,
        match="Second item must have type 'lost' or 'found'",
    ):
        calculate_match(
            first_item,
            second_item,
        )


# ============================================================================
# SCORE INVARIANTS
# ============================================================================


def test_match_score_never_exceeds_100():
    lost_item = make_item(
        item_type="lost",
    )

    found_item = make_item(
        item_type="found",
    )

    result = calculate_match(
        lost_item,
        found_item,
    )

    assert 0 <= result.score <= MAX_MATCH_SCORE


def test_match_result_contains_all_score_components():
    lost_item = make_item(
        item_type="lost",
    )

    found_item = make_item(
        item_type="found",
    )

    result = calculate_match(
        lost_item,
        found_item,
    )

    component_total = (
        result.category_score
        + result.title_score
        + result.description_score
        + result.location_score
        + result.time_score
    )

    assert component_total == result.score


def test_score_components_respect_their_maximums():
    lost_item = make_item(
        item_type="lost",
    )

    found_item = make_item(
        item_type="found",
    )

    result = calculate_match(
        lost_item,
        found_item,
    )

    assert 0 <= result.category_score <= CATEGORY_MAX_SCORE
    assert 0 <= result.title_score <= TITLE_MAX_SCORE
    assert 0 <= result.description_score <= DESCRIPTION_MAX_SCORE
    assert 0 <= result.location_score <= LOCATION_MAX_SCORE
    assert 0 <= result.time_score <= TIME_MAX_SCORE