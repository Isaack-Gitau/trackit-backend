"""
TRACKIT Matching Service.

Provides deterministic matching between LOST and FOUND items.

Architecture:

    Item
      ↓
    Matching Service
      ↓
    Match Result

This module intentionally does not persist Match records, create claims,
or send notifications. Those responsibilities belong to higher-level
application workflows.

V1 matching uses only information already present on Item:

- category
- title
- description
- location
- created_at
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from app.models.item import Item


# ============================================================================
# SCORE WEIGHTS
# ============================================================================


CATEGORY_MAX_SCORE = 25
TITLE_MAX_SCORE = 20
DESCRIPTION_MAX_SCORE = 30
LOCATION_MAX_SCORE = 15
TIME_MAX_SCORE = 10

MAX_MATCH_SCORE = (
    CATEGORY_MAX_SCORE
    + TITLE_MAX_SCORE
    + DESCRIPTION_MAX_SCORE
    + LOCATION_MAX_SCORE
    + TIME_MAX_SCORE
)


# ============================================================================
# MATCH THRESHOLDS
# ============================================================================


MATCH_THRESHOLD_POSSIBLE = 60
MATCH_THRESHOLD_STRONG = 80


MATCH_LEVEL_NONE = "none"
MATCH_LEVEL_POSSIBLE = "possible"
MATCH_LEVEL_STRONG = "strong"


# ============================================================================
# TIME SCORING
# ============================================================================


TIME_EXACT_DAYS = 1
TIME_CLOSE_DAYS = 3
TIME_RECENT_DAYS = 7
TIME_MAX_DAYS = 30


# ============================================================================
# TEXT NORMALIZATION
# ============================================================================


_WORD_PATTERN = re.compile(r"[a-z0-9]+")


def normalize_text(value: str) -> str:
    """
    Normalize text for deterministic comparison.

    The normalization:

    - converts text to lowercase
    - replaces punctuation with spaces
    - collapses repeated whitespace
    - strips leading/trailing whitespace
    """

    normalized = value.lower().strip()

    normalized = re.sub(
        r"[^a-z0-9]+",
        " ",
        normalized,
    )

    return " ".join(normalized.split())


def tokenize(value: str) -> set[str]:
    """
    Convert text into a normalized set of alphanumeric tokens.
    """

    return set(
        _WORD_PATTERN.findall(
            normalize_text(value),
        )
    )


def token_similarity(
    first: str,
    second: str,
) -> float:
    """
    Calculate Jaccard token similarity.

    Returns a value between 0.0 and 1.0.

    Formula:

        intersection / union

    Empty values produce 0.0.
    """

    first_tokens = tokenize(first)
    second_tokens = tokenize(second)

    if not first_tokens or not second_tokens:
        return 0.0

    intersection = first_tokens & second_tokens
    union = first_tokens | second_tokens

    if not union:
        return 0.0

    return len(intersection) / len(union)


# ============================================================================
# INDIVIDUAL SCORING FUNCTIONS
# ============================================================================


def score_category(
    lost_item: Item,
    found_item: Item,
) -> int:
    """
    Score category similarity.

    Exact normalized category match receives the full 25 points.
    """

    lost_category = normalize_text(lost_item.category)
    found_category = normalize_text(found_item.category)

    if (
        lost_category
        and found_category
        and lost_category == found_category
    ):
        return CATEGORY_MAX_SCORE

    return 0


def score_title(
    lost_item: Item,
    found_item: Item,
) -> int:
    """
    Score title similarity using normalized token overlap.
    """

    similarity = token_similarity(
        lost_item.title,
        found_item.title,
    )

    return round(
        similarity * TITLE_MAX_SCORE
    )


def score_description(
    lost_item: Item,
    found_item: Item,
) -> int:
    """
    Score description similarity using normalized token overlap.
    """

    similarity = token_similarity(
        lost_item.description,
        found_item.description,
    )

    return round(
        similarity * DESCRIPTION_MAX_SCORE
    )


def score_location(
    lost_item: Item,
    found_item: Item,
) -> int:
    """
    Score location similarity using normalized token overlap.
    """

    similarity = token_similarity(
        lost_item.location,
        found_item.location,
    )

    return round(
        similarity * LOCATION_MAX_SCORE
    )


def score_time(
    lost_item: Item,
    found_item: Item,
) -> int:
    """
    Score temporal proximity using Item.created_at.

    Current Item does not contain dedicated lost/found event timestamps,
    so created_at is the only reliable time signal available.

    Scoring:

        <= 1 day   → 10
        <= 3 days  → 8
        <= 7 days  → 6
        <= 30 days → linearly reduced
        > 30 days  → 0
    """

    difference = abs(
        lost_item.created_at - found_item.created_at
    )

    days = difference.total_seconds() / 86400

    if days <= TIME_EXACT_DAYS:
        return TIME_MAX_SCORE

    if days <= TIME_CLOSE_DAYS:
        return 8

    if days <= TIME_RECENT_DAYS:
        return 6

    if days <= TIME_MAX_DAYS:
        remaining_days = TIME_MAX_DAYS - days
        score = (
            remaining_days
            / (TIME_MAX_DAYS - TIME_RECENT_DAYS)
        ) * 6

        return max(
            0,
            round(score),
        )

    return 0


# ============================================================================
# MATCH CLASSIFICATION
# ============================================================================


def classify_match(score: int) -> str:
    """
    Convert a numeric score into a match level.
    """

    if score >= MATCH_THRESHOLD_STRONG:
        return MATCH_LEVEL_STRONG

    if score >= MATCH_THRESHOLD_POSSIBLE:
        return MATCH_LEVEL_POSSIBLE

    return MATCH_LEVEL_NONE


# ============================================================================
# MATCH RESULT
# ============================================================================


@dataclass(frozen=True)
class MatchResult:
    """
    Complete deterministic result produced by the matcher.
    """

    score: int
    match_level: str

    category_score: int
    title_score: int
    description_score: int
    location_score: int
    time_score: int

    reason: str


# ============================================================================
# REASON GENERATION
# ============================================================================


def build_match_reason(
    *,
    category_score: int,
    title_score: int,
    description_score: int,
    location_score: int,
    time_score: int,
    lost_item: Item,
    found_item: Item,
) -> str:
    """
    Build a human-readable explanation for the match score.
    """

    reasons: list[str] = []

    if category_score == CATEGORY_MAX_SCORE:
        reasons.append("exact category match")

    if title_score >= round(TITLE_MAX_SCORE * 0.75):
        reasons.append("strong title similarity")
    elif title_score >= round(TITLE_MAX_SCORE * 0.40):
        reasons.append("partial title similarity")

    if description_score >= round(
        DESCRIPTION_MAX_SCORE * 0.75
    ):
        reasons.append("strong description similarity")
    elif description_score >= round(
        DESCRIPTION_MAX_SCORE * 0.40
    ):
        reasons.append("partial description similarity")

    if location_score == LOCATION_MAX_SCORE:
        reasons.append("matching location")
    elif location_score >= round(
        LOCATION_MAX_SCORE * 0.50
    ):
        reasons.append("similar location")

    if time_score >= 8:
        reasons.append("items reported close together in time")
    elif time_score >= 4:
        reasons.append("items reported within a relatively close period")

    if not reasons:
        reasons.append(
            "limited similarity across the available item information"
        )

    return "; ".join(reasons) + "."


# ============================================================================
# MAIN MATCH FUNCTION
# ============================================================================


def calculate_match(
    first_item: Item,
    second_item: Item,
) -> MatchResult:
    """
    Calculate a deterministic match between a LOST and FOUND item.

    The order of the arguments does not matter. The function normalizes
    them so that the LOST item is always compared against the FOUND item.

    Raises:
        ValueError:
            If both items have the same type or contain invalid item types.
    """

    valid_types = {
        "lost",
        "found",
    }

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
        lost_item = first_item
        found_item = second_item
    else:
        lost_item = second_item
        found_item = first_item

    category_score = score_category(
        lost_item,
        found_item,
    )

    title_score = score_title(
        lost_item,
        found_item,
    )

    description_score = score_description(
        lost_item,
        found_item,
    )

    location_score = score_location(
        lost_item,
        found_item,
    )

    time_score = score_time(
        lost_item,
        found_item,
    )

    total_score = (
        category_score
        + title_score
        + description_score
        + location_score
        + time_score
    )

    match_level = classify_match(
        total_score,
    )

    reason = build_match_reason(
        category_score=category_score,
        title_score=title_score,
        description_score=description_score,
        location_score=location_score,
        time_score=time_score,
        lost_item=lost_item,
        found_item=found_item,
    )

    return MatchResult(
        score=total_score,
        match_level=match_level,
        category_score=category_score,
        title_score=title_score,
        description_score=description_score,
        location_score=location_score,
        time_score=time_score,
        reason=reason,
    )
