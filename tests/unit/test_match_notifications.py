"""
TRACKIT Match Notification Service Tests.

Tests the business logic responsible for notifying users when a
potential LOST/FOUND match is found.

Coverage:
- notification creation for LOST item owner
- notification creation for FOUND item owner
- notification deduplication
- same-user ownership deduplication
- score threshold behavior
- persisted match requirement
- match notification metadata
- match entity linkage

Architecture under test:

    Item
      ↓
    Match
      ↓
    Notification Service
      ↓
    Notification Repository
"""

from datetime import datetime, timezone

import pytest

from app.models.item import Item
from app.models.match import Match
from app.models.notification import Notification
from app.models.user import User
from app.services.notification import (
    NOTIFICATION_CATEGORY_MATCH,
    NOTIFICATION_MATCH_FOUND,
    NOTIFICATION_PRIORITY_HIGH,
    notify_match_found,
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
        username=f"matchnotificationuser{user_id}",
        first_name="Match",
        last_name="Notification",
        email=f"matchnotificationuser{user_id}@trackit.test",
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
):
    """
    Create a persisted approved Item.
    """

    create_test_user(
        db,
        user_id=user_id,
    )

    item = Item(
        user_id=user_id,
        title=title,
        description="Black Dell laptop with silver logo.",
        type=item_type,
        category="Electronics",
        location="Main Library",
        status="approved",
        created_at=datetime.now(timezone.utc),
    )

    db.add(item)
    db.flush()

    return item


def create_test_match(
    db,
    *,
    lost_user_id: int = 1,
    found_user_id: int = 2,
    score: int = 85,
):
    """
    Create a persisted LOST/FOUND Match.
    """

    lost_item = create_test_item(
        db,
        user_id=lost_user_id,
        item_type="lost",
        title="Black Dell Laptop",
    )

    found_item = create_test_item(
        db,
        user_id=found_user_id,
        item_type="found",
        title="Black Dell Laptop",
    )

    match = Match(
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        score=score,
        match_level="strong" if score >= 80 else "possible",
        category_score=25,
        title_score=18,
        description_score=25,
        location_score=12,
        time_score=5,
        reason="exact category match; strong title similarity.",
        is_dismissed=False,
    )

    db.add(match)
    db.flush()

    return match, lost_item, found_item


# ============================================================================
# CREATE — MATCH NOTIFICATION
# ============================================================================


def test_notify_match_found_notifies_lost_item_owner(db):
    """
    The owner of the LOST item should receive a match notification.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    assert len(notifications) == 2

    lost_owner_notifications = [
        notification
        for notification in notifications
        if notification.user_id == lost_item.user_id
    ]

    assert len(lost_owner_notifications) == 1

    notification = lost_owner_notifications[0]

    assert notification.type == NOTIFICATION_MATCH_FOUND
    assert notification.category == NOTIFICATION_CATEGORY_MATCH
    assert notification.priority == NOTIFICATION_PRIORITY_HIGH
    assert notification.entity_type == "match"
    assert notification.entity_id == match.id


def test_notify_match_found_notifies_found_item_owner(db):
    """
    The owner of the FOUND item should receive a match notification.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    found_owner_notifications = [
        notification
        for notification in notifications
        if notification.user_id == found_item.user_id
    ]

    assert len(found_owner_notifications) == 1

    notification = found_owner_notifications[0]

    assert notification.type == NOTIFICATION_MATCH_FOUND
    assert notification.category == NOTIFICATION_CATEGORY_MATCH
    assert notification.priority == NOTIFICATION_PRIORITY_HIGH
    assert notification.entity_type == "match"
    assert notification.entity_id == match.id


def test_notify_match_found_creates_two_notifications_for_two_owners(
    db,
):
    """
    When different users own the LOST and FOUND items, both users
    should receive one notification.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    assert len(notifications) == 2

    recipient_ids = {
        notification.user_id
        for notification in notifications
    }

    assert recipient_ids == {
        lost_item.user_id,
        found_item.user_id,
    }


def test_notify_match_found_creates_one_notification_when_same_user_owns_both(
    db,
):
    """
    If the same user owns both participating items, only one
    notification should be created.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=1,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    assert len(notifications) == 1
    assert notifications[0].user_id == 1


# ============================================================================
# DEDUPLICATION
# ============================================================================


def test_notify_match_found_does_not_create_duplicate_notifications(
    db,
):
    """
    Calling notify_match_found repeatedly for the same match should
    not create duplicate notifications.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
    )

    first_notifications = notify_match_found(
        db,
        match=match,
    )

    second_notifications = notify_match_found(
        db,
        match=match,
    )

    assert len(first_notifications) == 2
    assert second_notifications == []

    all_notifications = (
        db.query(Notification)
        .filter(
            Notification.type == NOTIFICATION_MATCH_FOUND,
            Notification.entity_type == "match",
            Notification.entity_id == match.id,
        )
        .all()
    )

    assert len(all_notifications) == 2


def test_notify_match_found_deduplication_is_per_user(db):
    """
    Deduplication should be scoped to each recipient.

    One user's existing notification must not prevent another
    participating owner from receiving theirs.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
    )

    first_notifications = notify_match_found(
        db,
        match=match,
    )

    assert len(first_notifications) == 2

    lost_owner_notification = next(
        notification
        for notification in first_notifications
        if notification.user_id == lost_item.user_id
    )

    db.delete(lost_owner_notification)
    db.flush()

    second_notifications = notify_match_found(
        db,
        match=match,
    )

    assert len(second_notifications) == 1
    assert second_notifications[0].user_id == lost_item.user_id


# ============================================================================
# THRESHOLD
# ============================================================================


def test_notify_match_found_does_not_notify_below_possible_threshold(
    db,
):
    """
    Matches below the possible-match threshold should not generate
    notifications.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
        score=59,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    assert notifications == []

    persisted_notifications = (
        db.query(Notification)
        .filter(
            Notification.type == NOTIFICATION_MATCH_FOUND,
            Notification.entity_type == "match",
            Notification.entity_id == match.id,
        )
        .all()
    )

    assert persisted_notifications == []


def test_notify_match_found_notifies_at_possible_threshold(
    db,
):
    """
    A score of exactly 60 should generate match notifications.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
        score=60,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    assert len(notifications) == 2


def test_notify_match_found_notifies_strong_match(db):
    """
    Strong matches should generate notifications.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
        score=80,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    assert len(notifications) == 2


# ============================================================================
# CONTENT
# ============================================================================


def test_notify_match_found_uses_expected_title(db):
    """
    Match notifications should use the expected user-facing title.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    assert all(
        notification.title == "Potential Match Found"
        for notification in notifications
    )


def test_notify_match_found_message_contains_match_score(db):
    """
    The notification message should tell the user the match score.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
        score=85,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    assert all(
        "85/100" in notification.message
        for notification in notifications
    )


def test_notify_match_found_message_contains_match_reason(db):
    """
    The notification message should include the persisted match reason.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    assert all(
        match.reason in notification.message
        for notification in notifications
    )


# ============================================================================
# PERSISTENCE
# ============================================================================


def test_notify_match_found_notifications_are_persisted(db):
    """
    Newly created match notifications should be persisted in the
    database.
    """

    match, lost_item, found_item = create_test_match(
        db,
        lost_user_id=1,
        found_user_id=2,
    )

    notifications = notify_match_found(
        db,
        match=match,
    )

    assert len(notifications) == 2

    db.expire_all()

    for notification in notifications:
        persisted = db.get(
            Notification,
            notification.id,
        )

        assert persisted is not None
        assert persisted.user_id == notification.user_id
        assert persisted.type == NOTIFICATION_MATCH_FOUND
        assert persisted.entity_type == "match"
        assert persisted.entity_id == match.id


# ============================================================================
# VALIDATION
# ============================================================================


def test_notify_match_found_requires_persisted_match(db):
    """
    An unpersisted Match cannot generate notifications because the
    notification must link to a real Match ID.
    """

    match = Match(
        score=85,
        match_level="strong",
        category_score=25,
        title_score=18,
        description_score=25,
        location_score=12,
        time_score=5,
        reason="exact category match; strong title similarity.",
        is_dismissed=False,
    )

    with pytest.raises(
        ValueError,
        match="match must be persisted",
    ):
        notify_match_found(
            db,
            match=match,
        )

