"""
TRACKIT Notification Repository Unit Tests.

Tests the notification database-access layer directly.

Coverage:
- notification creation
- notification retrieval
- user notification listing
- unread notification listing
- unread notification counting
- marking one notification as read
- marking all user notifications as read
- user isolation
- notification ordering
- notification lookup by user and entity
- empty-result behavior

Architecture under test:

    Repository
       ↓
    SQLAlchemy Model
       ↓
    PostgreSQL

These tests intentionally test repository behavior rather than
notification business rules or HTTP/API authorization.
"""

from datetime import datetime, timedelta, timezone

from app.models.notification import Notification
from app.models.user import User
from app.repositories.notifications import (
    count_unread_notifications,
    create_notification,
    get_notification_by_id,
    get_notification_by_user_and_entity,
    get_notifications_by_user,
    get_unread_notifications_by_user,
    mark_all_notifications_as_read,
    mark_notification_as_read,
)


# ============================================================================
# TEST CONSTANTS
# ============================================================================

TEST_USER_ID = 1
TEST_SECOND_USER_ID = 2


# ============================================================================
# TEST HELPERS
# ============================================================================


def create_test_user(
    db,
    *,
    user_id: int,
):
    """
    Create a minimal valid User required by the notifications
    foreign-key constraint.
    """

    user = db.get(User, user_id)

    if user is not None:
        return user

    user = User(
        id=user_id,
        username=f"notificationuser{user_id}",
        first_name="Notification",
        last_name="User",
        email=f"notificationuser{user_id}@trackit.test",
        password_hash="test-password-hash",
        role="user",
        is_active=True,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    return user


def create_test_notification(
    db,
    *,
    user_id: int = TEST_USER_ID,
    notification_type: str = "claim",
    title: str = "Claim Update",
    message: str = "Your claim has been updated.",
):
    """
    Create a valid notification directly through the repository.
    """

    create_test_user(
        db,
        user_id=user_id,
    )

    return create_notification(
        db,
        user_id=user_id,
        notification_type=notification_type,
        title=title,
        message=message,
    )


# ============================================================================
# CREATE
# ============================================================================


def test_create_notification_successfully(db):
    """
    A valid notification should be created and persisted.
    """

    notification = create_test_notification(db)

    assert notification.id is not None
    assert notification.user_id == TEST_USER_ID
    assert notification.type == "claim"
    assert notification.title == "Claim Update"
    assert notification.message == "Your claim has been updated."
    assert notification.is_read is False
    assert notification.created_at is not None


def test_create_notification_starts_unread(db):
    """
    Newly created notifications must start as unread.
    """

    notification = create_test_notification(db)

    assert notification.is_read is False


def test_create_notifications_for_different_users(db):
    """
    Notifications should retain their correct recipient.
    """

    first = create_test_notification(
        db,
        user_id=TEST_USER_ID,
        title="User One Notification",
    )

    second = create_test_notification(
        db,
        user_id=TEST_SECOND_USER_ID,
        title="User Two Notification",
    )

    assert first.user_id == TEST_USER_ID
    assert second.user_id == TEST_SECOND_USER_ID


# ============================================================================
# READ — SINGLE NOTIFICATION
# ============================================================================


def test_get_notification_by_id(db):
    """
    An existing notification should be retrievable by ID.
    """

    notification = create_test_notification(db)

    result = get_notification_by_id(
        db,
        notification_id=notification.id,
    )

    assert result is not None
    assert result.id == notification.id
    assert result.user_id == TEST_USER_ID
    assert result.title == notification.title


def test_get_nonexistent_notification_returns_none(db):
    """
    A nonexistent notification ID should return None.
    """

    result = get_notification_by_id(
        db,
        notification_id=999999,
    )

    assert result is None


# ============================================================================
# READ — USER NOTIFICATIONS
# ============================================================================


def test_get_notifications_by_user_returns_only_owned_notifications(db):
    """
    User notification listing must only return notifications belonging
    to the requested user.
    """

    create_test_notification(
        db,
        user_id=TEST_USER_ID,
        title="User One Notification",
    )

    create_test_notification(
        db,
        user_id=TEST_USER_ID,
        title="User One Second Notification",
    )

    create_test_notification(
        db,
        user_id=TEST_SECOND_USER_ID,
        title="User Two Notification",
    )

    results = get_notifications_by_user(
        db,
        user_id=TEST_USER_ID,
    )

    assert len(results) == 2
    assert all(
        notification.user_id == TEST_USER_ID
        for notification in results
    )


def test_get_notifications_by_user_returns_empty_list_for_user_without_notifications(
    db,
):
    """
    A user without notifications should receive an empty list.
    """

    create_test_user(
        db,
        user_id=50,
    )

    results = get_notifications_by_user(
        db,
        user_id=50,
    )

    assert results == []


def test_get_notifications_by_user_returns_newest_first(db):
    """
    Notifications should be returned newest first.
    """

    first = create_test_notification(
        db,
        title="First Notification",
    )

    second = create_test_notification(
        db,
        title="Second Notification",
    )

    # Ensure deterministic timestamp ordering even on databases where
    # multiple records may receive the same timestamp.
    first.created_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    second.created_at = datetime.now(timezone.utc) - timedelta(minutes=1)

    db.flush()

    results = get_notifications_by_user(
        db,
        user_id=TEST_USER_ID,
    )

    assert len(results) == 2
    assert results[0].id == second.id
    assert results[1].id == first.id


# ============================================================================
# READ — UNREAD NOTIFICATIONS
# ============================================================================


def test_get_unread_notifications_by_user_returns_only_unread(db):
    """
    Unread notification listing must exclude notifications already
    marked as read.
    """

    unread = create_test_notification(
        db,
        title="Unread Notification",
    )

    read = create_test_notification(
        db,
        title="Read Notification",
    )

    read.is_read = True
    db.flush()

    results = get_unread_notifications_by_user(
        db,
        user_id=TEST_USER_ID,
    )

    assert len(results) == 1
    assert results[0].id == unread.id
    assert results[0].is_read is False


def test_get_unread_notifications_does_not_return_other_users_notifications(
    db,
):
    """
    Unread notification listing must respect user ownership.
    """

    create_test_notification(
        db,
        user_id=TEST_USER_ID,
        title="User One Unread",
    )

    create_test_notification(
        db,
        user_id=TEST_SECOND_USER_ID,
        title="User Two Unread",
    )

    results = get_unread_notifications_by_user(
        db,
        user_id=TEST_USER_ID,
    )

    assert len(results) == 1
    assert results[0].user_id == TEST_USER_ID


def test_get_unread_notifications_returns_empty_when_all_are_read(db):
    """
    A user with only read notifications should receive an empty
    unread-notification list.
    """

    notification = create_test_notification(db)

    notification.is_read = True
    db.flush()

    results = get_unread_notifications_by_user(
        db,
        user_id=TEST_USER_ID,
    )

    assert results == []


# ============================================================================
# COUNT — UNREAD NOTIFICATIONS
# ============================================================================


def test_count_unread_notifications(db):
    """
    The unread count should equal the number of unread notifications
    belonging to the requested user.
    """

    create_test_notification(
        db,
        title="Unread One",
    )

    create_test_notification(
        db,
        title="Unread Two",
    )

    read = create_test_notification(
        db,
        title="Read Notification",
    )

    read.is_read = True
    db.flush()

    count = count_unread_notifications(
        db,
        user_id=TEST_USER_ID,
    )

    assert count == 2


def test_count_unread_notifications_returns_zero_when_none_are_unread(
    db,
):
    """
    A user with no unread notifications should receive a count of zero.
    """

    notification = create_test_notification(db)

    notification.is_read = True
    db.flush()

    count = count_unread_notifications(
        db,
        user_id=TEST_USER_ID,
    )

    assert count == 0


def test_count_unread_notifications_is_user_specific(db):
    """
    Unread notification counts must not include another user's
    notifications.
    """

    create_test_notification(
        db,
        user_id=TEST_USER_ID,
        title="User One Notification",
    )

    create_test_notification(
        db,
        user_id=TEST_SECOND_USER_ID,
        title="User Two Notification",
    )

    first_count = count_unread_notifications(
        db,
        user_id=TEST_USER_ID,
    )

    second_count = count_unread_notifications(
        db,
        user_id=TEST_SECOND_USER_ID,
    )

    assert first_count == 1
    assert second_count == 1


# ============================================================================
# UPDATE — MARK ONE AS READ
# ============================================================================


def test_mark_notification_as_read(db):
    """
    Marking an unread notification as read should update its state.
    """

    notification = create_test_notification(db)

    assert notification.is_read is False

    result = mark_notification_as_read(
        db,
        notification,
    )

    assert result is notification
    assert result.is_read is True


def test_mark_notification_as_read_is_idempotent(db):
    """
    Marking an already-read notification as read again should remain
    safe and leave it read.
    """

    notification = create_test_notification(db)

    notification.is_read = True
    db.flush()

    result = mark_notification_as_read(
        db,
        notification,
    )

    assert result.is_read is True


# ============================================================================
# UPDATE — MARK ALL AS READ
# ============================================================================


def test_mark_all_notifications_as_read(db):
    """
    Mark-all should change every unread notification belonging to the
    requested user to read.
    """

    first = create_test_notification(
        db,
        title="First Unread",
    )

    second = create_test_notification(
        db,
        title="Second Unread",
    )

    already_read = create_test_notification(
        db,
        title="Already Read",
    )

    already_read.is_read = True
    db.flush()

    updated_count = mark_all_notifications_as_read(
        db,
        user_id=TEST_USER_ID,
    )

    assert updated_count == 2
    assert first.is_read is True
    assert second.is_read is True
    assert already_read.is_read is True


def test_mark_all_notifications_as_read_does_not_modify_other_users(
    db,
):
    """
    Mark-all must never modify notifications belonging to another user.
    """

    user_one_notification = create_test_notification(
        db,
        user_id=TEST_USER_ID,
        title="User One Notification",
    )

    user_two_notification = create_test_notification(
        db,
        user_id=TEST_SECOND_USER_ID,
        title="User Two Notification",
    )

    updated_count = mark_all_notifications_as_read(
        db,
        user_id=TEST_USER_ID,
    )

    assert updated_count == 1
    assert user_one_notification.is_read is True
    assert user_two_notification.is_read is False


def test_mark_all_notifications_as_read_returns_zero_when_none_are_unread(
    db,
):
    """
    Mark-all should return zero when the user has no unread notifications.
    """

    notification = create_test_notification(db)

    notification.is_read = True
    db.flush()

    updated_count = mark_all_notifications_as_read(
        db,
        user_id=TEST_USER_ID,
    )

    assert updated_count == 0


# ============================================================================
# DATABASE PERSISTENCE
# ============================================================================


def test_notification_is_persisted_in_database(db):
    """
    A notification created through the repository should be retrievable
    through a fresh database lookup.
    """

    notification = create_test_notification(db)

    db.expire_all()

    persisted = db.get(
        Notification,
        notification.id,
    )

    assert persisted is not None
    assert persisted.id == notification.id
    assert persisted.user_id == TEST_USER_ID
    assert persisted.type == notification.type
    assert persisted.title == notification.title
    assert persisted.message == notification.message
    assert persisted.is_read is False


# ============================================================================
# READ — NOTIFICATION BY USER AND ENTITY
# ============================================================================


def test_get_notification_by_user_and_entity_returns_matching_notification(
    db,
):
    """
    A notification should be returned when user, notification type,
    entity type, and entity ID all match.
    """

    notification = create_test_notification(
        db,
        user_id=TEST_USER_ID,
        notification_type="match_found",
    )

    notification.entity_type = "match"
    notification.entity_id = 123
    db.flush()

    result = get_notification_by_user_and_entity(
        db,
        user_id=TEST_USER_ID,
        notification_type="match_found",
        entity_type="match",
        entity_id=123,
    )

    assert result is notification


def test_get_notification_by_user_and_entity_is_user_specific(db):
    """
    A matching notification belonging to another user must not be
    returned.
    """

    notification = create_test_notification(
        db,
        user_id=TEST_USER_ID,
        notification_type="match_found",
    )

    notification.entity_type = "match"
    notification.entity_id = 123
    db.flush()

    result = get_notification_by_user_and_entity(
        db,
        user_id=TEST_SECOND_USER_ID,
        notification_type="match_found",
        entity_type="match",
        entity_id=123,
    )

    assert result is None


def test_get_notification_by_user_and_entity_is_entity_specific(db):
    """
    A notification for a different entity must not be returned.
    """

    notification = create_test_notification(
        db,
        user_id=TEST_USER_ID,
        notification_type="match_found",
    )

    notification.entity_type = "match"
    notification.entity_id = 123
    db.flush()

    result = get_notification_by_user_and_entity(
        db,
        user_id=TEST_USER_ID,
        notification_type="match_found",
        entity_type="match",
        entity_id=456,
    )

    assert result is None


def test_get_notification_by_user_and_entity_is_type_specific(db):
    """
    A notification with a different notification type must not be
    returned even when the user and entity match.
    """

    notification = create_test_notification(
        db,
        user_id=TEST_USER_ID,
        notification_type="different_notification",
    )

    notification.entity_type = "match"
    notification.entity_id = 123
    db.flush()

    result = get_notification_by_user_and_entity(
        db,
        user_id=TEST_USER_ID,
        notification_type="match_found",
        entity_type="match",
        entity_id=123,
    )

    assert result is None


def test_get_notification_by_user_and_entity_returns_none_when_missing(
    db,
):
    """
    A lookup for a notification that does not exist should return None.
    """

    create_test_notification(
        db,
        user_id=TEST_USER_ID,
        notification_type="match_found",
    )

    result = get_notification_by_user_and_entity(
        db,
        user_id=TEST_USER_ID,
        notification_type="match_found",
        entity_type="match",
        entity_id=999,
    )

    assert result is None