"""
TRACKIT Notification Service Unit Tests.

Tests the notification business/service layer directly.

Coverage:
- notification creation
- notification content normalization
- invalid notification input
- single notification retrieval
- notification ownership isolation
- user notification listing
- unread notification listing
- unread notification counting
- marking one notification as read
- notification ownership protection
- marking all notifications as read

Architecture under test:

    Service
       ↓
    Repository
       ↓
    SQLAlchemy Model
       ↓
    PostgreSQL
"""

from app.models.notification import Notification
from app.models.user import User
from app.services.notification import (
    NOTIFICATION_CLAIM_APPROVED,
    NOTIFICATION_CLAIM_CREATED,
    NOTIFICATION_CLAIM_REJECTED,
    NOTIFICATION_CLAIM_WITHDRAWN,
    count_unread_notifications,
    create_notification,
    get_notification,
    list_unread_notifications,
    list_user_notifications,
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
        username=f"notificationserviceuser{user_id}",
        first_name="Notification",
        last_name="Service",
        email=f"notificationserviceuser{user_id}@trackit.test",
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
    notification_type: str = NOTIFICATION_CLAIM_CREATED,
    title: str = "Claim Update",
    message: str = "Your claim has been updated.",
):
    """
    Create a valid notification through the service.
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
    assert notification.type == NOTIFICATION_CLAIM_CREATED
    assert notification.title == "Claim Update"
    assert notification.message == "Your claim has been updated."
    assert notification.is_read is False
    assert notification.created_at is not None


def test_create_notification_normalizes_content(db):
    """
    Notification type, title, and message should be stripped of
    surrounding whitespace.
    """

    create_test_user(
        db,
        user_id=TEST_USER_ID,
    )

    notification = create_notification(
        db,
        user_id=TEST_USER_ID,
        notification_type="  claim_created  ",
        title="  Claim Created  ",
        message="  A new claim was submitted.  ",
    )

    assert notification.type == "claim_created"
    assert notification.title == "Claim Created"
    assert notification.message == "A new claim was submitted."


def test_create_notification_starts_unread(db):
    """
    Newly created notifications must start as unread.
    """

    notification = create_test_notification(db)

    assert notification.is_read is False


def test_create_notification_rejects_empty_type(db):
    """
    Empty notification types should be rejected.
    """

    create_test_user(
        db,
        user_id=TEST_USER_ID,
    )

    try:
        create_notification(
            db,
            user_id=TEST_USER_ID,
            notification_type="   ",
            title="Valid Title",
            message="Valid message.",
        )
    except ValueError as exc:
        assert str(exc) == "Notification type cannot be empty."
    else:
        raise AssertionError(
            "Expected ValueError for empty notification type."
        )


def test_create_notification_rejects_empty_title(db):
    """
    Empty notification titles should be rejected.
    """

    create_test_user(
        db,
        user_id=TEST_USER_ID,
    )

    try:
        create_notification(
            db,
            user_id=TEST_USER_ID,
            notification_type=NOTIFICATION_CLAIM_CREATED,
            title="   ",
            message="Valid message.",
        )
    except ValueError as exc:
        assert str(exc) == "Notification title cannot be empty."
    else:
        raise AssertionError(
            "Expected ValueError for empty notification title."
        )


def test_create_notification_rejects_empty_message(db):
    """
    Empty notification messages should be rejected.
    """

    create_test_user(
        db,
        user_id=TEST_USER_ID,
    )

    try:
        create_notification(
            db,
            user_id=TEST_USER_ID,
            notification_type=NOTIFICATION_CLAIM_CREATED,
            title="Valid Title",
            message="   ",
        )
    except ValueError as exc:
        assert str(exc) == "Notification message cannot be empty."
    else:
        raise AssertionError(
            "Expected ValueError for empty notification message."
        )


def test_create_notification_rejects_invalid_user_id(db):
    """
    Notification creation must reject a non-positive user ID.
    """

    try:
        create_notification(
            db,
            user_id=0,
            notification_type=NOTIFICATION_CLAIM_CREATED,
            title="Valid Title",
            message="Valid message.",
        )
    except ValueError as exc:
        assert str(exc) == (
            "Notification user ID must be a positive integer."
        )
    else:
        raise AssertionError(
            "Expected ValueError for invalid user ID."
        )


# ============================================================================
# READ — SINGLE NOTIFICATION
# ============================================================================


def test_get_notification_returns_owned_notification(db):
    """
    A user should be able to retrieve their own notification.
    """

    notification = create_test_notification(db)

    result = get_notification(
        db,
        notification_id=notification.id,
        user_id=TEST_USER_ID,
    )

    assert result is not None
    assert result.id == notification.id
    assert result.user_id == TEST_USER_ID


def test_get_notification_returns_none_for_missing_notification(db):
    """
    A nonexistent notification should return None.
    """

    create_test_user(
        db,
        user_id=TEST_USER_ID,
    )

    result = get_notification(
        db,
        notification_id=999999,
        user_id=TEST_USER_ID,
    )

    assert result is None


def test_get_notification_enforces_user_ownership(db):
    """
    A user must not be able to retrieve another user's notification.
    """

    notification = create_test_notification(
        db,
        user_id=TEST_USER_ID,
    )

    create_test_user(
        db,
        user_id=TEST_SECOND_USER_ID,
    )

    result = get_notification(
        db,
        notification_id=notification.id,
        user_id=TEST_SECOND_USER_ID,
    )

    assert result is None


def test_get_notification_returns_none_for_invalid_notification_id(db):
    """
    Invalid notification IDs should return None.
    """

    result = get_notification(
        db,
        notification_id=0,
        user_id=TEST_USER_ID,
    )

    assert result is None


# ============================================================================
# READ — USER NOTIFICATIONS
# ============================================================================


def test_list_user_notifications_returns_only_owned_notifications(db):
    """
    User notification listing must only return notifications belonging
    to the requested user.
    """

    first = create_test_notification(
        db,
        user_id=TEST_USER_ID,
        title="User One First",
    )

    second = create_test_notification(
        db,
        user_id=TEST_USER_ID,
        title="User One Second",
    )

    create_test_notification(
        db,
        user_id=TEST_SECOND_USER_ID,
        title="User Two Notification",
    )

    results = list_user_notifications(
        db,
        user_id=TEST_USER_ID,
    )

    assert len(results) == 2
    assert {result.id for result in results} == {
        first.id,
        second.id,
    }
    assert all(
        result.user_id == TEST_USER_ID
        for result in results
    )


def test_list_user_notifications_returns_empty_list_when_none_exist(db):
    """
    A user without notifications should receive an empty list.
    """

    create_test_user(
        db,
        user_id=50,
    )

    results = list_user_notifications(
        db,
        user_id=50,
    )

    assert results == []


def test_list_user_notifications_returns_empty_for_invalid_user_id(db):
    """
    An invalid user ID should return an empty notification list.
    """

    results = list_user_notifications(
        db,
        user_id=0,
    )

    assert results == []


# ============================================================================
# READ — UNREAD NOTIFICATIONS
# ============================================================================


def test_list_unread_notifications_returns_only_unread(db):
    """
    Unread listing must exclude notifications already marked as read.
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

    results = list_unread_notifications(
        db,
        user_id=TEST_USER_ID,
    )

    assert len(results) == 1
    assert results[0].id == unread.id
    assert results[0].is_read is False


def test_list_unread_notifications_enforces_user_ownership(db):
    """
    Unread notifications from another user must not be returned.
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

    results = list_unread_notifications(
        db,
        user_id=TEST_USER_ID,
    )

    assert len(results) == 1
    assert results[0].user_id == TEST_USER_ID


def test_list_unread_notifications_returns_empty_when_all_are_read(db):
    """
    A user with only read notifications should receive an empty list.
    """

    notification = create_test_notification(db)

    notification.is_read = True
    db.flush()

    results = list_unread_notifications(
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
    A user with no unread notifications should receive zero.
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
    Unread counts must not include another user's notifications.
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
    The owner should be able to mark their notification as read.
    """

    notification = create_test_notification(db)

    assert notification.is_read is False

    result = mark_notification_as_read(
        db,
        notification=notification,
        user_id=TEST_USER_ID,
    )

    assert result is notification
    assert result.is_read is True


def test_mark_notification_as_read_is_idempotent(db):
    """
    Marking an already-read notification as read should remain safe.
    """

    notification = create_test_notification(db)

    notification.is_read = True
    db.flush()

    result = mark_notification_as_read(
        db,
        notification=notification,
        user_id=TEST_USER_ID,
    )

    assert result.is_read is True


def test_mark_notification_as_read_rejects_other_users_notification(
    db,
):
    """
    A user must not be able to mark another user's notification as read.
    """

    notification = create_test_notification(
        db,
        user_id=TEST_USER_ID,
    )

    create_test_user(
        db,
        user_id=TEST_SECOND_USER_ID,
    )

    try:
        mark_notification_as_read(
            db,
            notification=notification,
            user_id=TEST_SECOND_USER_ID,
        )
    except PermissionError as exc:
        assert str(exc) == (
            "You are not authorized to modify this notification."
        )
    else:
        raise AssertionError(
            "Expected PermissionError for another user's notification."
        )

    assert notification.is_read is False


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
# NOTIFICATION TYPE CONSTANTS
# ============================================================================


def test_claim_notification_types_are_defined():
    """
    Claim lifecycle notification types should be stable constants.
    """

    assert NOTIFICATION_CLAIM_CREATED == "claim_created"
    assert NOTIFICATION_CLAIM_APPROVED == "claim_approved"
    assert NOTIFICATION_CLAIM_REJECTED == "claim_rejected"
    assert NOTIFICATION_CLAIM_WITHDRAWN == "claim_withdrawn"


# ============================================================================
# DATABASE PERSISTENCE
# ============================================================================


def test_notification_service_persists_notification(db):
    """
    A notification created through the service should be retrievable
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
    assert persisted.type == NOTIFICATION_CLAIM_CREATED
    assert persisted.title == notification.title
    assert persisted.message == notification.message
    assert persisted.is_read is False
