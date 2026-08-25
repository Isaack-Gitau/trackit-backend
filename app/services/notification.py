"""
TRACKIT Notification Service.

Business logic for creating and managing persistent in-app
notifications.

Architecture:

    Router / Other Services
             ↓
    Notification Service
             ↓
    Notification Repository
             ↓
    Notification Model
             ↓
        PostgreSQL

Responsibilities:

- Create notifications for users.
- Retrieve a user's notifications.
- Retrieve unread notifications.
- Count unread notifications.
- Mark individual notifications as read.
- Mark all notifications belonging to a user as read.

Security principles:

- Notification ownership is always based on user_id.
- Callers must provide the authenticated user's identity.
- Notification content must never contain passwords, JWTs,
  authentication tokens, or other secrets.
- Authorization decisions remain at the service/router boundary.
- Database operations are delegated to the repository layer.
"""

from sqlalchemy.orm import Session

from app.models.notification import Notification
from app.repositories.notifications import (
    count_unread_notifications as repository_count_unread_notifications,
    create_notification as repository_create_notification,
    get_notification_by_id,
    get_notifications_by_user,
    get_unread_notifications_by_user,
    mark_all_notifications_as_read as repository_mark_all_notifications_as_read,
    mark_notification_as_read as repository_mark_notification_as_read,
)


# ============================================================================
# NOTIFICATION TYPES
# ============================================================================

NOTIFICATION_CLAIM_CREATED = "claim_created"
NOTIFICATION_CLAIM_APPROVED = "claim_approved"
NOTIFICATION_CLAIM_REJECTED = "claim_rejected"
NOTIFICATION_CLAIM_WITHDRAWN = "claim_withdrawn"


# ============================================================================
# CREATE
# ============================================================================


def create_notification(
    db: Session,
    *,
    user_id: int,
    notification_type: str,
    title: str,
    message: str,
) -> Notification:
    """
    Create a notification for a user.

    The notification starts unread.

    Basic content validation is performed here because notification
    creation is a service-level operation. Database persistence is
    delegated to the repository.
    """

    normalized_type = notification_type.strip()
    normalized_title = title.strip()
    normalized_message = message.strip()

    if not normalized_type:
        raise ValueError(
            "Notification type cannot be empty."
        )

    if not normalized_title:
        raise ValueError(
            "Notification title cannot be empty."
        )

    if not normalized_message:
        raise ValueError(
            "Notification message cannot be empty."
        )

    if user_id <= 0:
        raise ValueError(
            "Notification user ID must be a positive integer."
        )

    return repository_create_notification(
        db,
        user_id=user_id,
        notification_type=normalized_type,
        title=normalized_title,
        message=normalized_message,
    )


# ============================================================================
# READ — SINGLE NOTIFICATION
# ============================================================================


def get_notification(
    db: Session,
    *,
    notification_id: int,
    user_id: int,
) -> Notification | None:
    """
    Retrieve a notification belonging to the requested user.

    Ownership is enforced here rather than exposing the repository's
    unrestricted primary-key lookup directly to callers.

    Returns None when:

    - the notification does not exist; or
    - the notification belongs to another user.
    """

    if notification_id <= 0:
        return None

    if user_id <= 0:
        return None

    notification = get_notification_by_id(
        db,
        notification_id,
    )

    if notification is None:
        return None

    if notification.user_id != user_id:
        return None

    return notification


# ============================================================================
# READ — USER NOTIFICATIONS
# ============================================================================


def list_user_notifications(
    db: Session,
    *,
    user_id: int,
) -> list[Notification]:
    """
    Retrieve all notifications belonging to a user.

    Results are returned newest first by the repository.
    """

    if user_id <= 0:
        return []

    return get_notifications_by_user(
        db,
        user_id=user_id,
    )


# ============================================================================
# READ — UNREAD NOTIFICATIONS
# ============================================================================


def list_unread_notifications(
    db: Session,
    *,
    user_id: int,
) -> list[Notification]:
    """
    Retrieve unread notifications belonging to a user.

    Results are returned newest first by the repository.
    """

    if user_id <= 0:
        return []

    return get_unread_notifications_by_user(
        db,
        user_id=user_id,
    )


# ============================================================================
# COUNT — UNREAD NOTIFICATIONS
# ============================================================================


def count_unread_notifications(
    db: Session,
    *,
    user_id: int,
) -> int:
    """
    Count unread notifications belonging to a user.
    """

    if user_id <= 0:
        return 0

    return repository_count_unread_notifications(
        db,
        user_id=user_id,
    )


# ============================================================================
# UPDATE — MARK ONE AS READ
# ============================================================================


def mark_notification_as_read(
    db: Session,
    *,
    notification: Notification,
    user_id: int,
) -> Notification:
    """
    Mark one notification as read.

    The notification must belong to the requesting user.

    Raises PermissionError when another user's notification is supplied.
    """

    if user_id <= 0:
        raise PermissionError(
            "You are not authorized to modify this notification."
        )

    if notification.user_id != user_id:
        raise PermissionError(
            "You are not authorized to modify this notification."
        )

    return repository_mark_notification_as_read(
        db,
        notification,
    )


# ============================================================================
# UPDATE — MARK ALL AS READ
# ============================================================================


def mark_all_notifications_as_read(
    db: Session,
    *,
    user_id: int,
) -> int:
    """
    Mark all unread notifications belonging to a user as read.

    Returns the number of notifications changed.
    """

    if user_id <= 0:
        return 0

    return repository_mark_all_notifications_as_read(
        db,
        user_id=user_id,
    )
