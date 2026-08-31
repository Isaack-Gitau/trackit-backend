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
- Delete individual notifications.
- Delete selected notifications.
- Delete all notifications belonging to a user.

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
    delete_all_notifications_by_user as repository_delete_all_notifications_by_user,
    delete_notification as repository_delete_notification,
    delete_selected_notifications as repository_delete_selected_notifications,
    get_notification_by_id,
    get_notifications_by_user,
    get_unread_notifications_by_user,
    mark_all_notifications_as_read as repository_mark_all_notifications_as_read,
    mark_notification_as_read as repository_mark_notification_as_read,
)


# ============================================================================
# NOTIFICATION TYPES
# ============================================================================


NOTIFICATION_ITEM_APPROVED = "item_approved"
NOTIFICATION_ITEM_REJECTED = "item_rejected"

NOTIFICATION_CLAIM_CREATED = "claim_created"
NOTIFICATION_CLAIM_APPROVED = "claim_approved"
NOTIFICATION_CLAIM_REJECTED = "claim_rejected"
NOTIFICATION_CLAIM_WITHDRAWN = "claim_withdrawn"


# ============================================================================
# NOTIFICATION CATEGORIES
# ============================================================================


NOTIFICATION_CATEGORY_SYSTEM = "system"
NOTIFICATION_CATEGORY_CLAIM = "claim"
NOTIFICATION_CATEGORY_ITEM = "item"
NOTIFICATION_CATEGORY_ACCOUNT = "account"
NOTIFICATION_CATEGORY_SECURITY = "security"


# ============================================================================
# NOTIFICATION PRIORITIES
# ============================================================================


NOTIFICATION_PRIORITY_LOW = "low"
NOTIFICATION_PRIORITY_NORMAL = "normal"
NOTIFICATION_PRIORITY_HIGH = "high"
NOTIFICATION_PRIORITY_URGENT = "urgent"


VALID_NOTIFICATION_CATEGORIES = {
    NOTIFICATION_CATEGORY_SYSTEM,
    NOTIFICATION_CATEGORY_CLAIM,
    NOTIFICATION_CATEGORY_ITEM,
    NOTIFICATION_CATEGORY_ACCOUNT,
    NOTIFICATION_CATEGORY_SECURITY,
}


VALID_NOTIFICATION_PRIORITIES = {
    NOTIFICATION_PRIORITY_LOW,
    NOTIFICATION_PRIORITY_NORMAL,
    NOTIFICATION_PRIORITY_HIGH,
    NOTIFICATION_PRIORITY_URGENT,
}


# ============================================================================
# DEFAULT TYPE METADATA
# ============================================================================


_NOTIFICATION_TYPE_METADATA = {
    NOTIFICATION_ITEM_APPROVED: (
        NOTIFICATION_CATEGORY_ITEM,
        NOTIFICATION_PRIORITY_HIGH,
    ),
    NOTIFICATION_ITEM_REJECTED: (
        NOTIFICATION_CATEGORY_ITEM,
        NOTIFICATION_PRIORITY_HIGH,
    ),
    NOTIFICATION_CLAIM_CREATED: (
        NOTIFICATION_CATEGORY_CLAIM,
        NOTIFICATION_PRIORITY_NORMAL,
    ),
    NOTIFICATION_CLAIM_APPROVED: (
        NOTIFICATION_CATEGORY_CLAIM,
        NOTIFICATION_PRIORITY_HIGH,
    ),
    NOTIFICATION_CLAIM_REJECTED: (
        NOTIFICATION_CATEGORY_CLAIM,
        NOTIFICATION_PRIORITY_HIGH,
    ),
    NOTIFICATION_CLAIM_WITHDRAWN: (
        NOTIFICATION_CATEGORY_CLAIM,
        NOTIFICATION_PRIORITY_NORMAL,
    ),
}


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
    category: str | None = None,
    priority: str | None = None,
    entity_type: str | None = None,
    entity_id: int | None = None,
) -> Notification:
    """
    Create a notification for a user.

    Category and priority are automatically derived from the notification
    type when they are not explicitly supplied.

    This keeps existing notification callers backward-compatible while
    allowing newer callers to provide explicit context.
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

    if entity_id is not None and entity_id <= 0:
        raise ValueError(
            "Notification entity ID must be a positive integer."
        )

    metadata = _NOTIFICATION_TYPE_METADATA.get(
        normalized_type,
        (
            NOTIFICATION_CATEGORY_SYSTEM,
            NOTIFICATION_PRIORITY_NORMAL,
        ),
    )

    resolved_category = (
        category.strip()
        if category is not None
        else metadata[0]
    )

    resolved_priority = (
        priority.strip()
        if priority is not None
        else metadata[1]
    )

    if not resolved_category:
        raise ValueError(
            "Notification category cannot be empty."
        )

    if resolved_category not in VALID_NOTIFICATION_CATEGORIES:
        raise ValueError(
            "Invalid notification category."
        )

    if not resolved_priority:
        raise ValueError(
            "Notification priority cannot be empty."
        )

    if resolved_priority not in VALID_NOTIFICATION_PRIORITIES:
        raise ValueError(
            "Invalid notification priority."
        )

    normalized_entity_type = (
        entity_type.strip()
        if entity_type is not None
        else None
    )

    if normalized_entity_type == "":
        normalized_entity_type = None

    if normalized_entity_type is None and entity_id is not None:
        raise ValueError(
            "Notification entity type is required when entity ID is provided."
        )

    if normalized_entity_type is not None and entity_id is None:
        raise ValueError(
            "Notification entity ID is required when entity type is provided."
        )

    return repository_create_notification(
        db,
        user_id=user_id,
        notification_type=normalized_type,
        title=normalized_title,
        message=normalized_message,
        category=resolved_category,
        priority=resolved_priority,
        entity_type=normalized_entity_type,
        entity_id=entity_id,
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

    Returns None when the notification does not exist or belongs
    to another user.
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


# ============================================================================
# DELETE — ONE NOTIFICATION
# ============================================================================


def delete_notification(
    db: Session,
    *,
    notification: Notification,
    user_id: int,
) -> None:
    """
    Permanently delete one notification.

    The notification must belong to the authenticated user.

    Raises PermissionError when another user's notification is supplied.
    """

    if user_id <= 0:
        raise PermissionError(
            "You are not authorized to delete this notification."
        )

    if notification.user_id != user_id:
        raise PermissionError(
            "You are not authorized to delete this notification."
        )

    repository_delete_notification(
        db,
        notification,
    )


# ============================================================================
# DELETE — SELECTED NOTIFICATIONS
# ============================================================================


def delete_selected_notifications(
    db: Session,
    *,
    user_id: int,
    notification_ids: list[int],
) -> int:
    """
    Permanently delete selected notifications belonging to the
    authenticated user.

    Notification IDs belonging to other users are ignored.

    Nonexistent notification IDs are ignored.

    Returns the number of notifications actually deleted.
    """

    if user_id <= 0:
        return 0

    if not notification_ids:
        return 0

    normalized_ids = sorted(
        {
            notification_id
            for notification_id in notification_ids
            if notification_id > 0
        }
    )

    if not normalized_ids:
        return 0

    return repository_delete_selected_notifications(
        db,
        user_id=user_id,
        notification_ids=normalized_ids,
    )


# ============================================================================
# DELETE — ALL NOTIFICATIONS
# ============================================================================


def delete_all_notifications(
    db: Session,
    *,
    user_id: int,
) -> int:
    """
    Permanently delete all notifications belonging to the authenticated user.

    Returns the number of notifications deleted.
    """

    if user_id <= 0:
        return 0

    return repository_delete_all_notifications_by_user(
        db,
        user_id=user_id,
    )
