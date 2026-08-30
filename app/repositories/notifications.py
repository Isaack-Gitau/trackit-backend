
"""
TRACKIT Notification Repository.

Database access layer for persistent in-app notifications.

Architecture:

    Router
       ↓
    Service / Business Rules
       ↓
    Notification Repository
       ↓
    SQLAlchemy Notification Model

Responsibilities:

- Create notifications.
- Retrieve a notification by ID.
- Retrieve all notifications for a user.
- Retrieve unread notifications for a user.
- Count unread notifications for a user.
- Mark individual notifications as read.
- Mark all notifications for a user as read.
- Delete individual notifications.
- Delete selected notifications for a user.
- Delete all notifications for a user.

This repository intentionally does NOT perform:

- Authentication.
- Authorization.
- Ownership decisions outside database filtering required
  to safely scope user operations.
- Notification business-rule validation.
- Notification type validation.
- Notification content validation.

Those responsibilities belong to the service and API layers.
"""

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.models.notification import Notification


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
    Create and persist a notification.

    The notification is created as unread.

    Validation and authorization are handled by the service layer.
    """

    notification = Notification(
        user_id=user_id,
        type=notification_type,
        title=title,
        message=message,
        is_read=False,
    )

    db.add(notification)
    db.flush()

    return notification


# ============================================================================
# READ — SINGLE NOTIFICATION
# ============================================================================


def get_notification_by_id(
    db: Session,
    notification_id: int,
) -> Notification | None:
    """
    Retrieve a notification by its primary key.

    This function does not perform ownership or authorization checks.
    Callers that expose the result to users must enforce ownership
    through the service layer.
    """

    statement = select(Notification).where(
        Notification.id == notification_id,
    )

    return db.scalar(statement)


# ============================================================================
# READ — USER NOTIFICATIONS
# ============================================================================


def get_notifications_by_user(
    db: Session,
    *,
    user_id: int,
) -> list[Notification]:
    """
    Retrieve all notifications belonging to a user.

    Results are ordered newest first.

    The notification ID is used as a secondary ordering field to provide
    deterministic ordering when notifications share the same timestamp.
    """

    statement = (
        select(Notification)
        .where(
            Notification.user_id == user_id,
        )
        .order_by(
            Notification.created_at.desc(),
            Notification.id.desc(),
        )
    )

    return list(db.scalars(statement).all())


# ============================================================================
# READ — UNREAD NOTIFICATIONS
# ============================================================================


def get_unread_notifications_by_user(
    db: Session,
    *,
    user_id: int,
) -> list[Notification]:
    """
    Retrieve all unread notifications belonging to a user.

    Results are ordered newest first.
    """

    statement = (
        select(Notification)
        .where(
            Notification.user_id == user_id,
            Notification.is_read.is_(False),
        )
        .order_by(
            Notification.created_at.desc(),
            Notification.id.desc(),
        )
    )

    return list(db.scalars(statement).all())


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

    Returns zero when the user has no unread notifications.
    """

    statement = (
        select(func.count(Notification.id))
        .where(
            Notification.user_id == user_id,
            Notification.is_read.is_(False),
        )
    )

    return int(db.scalar(statement) or 0)


# ============================================================================
# UPDATE — MARK ONE AS READ
# ============================================================================


def mark_notification_as_read(
    db: Session,
    notification: Notification,
) -> Notification:
    """
    Mark a notification as read.

    Ownership and authorization must already have been verified
    by the service layer.
    """

    notification.is_read = True

    db.flush()

    return notification


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

    The user_id condition is intentionally part of the SQL UPDATE
    statement so that notifications belonging to other users cannot
    be modified by this operation.
    """

    statement = (
        update(Notification)
        .where(
            Notification.user_id == user_id,
            Notification.is_read.is_(False),
        )
        .values(
            is_read=True,
        )
    )

    result = db.execute(statement)

    db.flush()

    return int(result.rowcount or 0)


# ============================================================================
# DELETE — ONE NOTIFICATION
# ============================================================================


def delete_notification(
    db: Session,
    notification: Notification,
) -> None:
    """
    Permanently delete one notification.

    Ownership and authorization must already have been verified
    by the service layer.
    """

    db.delete(notification)
    db.flush()


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
    Permanently delete selected notifications belonging to a user.

    The user_id condition is included directly in the SQL DELETE
    statement to prevent notifications belonging to another user
    from being deleted.

    Nonexistent notification IDs are ignored.

    Returns the number of notifications actually deleted.
    """

    if not notification_ids:
        return 0

    statement = delete(Notification).where(
        Notification.user_id == user_id,
        Notification.id.in_(notification_ids),
    )

    result = db.execute(statement)

    db.flush()

    return int(result.rowcount or 0)


# ============================================================================
# DELETE — ALL USER NOTIFICATIONS
# ============================================================================


def delete_all_notifications_by_user(
    db: Session,
    *,
    user_id: int,
) -> int:
    """
    Permanently delete all notifications belonging to a user.

    Returns the number of notifications deleted.

    The user_id condition is deliberately included in the SQL DELETE
    statement so that notifications belonging to other users cannot
    be affected.
    """

    statement = delete(Notification).where(
        Notification.user_id == user_id,
    )

    result = db.execute(statement)

    db.flush()

    return int(result.rowcount or 0)

