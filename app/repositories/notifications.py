"""
TRACKIT Notification Repository.

Database access layer for persistent in-app notifications.

Business rules and authorization decisions belong in the service layer.
This module is responsible only for querying and persisting Notification
records.

Security principles:

- Queries are always scoped by the relevant user when user ownership
  matters.
- Notification content is never interpreted as trusted authorization data.
- The repository does not decide whether a notification should exist.
- The repository does not send notifications or perform external actions.
"""

from datetime import datetime, timezone

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
    category: str = "system",
    priority: str = "normal",
    entity_type: str | None = None,
    entity_id: int | None = None,
) -> Notification:
    """
    Create and persist a notification.

    The service layer is responsible for validating the supplied values.
    """

    notification = Notification(
        user_id=user_id,
        type=notification_type,
        category=category,
        priority=priority,
        entity_type=entity_type,
        entity_id=entity_id,
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
    Retrieve one notification by ID.
    """

    return db.scalar(
        select(Notification).where(
            Notification.id == notification_id,
        )
    )


# ============================================================================
# READ — MATCHING ENTITY NOTIFICATION
# ============================================================================


def get_notification_by_user_and_entity(
    db: Session,
    *,
    user_id: int,
    notification_type: str,
    entity_type: str,
    entity_id: int,
) -> Notification | None:
    """
    Retrieve an existing notification for a specific user and entity.

    This is primarily used to prevent duplicate event notifications.

    Example:

        user_id=12
        notification_type="match_found"
        entity_type="match"
        entity_id=45

    will locate an existing notification representing the notification
    that Match #45 was found for user #12.

    Ownership is enforced by user_id in the query.
    """

    statement = (
        select(Notification)
        .where(
            Notification.user_id == user_id,
            Notification.type == notification_type,
            Notification.entity_type == entity_type,
            Notification.entity_id == entity_id,
        )
        .order_by(
            Notification.created_at.desc(),
            Notification.id.desc(),
        )
        .limit(1)
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

    Results are returned newest first.
    """

    statement = (
        select(Notification)
        .where(Notification.user_id == user_id)
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
    Retrieve unread notifications belonging to a user.

    Results are returned newest first.
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
    """

    statement = select(
        func.count(Notification.id)
    ).where(
        Notification.user_id == user_id,
        Notification.is_read.is_(False),
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
    Mark one notification as read.

    The caller/service is responsible for ownership authorization.

    Marking an already-read notification is intentionally idempotent.
    """

    if not notification.is_read:
        notification.is_read = True
        notification.read_at = datetime.now(timezone.utc)
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
    """

    read_at = datetime.now(timezone.utc)

    statement = (
        update(Notification)
        .where(
            Notification.user_id == user_id,
            Notification.is_read.is_(False),
        )
        .values(
            is_read=True,
            read_at=read_at,
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
    Delete one notification.

    The caller/service is responsible for ownership authorization.
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
    Delete selected notifications belonging to a specific user.

    Notifications belonging to other users are never deleted.

    Returns the number of notifications deleted.
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
    Delete all notifications belonging to a specific user.

    Returns the number of notifications deleted.
    """

    statement = delete(Notification).where(
        Notification.user_id == user_id,
    )

    result = db.execute(statement)
    db.flush()

    return int(result.rowcount or 0)