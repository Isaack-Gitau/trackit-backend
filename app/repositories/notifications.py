
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

Responsibilities of this repository:

- Create notifications.
- Retrieve notifications.
- List notifications for a user.
- Retrieve unread notifications.
- Count unread notifications.
- Mark individual notifications as read.
- Mark all notifications for a user as read.

Business rules and authorization do NOT belong here.

In particular, this repository does not decide:

- whether a user is allowed to receive a notification;
- whether a user is allowed to view a notification;
- whether a notification should be created;
- whether a notification type is valid;
- whether a notification may be deleted.

Those decisions belong in the service layer.
"""

from sqlalchemy import func, select, update
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

    The repository does not perform authorization or business-rule
    validation. Those responsibilities belong to the service layer.

    The notification starts unread.
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

    Ownership and authorization must be checked by the service
    layer before exposing the notification to a user.
    """

    return db.scalar(
        select(Notification).where(
            Notification.id == notification_id
        )
    )


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
        .where(
            Notification.user_id == user_id
        )
        .order_by(
            Notification.created_at.desc(),
            Notification.id.desc(),
        )
    )

    return list(
        db.scalars(statement).all()
    )


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

    return list(
        db.scalars(statement).all()
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

    Returns zero when the user has no unread notifications.
    """

    statement = (
        select(func.count(Notification.id))
        .where(
            Notification.user_id == user_id,
            Notification.is_read.is_(False),
        )
    )

    return int(
        db.scalar(statement) or 0
    )


# ============================================================================
# UPDATE — MARK ONE AS READ
# ============================================================================


def mark_notification_as_read(
    db: Session,
    notification: Notification,
) -> Notification:
    """
    Mark a notification as read.

    Authorization and ownership validation must be performed
    by the service layer before this function is called.
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

    The user_id restriction is deliberately included in the database
    update so this operation cannot accidentally mark notifications
    belonging to another user as read.
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

    return int(
        result.rowcount or 0
    )

