"""
TRACKIT Notification API Router.

Provides endpoints for:

- viewing the authenticated user's notifications
- viewing unread notifications
- counting unread notifications
- viewing one owned notification
- marking one owned notification as read
- marking all owned notifications as read
- deleting one owned notification
- deleting selected owned notifications
- deleting all owned notifications

Security principles:

- Every endpoint requires an authenticated, verified user.
- user_id always comes from the authenticated user.
- A client can never select another user's notification through
  a request parameter.
- Notification ownership is additionally enforced by the service layer.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_verified_user
from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.notification import (
    NotificationDeleteSelectedRequest,
    NotificationReadResponse,
    NotificationResponse,
    NotificationUnreadCountResponse,
)
from app.services.notification import (
    count_unread_notifications,
    delete_all_notifications,
    delete_notification,
    delete_selected_notifications,
    get_notification,
    list_unread_notifications,
    list_user_notifications,
    mark_all_notifications_as_read,
    mark_notification_as_read,
)


# ============================================================================
# ROUTER
# ============================================================================


router = APIRouter(
    prefix="/notifications",
    tags=["Notifications"],
)


# ============================================================================
# MY NOTIFICATIONS
# ============================================================================


@router.get(
    "",
    response_model=list[NotificationResponse],
    summary="List the authenticated user's notifications",
)
def list_my_notifications_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Return all notifications belonging to the authenticated user.

    Notifications are returned newest first by the repository.
    """

    return list_user_notifications(
        db,
        user_id=current_user.id,
    )


# ============================================================================
# UNREAD NOTIFICATIONS
# ============================================================================


@router.get(
    "/unread",
    response_model=list[NotificationResponse],
    summary="List unread notifications",
)
def list_unread_notifications_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Return unread notifications belonging to the authenticated user.
    """

    return list_unread_notifications(
        db,
        user_id=current_user.id,
    )


# ============================================================================
# UNREAD COUNT
# ============================================================================


@router.get(
    "/unread/count",
    response_model=NotificationUnreadCountResponse,
    summary="Count unread notifications",
)
def count_unread_notifications_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Return the number of unread notifications belonging to the
    authenticated user.
    """

    return NotificationUnreadCountResponse(
        unread_count=count_unread_notifications(
            db,
            user_id=current_user.id,
        ),
    )


# ============================================================================
# GET ONE NOTIFICATION
# ============================================================================


@router.get(
    "/{notification_id}",
    response_model=NotificationResponse,
    summary="Get a notification",
)
def get_notification_endpoint(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Retrieve one notification.

    The notification must belong to the authenticated user.

    Another user's notification is intentionally returned as
    not found so the API does not expose notification ownership
    information.
    """

    notification = get_notification(
        db,
        notification_id=notification_id,
        user_id=current_user.id,
    )

    if notification is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found.",
        )

    return notification


# ============================================================================
# DELETE SELECTED NOTIFICATIONS
# ============================================================================


@router.delete(
    "/selected",
    response_model=dict[str, int],
    summary="Delete selected notifications",
)
def delete_selected_notifications_endpoint(
    request: NotificationDeleteSelectedRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Permanently delete selected notifications belonging to the
    authenticated user.

    Notification IDs belonging to another user are ignored.

    Nonexistent notification IDs are ignored.

    Returns the number of notifications actually deleted.
    """

    deleted_count = delete_selected_notifications(
        db,
        user_id=current_user.id,
        notification_ids=request.notification_ids,
    )

    return {
        "deleted_count": deleted_count,
    }


# ============================================================================
# DELETE ONE NOTIFICATION
# ============================================================================


@router.delete(
    "/{notification_id}",
    response_model=dict[str, int],
    summary="Delete a notification",
)
def delete_notification_endpoint(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Permanently delete one notification belonging to the authenticated user.

    Another user's notification is intentionally returned as not found.
    """

    notification = get_notification(
        db,
        notification_id=notification_id,
        user_id=current_user.id,
    )

    if notification is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found.",
        )

    try:
        delete_notification(
            db,
            notification=notification,
            user_id=current_user.id,
        )

    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    return {
        "deleted_count": 1,
    }


# ============================================================================
# MARK ONE AS READ
# ============================================================================


@router.patch(
    "/{notification_id}/read",
    response_model=NotificationReadResponse,
    summary="Mark a notification as read",
)
def mark_notification_as_read_endpoint(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Mark one notification belonging to the authenticated user as read.
    """

    notification = get_notification(
        db,
        notification_id=notification_id,
        user_id=current_user.id,
    )

    if notification is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found.",
        )

    try:
        result = mark_notification_as_read(
            db,
            notification=notification,
            user_id=current_user.id,
        )

    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    return result


# ============================================================================
# MARK ALL AS READ
# ============================================================================


@router.patch(
    "/read-all",
    response_model=dict[str, int],
    summary="Mark all notifications as read",
)
def mark_all_notifications_as_read_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Mark all unread notifications belonging to the authenticated user
    as read.

    Returns the number of notifications changed.
    """

    updated_count = mark_all_notifications_as_read(
        db,
        user_id=current_user.id,
    )

    return {
        "updated_count": updated_count,
    }


# ============================================================================
# DELETE ALL NOTIFICATIONS
# ============================================================================


@router.delete(
    "",
    response_model=dict[str, int],
    summary="Delete all notifications",
)
def delete_all_notifications_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Permanently delete all notifications belonging to the authenticated user.

    Notifications belonging to other users are never affected.

    Returns the number of notifications deleted.
    """

    deleted_count = delete_all_notifications(
        db,
        user_id=current_user.id,
    )

    return {
        "deleted_count": deleted_count,
    }