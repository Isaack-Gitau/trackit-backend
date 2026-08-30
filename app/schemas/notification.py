"""
TRACKIT Notification Schemas.

Pydantic schemas used by the notification API.

Security principles:

- user_id is never accepted from the client.
- Notification ownership comes from the authenticated user.
- Notification read state is controlled by API actions.
- Notification responses expose only application-safe fields.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


# ============================================================================
# NOTIFICATION RESPONSE
# ============================================================================


class NotificationResponse(BaseModel):
    """
    API representation of a notification.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    user_id: int
    type: str
    title: str
    message: str
    is_read: bool
    created_at: datetime


# ============================================================================
# UNREAD COUNT RESPONSE
# ============================================================================


class NotificationUnreadCountResponse(BaseModel):
    """
    Response containing the authenticated user's unread notification count.
    """

    unread_count: int


# ============================================================================
# MARK AS READ RESPONSE
# ============================================================================


class NotificationReadResponse(BaseModel):
    """
    Response returned after marking a notification as read.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    user_id: int
    is_read: bool


# ============================================================================
# DELETE SELECTED NOTIFICATIONS REQUEST
# ============================================================================


class NotificationDeleteSelectedRequest(BaseModel):
    """
    Request containing notification IDs selected by the authenticated user
    for deletion.

    The user_id is deliberately not accepted from the client.
    Ownership is determined by the authenticated user in the service layer.
    """

    notification_ids: list[int]