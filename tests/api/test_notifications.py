"""
TRACKIT Notification API Integration Tests.

Tests the HTTP/API layer for:
- authentication
- verified-user authorization
- listing notifications
- listing unread notifications
- unread notification counts
- notification ownership
- marking one notification as read
- marking all notifications as read
- deleting one notification
- deleting selected notifications
- deleting all notifications
"""

from app.core.security import create_access_token
from app.models.notification import Notification
from app.models.user import User


# ============================================================================
# HELPERS
# ============================================================================


def create_user(
    db,
    *,
    user_id: int,
    username: str,
    role: str = "user",
    is_verified: bool = True,
    is_active: bool = True,
    token_version: int = 0,
):
    user = User(
        id=user_id,
        username=username,
        first_name="Test",
        last_name="User",
        email=f"{username}@trackit.test",
        password_hash="test-password-hash",
        role=role,
        is_active=is_active,
        is_verified=is_verified,
        token_version=token_version,
    )

    db.add(user)
    db.flush()

    return user


def create_notification(
    db,
    *,
    user_id: int,
    notification_type: str = "claim_created",
    title: str = "New Claim",
    message: str = "Someone submitted a claim for your item.",
    is_read: bool = False,
):
    notification = Notification(
        user_id=user_id,
        type=notification_type,
        title=title,
        message=message,
        is_read=is_read,
    )

    db.add(notification)
    db.flush()

    return notification


def auth_headers(user):
    """
    Generate a real TRACKIT access token using the
    same JWT structure as the production login flow.
    """

    token = create_access_token(
        data={
            "sub": str(user.id),
            "role": user.role,
            "token_version": user.token_version,
        }
    )

    return {
        "Authorization": f"Bearer {token}",
    }


# ============================================================================
# AUTHENTICATION
# ============================================================================


def test_unauthenticated_user_cannot_list_notifications(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2001,
        username="notification_auth_user",
    )

    create_notification(
        db,
        user_id=user.id,
    )

    response = client.get(
        "/api/notifications",
    )

    assert response.status_code == 401


def test_unverified_user_cannot_list_notifications(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2002,
        username="notification_unverified",
        is_verified=False,
    )

    response = client.get(
        "/api/notifications",
        headers=auth_headers(user),
    )

    assert response.status_code == 403


# ============================================================================
# LIST NOTIFICATIONS
# ============================================================================


def test_verified_user_can_list_own_notifications(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2003,
        username="notification_list_user",
    )

    first = create_notification(
        db,
        user_id=user.id,
        title="First Notification",
        message="First notification message.",
    )

    second = create_notification(
        db,
        user_id=user.id,
        title="Second Notification",
        message="Second notification message.",
    )

    response = client.get(
        "/api/notifications",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 2

    returned_ids = {
        notification["id"]
        for notification in data
    }

    assert returned_ids == {
        first.id,
        second.id,
    }


def test_user_cannot_see_another_users_notifications(
    client,
    db,
):
    user_one = create_user(
        db,
        user_id=2004,
        username="notification_owner_one",
    )

    user_two = create_user(
        db,
        user_id=2005,
        username="notification_owner_two",
    )

    own_notification = create_notification(
        db,
        user_id=user_one.id,
        title="Own Notification",
        message="This belongs to user one.",
    )

    other_notification = create_notification(
        db,
        user_id=user_two.id,
        title="Other Notification",
        message="This belongs to user two.",
    )

    response = client.get(
        "/api/notifications",
        headers=auth_headers(user_one),
    )

    assert response.status_code == 200

    data = response.json()

    returned_ids = {
        notification["id"]
        for notification in data
    }

    assert own_notification.id in returned_ids
    assert other_notification.id not in returned_ids


# ============================================================================
# UNREAD NOTIFICATIONS
# ============================================================================


def test_user_can_list_only_unread_notifications(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2006,
        username="notification_unread_user",
    )

    unread_one = create_notification(
        db,
        user_id=user.id,
        title="Unread One",
        message="Unread notification one.",
        is_read=False,
    )

    unread_two = create_notification(
        db,
        user_id=user.id,
        title="Unread Two",
        message="Unread notification two.",
        is_read=False,
    )

    read_notification = create_notification(
        db,
        user_id=user.id,
        title="Already Read",
        message="This notification has already been read.",
        is_read=True,
    )

    response = client.get(
        "/api/notifications/unread",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    returned_ids = {
        notification["id"]
        for notification in data
    }

    assert unread_one.id in returned_ids
    assert unread_two.id in returned_ids
    assert read_notification.id not in returned_ids


def test_unread_notifications_are_user_specific(
    client,
    db,
):
    user_one = create_user(
        db,
        user_id=2007,
        username="notification_unread_one",
    )

    user_two = create_user(
        db,
        user_id=2008,
        username="notification_unread_two",
    )

    own_notification = create_notification(
        db,
        user_id=user_one.id,
        is_read=False,
    )

    other_notification = create_notification(
        db,
        user_id=user_two.id,
        is_read=False,
    )

    response = client.get(
        "/api/notifications/unread",
        headers=auth_headers(user_one),
    )

    assert response.status_code == 200

    data = response.json()

    returned_ids = {
        notification["id"]
        for notification in data
    }

    assert own_notification.id in returned_ids
    assert other_notification.id not in returned_ids


# ============================================================================
# UNREAD COUNT
# ============================================================================


def test_user_can_get_unread_notification_count(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2009,
        username="notification_count_user",
    )

    create_notification(
        db,
        user_id=user.id,
        is_read=False,
    )

    create_notification(
        db,
        user_id=user.id,
        is_read=False,
    )

    create_notification(
        db,
        user_id=user.id,
        is_read=True,
    )

    response = client.get(
        "/api/notifications/unread/count",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    assert response.json() == {
        "unread_count": 2,
    }


def test_unread_count_is_user_specific(
    client,
    db,
):
    user_one = create_user(
        db,
        user_id=2010,
        username="notification_count_one",
    )

    user_two = create_user(
        db,
        user_id=2011,
        username="notification_count_two",
    )

    create_notification(
        db,
        user_id=user_one.id,
        is_read=False,
    )

    create_notification(
        db,
        user_id=user_two.id,
        is_read=False,
    )

    create_notification(
        db,
        user_id=user_two.id,
        is_read=False,
    )

    response = client.get(
        "/api/notifications/unread/count",
        headers=auth_headers(user_one),
    )

    assert response.status_code == 200

    assert response.json() == {
        "unread_count": 1,
    }


# ============================================================================
# GET ONE NOTIFICATION
# ============================================================================


def test_user_can_get_own_notification(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2012,
        username="notification_get_user",
    )

    notification = create_notification(
        db,
        user_id=user.id,
        title="My Notification",
        message="This is my notification.",
    )

    response = client.get(
        f"/api/notifications/{notification.id}",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == notification.id
    assert data["user_id"] == user.id
    assert data["title"] == "My Notification"
    assert data["message"] == "This is my notification."


def test_user_cannot_get_another_users_notification(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2013,
        username="notification_private_owner",
    )

    attacker = create_user(
        db,
        user_id=2014,
        username="notification_private_attacker",
    )

    notification = create_notification(
        db,
        user_id=owner.id,
    )

    response = client.get(
        f"/api/notifications/{notification.id}",
        headers=auth_headers(attacker),
    )

    assert response.status_code == 404


def test_get_nonexistent_notification_returns_404(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2015,
        username="notification_missing_user",
    )

    response = client.get(
        "/api/notifications/999999",
        headers=auth_headers(user),
    )

    assert response.status_code == 404


# ============================================================================
# MARK ONE AS READ
# ============================================================================


def test_user_can_mark_own_notification_as_read(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2016,
        username="notification_read_user",
    )

    notification = create_notification(
        db,
        user_id=user.id,
        is_read=False,
    )

    response = client.patch(
        f"/api/notifications/{notification.id}/read",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == notification.id
    assert data["user_id"] == user.id
    assert data["is_read"] is True

    db.refresh(notification)

    assert notification.is_read is True


def test_user_cannot_mark_another_users_notification_as_read(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2017,
        username="notification_read_owner",
    )

    attacker = create_user(
        db,
        user_id=2018,
        username="notification_read_attacker",
    )

    notification = create_notification(
        db,
        user_id=owner.id,
        is_read=False,
    )

    response = client.patch(
        f"/api/notifications/{notification.id}/read",
        headers=auth_headers(attacker),
    )

    assert response.status_code == 404

    db.refresh(notification)

    assert notification.is_read is False


def test_marking_already_read_notification_is_idempotent(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2019,
        username="notification_idempotent_user",
    )

    notification = create_notification(
        db,
        user_id=user.id,
        is_read=True,
    )

    response = client.patch(
        f"/api/notifications/{notification.id}/read",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == notification.id
    assert data["is_read"] is True


# ============================================================================
# MARK ALL AS READ
# ============================================================================


def test_user_can_mark_all_own_notifications_as_read(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2020,
        username="notification_read_all_user",
    )

    first = create_notification(
        db,
        user_id=user.id,
        is_read=False,
    )

    second = create_notification(
        db,
        user_id=user.id,
        is_read=False,
    )

    already_read = create_notification(
        db,
        user_id=user.id,
        is_read=True,
    )

    response = client.patch(
        "/api/notifications/read-all",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["updated_count"] == 2

    db.refresh(first)
    db.refresh(second)
    db.refresh(already_read)

    assert first.is_read is True
    assert second.is_read is True
    assert already_read.is_read is True


def test_mark_all_read_only_changes_authenticated_users_notifications(
    client,
    db,
):
    user_one = create_user(
        db,
        user_id=2021,
        username="notification_all_one",
    )

    user_two = create_user(
        db,
        user_id=2022,
        username="notification_all_two",
    )

    own_one = create_notification(
        db,
        user_id=user_one.id,
        is_read=False,
    )

    own_two = create_notification(
        db,
        user_id=user_one.id,
        is_read=False,
    )

    other_one = create_notification(
        db,
        user_id=user_two.id,
        is_read=False,
    )

    response = client.patch(
        "/api/notifications/read-all",
        headers=auth_headers(user_one),
    )

    assert response.status_code == 200
    assert response.json()["updated_count"] == 2

    db.refresh(own_one)
    db.refresh(own_two)
    db.refresh(other_one)

    assert own_one.is_read is True
    assert own_two.is_read is True
    assert other_one.is_read is False


def test_mark_all_read_returns_zero_when_nothing_is_unread(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2023,
        username="notification_all_none",
    )

    create_notification(
        db,
        user_id=user.id,
        is_read=True,
    )

    response = client.patch(
        "/api/notifications/read-all",
        headers=auth_headers(user),
    )

    assert response.status_code == 200
    assert response.json()["updated_count"] == 0


# ============================================================================
# ROUTE / RESPONSE CONTRACT
# ============================================================================


def test_notification_response_contains_expected_fields(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2024,
        username="notification_contract_user",
    )

    notification = create_notification(
        db,
        user_id=user.id,
        notification_type="claim_approved",
        title="Claim Approved",
        message="Your claim has been approved.",
        is_read=False,
    )

    response = client.get(
        f"/api/notifications/{notification.id}",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert set(data.keys()) == {
        "id",
        "user_id",
        "type",
        "title",
        "message",
        "is_read",
        "created_at",
    }

    assert data["type"] == "claim_approved"
    assert data["title"] == "Claim Approved"
    assert data["message"] == "Your claim has been approved."
    assert data["is_read"] is False
    assert data["created_at"] is not None


# ============================================================================
# DELETE ONE NOTIFICATION
# ============================================================================


def test_user_can_delete_own_notification(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2025,
        username="notification_delete_user",
    )

    notification = create_notification(
        db,
        user_id=user.id,
    )

    response = client.delete(
        f"/api/notifications/{notification.id}",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    assert response.json() == {
        "deleted_count": 1,
    }

    assert db.get(
        Notification,
        notification.id,
    ) is None


def test_user_cannot_delete_another_users_notification(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2026,
        username="notification_delete_owner",
    )

    attacker = create_user(
        db,
        user_id=2027,
        username="notification_delete_attacker",
    )

    notification = create_notification(
        db,
        user_id=owner.id,
    )

    response = client.delete(
        f"/api/notifications/{notification.id}",
        headers=auth_headers(attacker),
    )

    assert response.status_code == 404

    assert db.get(
        Notification,
        notification.id,
    ) is not None


def test_delete_nonexistent_notification_returns_404(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2028,
        username="notification_delete_missing",
    )

    response = client.delete(
        "/api/notifications/999999",
        headers=auth_headers(user),
    )

    assert response.status_code == 404


# ============================================================================
# DELETE SELECTED NOTIFICATIONS
# ============================================================================


def test_user_can_delete_selected_own_notifications(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2029,
        username="notification_delete_selected_user",
    )

    first = create_notification(
        db,
        user_id=user.id,
        title="Notification One",
    )

    second = create_notification(
        db,
        user_id=user.id,
        title="Notification Two",
    )

    third = create_notification(
        db,
        user_id=user.id,
        title="Notification Three",
    )

    response = client.request(
        "DELETE",
        "/api/notifications/selected",
        json={
            "notification_ids": [
                first.id,
                third.id,
            ],
        },
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    assert response.json() == {
        "deleted_count": 2,
    }

    assert db.get(
        Notification,
        first.id,
    ) is None

    assert db.get(
        Notification,
        second.id,
    ) is not None

    assert db.get(
        Notification,
        third.id,
    ) is None


def test_selected_delete_only_deletes_authenticated_users_notifications(
    client,
    db,
):
    user_one = create_user(
        db,
        user_id=2030,
        username="notification_selected_one",
    )

    user_two = create_user(
        db,
        user_id=2031,
        username="notification_selected_two",
    )

    own_one = create_notification(
        db,
        user_id=user_one.id,
    )

    own_two = create_notification(
        db,
        user_id=user_one.id,
    )

    other_one = create_notification(
        db,
        user_id=user_two.id,
    )

    response = client.request(
        "DELETE",
        "/api/notifications/selected",
        json={
            "notification_ids": [
                own_one.id,
                other_one.id,
            ],
        },
        headers=auth_headers(user_one),
    )

    assert response.status_code == 200

    assert response.json() == {
        "deleted_count": 1,
    }

    assert db.get(
        Notification,
        own_one.id,
    ) is None

    assert db.get(
        Notification,
        own_two.id,
    ) is not None

    assert db.get(
        Notification,
        other_one.id,
    ) is not None


def test_selected_delete_with_nonexistent_notification_ids(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2032,
        username="notification_selected_missing",
    )

    notification = create_notification(
        db,
        user_id=user.id,
    )

    response = client.request(
        "DELETE",
        "/api/notifications/selected",
        json={
            "notification_ids": [
                notification.id,
                999999,
            ],
        },
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    assert response.json() == {
        "deleted_count": 1,
    }

    assert db.get(
        Notification,
        notification.id,
    ) is None


def test_selected_delete_empty_list_returns_zero(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2033,
        username="notification_selected_empty",
    )

    notification = create_notification(
        db,
        user_id=user.id,
    )

    response = client.request(
        "DELETE",
        "/api/notifications/selected",
        json={
            "notification_ids": [],
        },
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    assert response.json() == {
        "deleted_count": 0,
    }

    assert db.get(
        Notification,
        notification.id,
    ) is not None


# ============================================================================
# DELETE ALL NOTIFICATIONS
# ============================================================================


def test_user_can_delete_all_own_notifications(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2034,
        username="notification_delete_all_user",
    )

    first = create_notification(
        db,
        user_id=user.id,
        title="Notification One",
    )

    second = create_notification(
        db,
        user_id=user.id,
        title="Notification Two",
    )

    response = client.delete(
        "/api/notifications",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["deleted_count"] == 2

    assert db.get(
        Notification,
        first.id,
    ) is None

    assert db.get(
        Notification,
        second.id,
    ) is None


def test_delete_all_only_deletes_authenticated_users_notifications(
    client,
    db,
):
    user_one = create_user(
        db,
        user_id=2035,
        username="notification_delete_all_one",
    )

    user_two = create_user(
        db,
        user_id=2036,
        username="notification_delete_all_two",
    )

    own_one = create_notification(
        db,
        user_id=user_one.id,
    )

    own_two = create_notification(
        db,
        user_id=user_one.id,
    )

    other = create_notification(
        db,
        user_id=user_two.id,
    )

    response = client.delete(
        "/api/notifications",
        headers=auth_headers(user_one),
    )

    assert response.status_code == 200

    assert response.json() == {
        "deleted_count": 2,
    }

    assert db.get(
        Notification,
        own_one.id,
    ) is None

    assert db.get(
        Notification,
        own_two.id,
    ) is None

    assert db.get(
        Notification,
        other.id,
    ) is not None


def test_delete_all_returns_zero_when_user_has_no_notifications(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2037,
        username="notification_delete_all_empty",
    )

    response = client.delete(
        "/api/notifications",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    assert response.json() == {
        "deleted_count": 0,
    }


def test_unauthenticated_user_cannot_delete_all_notifications(
    client,
    db,
):
    response = client.delete(
        "/api/notifications",
    )

    assert response.status_code == 401


def test_unverified_user_cannot_delete_all_notifications(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2038,
        username="notification_delete_unverified",
        is_verified=False,
    )

    response = client.delete(
        "/api/notifications",
        headers=auth_headers(user),
    )

    assert response.status_code == 403


def test_unauthenticated_user_cannot_delete_selected_notifications(
    client,
    db,
):
    response = client.request(
        "DELETE",
        "/api/notifications/selected",
        json={
            "notification_ids": [
                1,
                2,
            ],
        },
    )

    assert response.status_code == 401


def test_unverified_user_cannot_delete_selected_notifications(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2039,
        username="notification_selected_unverified",
        is_verified=False,
    )

    response = client.request(
        "DELETE",
        "/api/notifications/selected",
        json={
            "notification_ids": [
                1,
                2,
            ],
        },
        headers=auth_headers(user),
    )

    assert response.status_code == 403