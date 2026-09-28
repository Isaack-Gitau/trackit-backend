"""
TRACKIT Audit Log API Tests.

Tests the administrator-only audit-log listing endpoint.

Coverage:

- Administrator access.
- Moderator and normal-user authorization denial.
- Restricted response fields.
- Actor identity exposure.
- System-generated events without an actor.
- Action, success, user, resource-type, and resource-id filters.
- Pagination.
- Newest-first deterministic ordering.
- Invalid query-parameter handling.
"""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.user import User
from tests.api.test_profile import (
    authenticated_headers,
    create_admin,
    create_moderator,
    create_test_user,
)


# ============================================================================
# TEST HELPERS
# ============================================================================


def create_audit_log(
    db: Session,
    *,
    action: str,
    success: bool = True,
    details: str | None = None,
    user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: int | None = None,
    created_at: datetime | None = None,
    ip_address: str | None = "192.168.1.100",
    user_agent: str | None = "TRACKIT-TestClient",
) -> AuditLog:
    """
    Create and persist an audit-log entry for API tests.
    """

    audit_log = AuditLog(
        action=action,
        success=success,
        details=details,
        user_id=user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        created_at=created_at,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.add(audit_log)
    db.flush()

    return audit_log


# ============================================================================
# AUTHORIZATION
# ============================================================================


def test_admin_can_list_audit_logs(
    client: TestClient,
    db: Session,
):
    """
    Administrators can retrieve audit logs.
    """

    admin = create_admin(
        db,
        user_id=9101,
        username="auditadmin",
        email="auditadmin@example.com",
    )

    log = create_audit_log(
        db,
        action="test_event",
        details="Test audit event.",
        user_id=admin.id,
        resource_type="user",
        resource_id=42,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"action": "test_event"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["page"] == 1
    assert data["limit"] == 20
    assert data["total"] == 1
    assert data["pages"] == 1
    assert len(data["items"]) == 1

    item = data["items"][0]

    assert item["id"] == log.id
    assert item["action"] == "test_event"
    assert item["success"] is True
    assert item["details"] == "Test audit event."
    assert item["resource_type"] == "user"
    assert item["resource_id"] == 42
    assert item["user_id"] == admin.id
    assert item["actor"] == {
        "id": admin.id,
        "username": admin.username,
    }
    assert "ip_address" not in item
    assert "user_agent" not in item


def test_moderator_cannot_list_audit_logs(
    client: TestClient,
    db: Session,
):
    """
    Moderators must not have access to the administrator-only audit log.
    """

    moderator = create_moderator(
        db,
        user_id=9102,
        username="auditmoderator",
        email="auditmoderator@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        headers=authenticated_headers(moderator),
    )

    assert response.status_code == 403


def test_normal_user_cannot_list_audit_logs(
    client: TestClient,
    db: Session,
):
    """
    Normal users must not have access to the administrator-only audit log.
    """

    user = create_test_user(
        db,
        user_id=9103,
        username="audituser",
        email="audituser@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        headers=authenticated_headers(user),
    )

    assert response.status_code == 403


# ============================================================================
# ACTOR PRIVACY / SYSTEM EVENTS
# ============================================================================


def test_audit_log_actor_is_restricted_to_id_and_username(
    client: TestClient,
    db: Session,
):
    """
    The audit API exposes only the actor's moderation-safe identity.
    """

    admin = create_admin(
        db,
        user_id=9110,
        username="restrictedactor",
        email="restrictedactor@example.com",
    )

    create_audit_log(
        db,
        action="actor_test",
        user_id=admin.id,
        ip_address="10.10.10.10",
        user_agent="Secret-Test-Agent",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    item = response.json()["items"][0]

    assert item["actor"] == {
        "id": admin.id,
        "username": admin.username,
    }

    assert "email" not in item["actor"]
    assert "first_name" not in item["actor"]
    assert "last_name" not in item["actor"]
    assert "ip_address" not in item
    assert "user_agent" not in item


def test_system_audit_log_has_no_actor(
    client: TestClient,
    db: Session,
):
    """
    Automated events with no user_id are represented with actor=null.
    """

    admin = create_admin(
        db,
        user_id=9111,
        username="systemviewer",
        email="systemviewer@example.com",
    )

    create_audit_log(
        db,
        action="system_event",
        details="Automatic account reactivation.",
        user_id=None,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    item = response.json()["items"][0]

    assert item["user_id"] is None
    assert item["actor"] is None


# ============================================================================
# FILTERS
# ============================================================================


def test_audit_log_action_filter(
    client: TestClient,
    db: Session,
):
    """
    The action filter returns only matching event types.
    """

    admin = create_admin(
        db,
        user_id=9120,
        username="actionfilteradmin",
        email="actionfilteradmin@example.com",
    )

    create_audit_log(
        db,
        action="login_success",
        user_id=admin.id,
    )
    create_audit_log(
        db,
        action="login_failure",
        success=False,
        user_id=admin.id,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"action": "login_success"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["items"][0]["action"] == "login_success"


def test_audit_log_success_filter(
    client: TestClient,
    db: Session,
):
    """
    The success filter distinguishes successful and failed events.
    """

    admin = create_admin(
        db,
        user_id=9121,
        username="successfilteradmin",
        email="successfilteradmin@example.com",
    )

    create_audit_log(
        db,
        action="successful_event",
        success=True,
        user_id=admin.id,
    )
    create_audit_log(
        db,
        action="failed_event",
        success=False,
        user_id=admin.id,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"success": "false"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["items"][0]["action"] == "failed_event"
    assert data["items"][0]["success"] is False


def test_audit_log_user_id_filter(
    client: TestClient,
    db: Session,
):
    """
    The user_id filter restricts results to a specific actor.
    """

    admin = create_admin(
        db,
        user_id=9122,
        username="userfilteradmin",
        email="userfilteradmin@example.com",
    )

    other_user = create_test_user(
        db,
        user_id=9123,
        username="otheractor",
        email="otheractor@example.com",
    )

    create_audit_log(
        db,
        action="admin_event",
        user_id=admin.id,
    )
    create_audit_log(
        db,
        action="user_event",
        user_id=other_user.id,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"user_id": other_user.id},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["items"][0]["user_id"] == other_user.id
    assert data["items"][0]["action"] == "user_event"


def test_audit_log_resource_type_filter(
    client: TestClient,
    db: Session,
):
    """
    The resource_type filter restricts results by affected resource type.
    """

    admin = create_admin(
        db,
        user_id=9124,
        username="resourcefilteradmin",
        email="resourcefilteradmin@example.com",
    )

    create_audit_log(
        db,
        action="user_action",
        user_id=admin.id,
        resource_type="user",
        resource_id=100,
    )
    create_audit_log(
        db,
        action="item_action",
        user_id=admin.id,
        resource_type="item",
        resource_id=200,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"resource_type": "item"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["items"][0]["resource_type"] == "item"


def test_audit_log_resource_id_filter(
    client: TestClient,
    db: Session,
):
    """
    The resource_id filter restricts results to a specific resource.
    """

    admin = create_admin(
        db,
        user_id=9125,
        username="resourceidfilteradmin",
        email="resourceidfilteradmin@example.com",
    )

    create_audit_log(
        db,
        action="resource_one",
        user_id=admin.id,
        resource_type="item",
        resource_id=501,
    )
    create_audit_log(
        db,
        action="resource_two",
        user_id=admin.id,
        resource_type="item",
        resource_id=502,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"resource_id": 502},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["items"][0]["resource_id"] == 502
    assert data["items"][0]["action"] == "resource_two"


# ============================================================================
# PAGINATION / ORDERING
# ============================================================================


def test_audit_log_pagination_and_newest_first_order(
    client: TestClient,
    db: Session,
):
    """
    Audit logs are paginated and returned newest-first.

    IDs are deliberately assigned by insertion order while timestamps
    establish the primary ordering. The secondary ID ordering is also
    tested separately by giving two records the same timestamp.
    """

    admin = create_admin(
        db,
        user_id=9130,
        username="paginationadmin",
        email="paginationadmin@example.com",
    )

    base_time = datetime.now(timezone.utc)

    first = create_audit_log(
        db,
        action="pagination_test",
        user_id=admin.id,
        created_at=base_time - timedelta(minutes=3),
    )

    second = create_audit_log(
        db,
        action="pagination_test",
        user_id=admin.id,
        created_at=base_time - timedelta(minutes=2),
    )

    third = create_audit_log(
        db,
        action="pagination_test",
        user_id=admin.id,
        created_at=base_time - timedelta(minutes=1),
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={
            "action": "pagination_test",
            "page": 1,
            "limit": 2,
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["page"] == 1
    assert data["limit"] == 2
    assert data["total"] == 3
    assert data["pages"] == 2

    assert [item["id"] for item in data["items"]] == [
        third.id,
        second.id,
    ]

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={
            "action": "pagination_test",
            "page": 2,
            "limit": 2,
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert [item["id"] for item in data["items"]] == [
        first.id,
    ]


def test_audit_log_same_timestamp_uses_id_as_secondary_order(
    client: TestClient,
    db: Session,
):
    """
    Audit logs with identical timestamps are ordered by descending ID.
    """

    admin = create_admin(
        db,
        user_id=9131,
        username="sameorderadmin",
        email="sameorderadmin@example.com",
    )

    timestamp = datetime.now(timezone.utc)

    first = create_audit_log(
        db,
        action="same_timestamp_test",
        user_id=admin.id,
        created_at=timestamp,
    )

    second = create_audit_log(
        db,
        action="same_timestamp_test",
        user_id=admin.id,
        created_at=timestamp,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"action": "same_timestamp_test"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert [item["id"] for item in data["items"]] == [
        second.id,
        first.id,
    ]


# ============================================================================
# VALIDATION
# ============================================================================


def test_audit_log_invalid_page_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    Page values below one are rejected by the service layer.
    """

    admin = create_admin(
        db,
        user_id=9140,
        username="invalidpageadmin",
        email="invalidpageadmin@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"page": 0},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400


def test_audit_log_invalid_limit_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    Limit values outside the supported range are rejected.
    """

    admin = create_admin(
        db,
        user_id=9141,
        username="invalidlimitadmin",
        email="invalidlimitadmin@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"limit": 101},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400


def test_audit_log_invalid_user_id_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    User IDs must be positive whole numbers.
    """

    admin = create_admin(
        db,
        user_id=9142,
        username="invaliduseridadmin",
        email="invaliduseridadmin@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"user_id": 0},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400


def test_audit_log_invalid_resource_id_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    Resource IDs must be positive whole numbers.
    """

    admin = create_admin(
        db,
        user_id=9143,
        username="invalidresourceadmin",
        email="invalidresourceadmin@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"resource_id": 0},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400


def test_audit_log_overlong_action_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    Action filters longer than the database-supported length are rejected.
    """

    admin = create_admin(
        db,
        user_id=9144,
        username="overlongactionadmin",
        email="overlongactionadmin@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"action": "x" * 101},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400


def test_audit_log_overlong_resource_type_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    Resource-type filters longer than the supported length are rejected.
    """

    admin = create_admin(
        db,
        user_id=9145,
        username="overlongresourceadmin",
        email="overlongresourceadmin@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"resource_type": "x" * 101},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400
