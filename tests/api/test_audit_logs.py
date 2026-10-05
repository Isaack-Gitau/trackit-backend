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
- Administrator audit-log preview.
- Preview filter normalization and metadata safety.
- Administrator CSV audit-log export.
- Administrator JSON audit-log export.
- Export filtering and sensitive-field exclusion.
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
    subject_user_id: int | None = None,
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
        subject_user_id=subject_user_id,
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
    assert item["category"] == "other"
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


def test_audit_log_known_action_exposes_derived_category(
    client: TestClient,
    db: Session,
):
    """
    Known audit actions expose their application-level category.
    """

    admin = create_admin(
        db,
        user_id=9104,
        username="auditcategoryadmin",
        email="auditcategoryadmin@example.com",
    )

    log = create_audit_log(
        db,
        action="login_success",
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
    assert data["items"][0]["id"] == log.id
    assert data["items"][0]["action"] == "login_success"
    assert data["items"][0]["category"] == "authentication"


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


def test_audit_log_other_category_filter(
    client: TestClient,
    db: Session,
):
    """
    The 'other' category returns only actions outside the known category map.
    """

    admin = create_admin(
        db,
        user_id=9128,
        username="othercategoryadmin",
        email="othercategoryadmin@example.com",
    )

    create_audit_log(
        db,
        action="login_success",
        user_id=admin.id,
    )
    create_audit_log(
        db,
        action="custom_future_event",
        user_id=admin.id,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"category": "other"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["items"][0]["action"] == "custom_future_event"
    assert data["items"][0]["category"] == "other"


def test_audit_log_invalid_category_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    Unknown audit categories must be rejected rather than silently ignored.
    """

    admin = create_admin(
        db,
        user_id=9129,
        username="invalidcategoryadmin",
        email="invalidcategoryadmin@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"category": "not_a_real_category"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400


def test_audit_log_category_filter(
    client: TestClient,
    db: Session,
):
    """
    The category filter returns only audit events in the requested category.
    """

    admin = create_admin(
        db,
        user_id=9127,
        username="categoryfilteradmin",
        email="categoryfilteradmin@example.com",
    )

    create_audit_log(
        db,
        action="login_success",
        user_id=admin.id,
    )
    create_audit_log(
        db,
        action="item_created",
        user_id=admin.id,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"category": "authentication"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["items"][0]["action"] == "login_success"
    assert data["items"][0]["category"] == "authentication"


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
# DATE RANGE FILTERING
# ============================================================================


def test_audit_log_created_from_filter(
    client: TestClient,
    db: Session,
):
    """
    created_from includes logs created at or after the supplied timestamp.
    """

    admin = create_admin(
        db,
        user_id=9160,
        username="datefromadmin",
        email="datefromadmin@example.com",
    )

    base_time = datetime(
        2026,
        10,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    before = create_audit_log(
        db,
        action="date_from_test",
        user_id=admin.id,
        created_at=base_time - timedelta(hours=1),
    )

    at_boundary = create_audit_log(
        db,
        action="date_from_test",
        user_id=admin.id,
        created_at=base_time,
    )

    after = create_audit_log(
        db,
        action="date_from_test",
        user_id=admin.id,
        created_at=base_time + timedelta(hours=1),
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={
            "action": "date_from_test",
            "created_from": base_time.isoformat(),
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2
    assert [item["id"] for item in data["items"]] == [
        after.id,
        at_boundary.id,
    ]
    assert before.id not in [
        item["id"] for item in data["items"]
    ]


def test_audit_log_created_to_filter(
    client: TestClient,
    db: Session,
):
    """
    created_to excludes logs created at or after the supplied timestamp.
    """

    admin = create_admin(
        db,
        user_id=9161,
        username="datetoadmin",
        email="datetoadmin@example.com",
    )

    base_time = datetime(
        2026,
        10,
        2,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    before = create_audit_log(
        db,
        action="date_to_test",
        user_id=admin.id,
        created_at=base_time - timedelta(hours=1),
    )

    at_boundary = create_audit_log(
        db,
        action="date_to_test",
        user_id=admin.id,
        created_at=base_time,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={
            "action": "date_to_test",
            "created_to": base_time.isoformat(),
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["items"][0]["id"] == before.id
    assert at_boundary.id not in [
        item["id"] for item in data["items"]
    ]


def test_audit_log_created_date_range_filter(
    client: TestClient,
    db: Session,
):
    """
    created_from and created_to can be combined into a bounded range.
    """

    admin = create_admin(
        db,
        user_id=9162,
        username="daterangeadmin",
        email="daterangeadmin@example.com",
    )

    start = datetime(
        2026,
        10,
        3,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    end = start + timedelta(hours=2)

    before = create_audit_log(
        db,
        action="date_range_test",
        user_id=admin.id,
        created_at=start - timedelta(seconds=1),
    )

    first = create_audit_log(
        db,
        action="date_range_test",
        user_id=admin.id,
        created_at=start,
    )

    middle = create_audit_log(
        db,
        action="date_range_test",
        user_id=admin.id,
        created_at=start + timedelta(hours=1),
    )

    at_end = create_audit_log(
        db,
        action="date_range_test",
        user_id=admin.id,
        created_at=end,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={
            "action": "date_range_test",
            "created_from": start.isoformat(),
            "created_to": end.isoformat(),
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2
    assert [item["id"] for item in data["items"]] == [
        middle.id,
        first.id,
    ]

    returned_ids = {
        item["id"]
        for item in data["items"]
    }

    assert before.id not in returned_ids
    assert at_end.id not in returned_ids


def test_audit_log_invalid_date_range_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    created_from must be earlier than created_to.
    """

    admin = create_admin(
        db,
        user_id=9163,
        username="invaliddaterangeadmin",
        email="invaliddaterangeadmin@example.com",
    )

    start = datetime(
        2026,
        10,
        4,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={
            "created_from": start.isoformat(),
            "created_to": start.isoformat(),
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "created_from must be earlier than created_to."
    )

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


# ============================================================================
# SUBJECT USER FILTER
# ============================================================================


def test_audit_log_subject_user_id_filter(
    client: TestClient,
    db: Session,
):
    """
    The subject_user_id filter restricts results to events affecting
    a specific user and keeps the filtered total accurate.
    """

    admin = create_admin(
        db,
        user_id=9150,
        username="subjectfilteradmin",
        email="subjectfilteradmin@example.com",
    )

    subject_one = create_test_user(
        db,
        user_id=9151,
        username="subjectone",
        email="subjectone@example.com",
    )

    subject_two = create_test_user(
        db,
        user_id=9152,
        username="subjecttwo",
        email="subjecttwo@example.com",
    )

    create_audit_log(
        db,
        action="subject_event_one",
        user_id=admin.id,
        subject_user_id=subject_one.id,
    )

    create_audit_log(
        db,
        action="subject_event_two",
        user_id=admin.id,
        subject_user_id=subject_two.id,
    )

    create_audit_log(
        db,
        action="subject_event_three",
        user_id=admin.id,
        subject_user_id=subject_one.id,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params={"subject_user_id": subject_one.id},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2
    assert len(data["items"]) == 2

    assert all(
        item["subject_user_id"] == subject_one.id
        for item in data["items"]
    )

    assert {
        item["action"]
        for item in data["items"]
    } == {
        "subject_event_one",
        "subject_event_three",
    }


# ============================================================================
# AUDIT LOG PREVIEW
# ============================================================================


def test_audit_log_preview_admin_can_preview(
    client: TestClient,
    db: Session,
):
    """
    Administrators can preview the matching audit-log count.

    The preview returns filter metadata only and does not expose
    individual audit-log fields such as IP addresses or user agents.
    """

    admin = create_admin(
        db,
        user_id=9160,
        username="previewadmin",
        email="previewadmin@example.com",
    )

    create_audit_log(
        db,
        action="login_success",
        user_id=admin.id,
        ip_address="10.10.10.10",
        user_agent="Sensitive-Test-Agent",
    )

    create_audit_log(
        db,
        action="login_failure",
        user_id=admin.id,
        success=False,
    )

    response = client.get(
        "/api/profile/admin/audit-logs/preview",
        params={"action": " login_success "},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["action"] == "login_success"
    assert data["category"] is None
    assert data["success"] is None
    assert data["user_id"] is None
    assert data["subject_user_id"] is None
    assert data["resource_type"] is None
    assert data["resource_id"] is None
    assert data["created_from"] is None
    assert data["created_to"] is None

    assert "items" not in data
    assert "ip_address" not in data
    assert "user_agent" not in data


def test_audit_log_preview_denies_moderator(
    client: TestClient,
    db: Session,
):
    """
    Moderators cannot access the administrator-only preview endpoint.
    """

    moderator = create_moderator(
        db,
        user_id=9161,
        username="previewmoderator",
        email="previewmoderator@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs/preview",
        headers=authenticated_headers(moderator),
    )

    assert response.status_code in (401, 403)


def test_audit_log_preview_denies_normal_user(
    client: TestClient,
    db: Session,
):
    """
    Normal users cannot access the administrator-only preview endpoint.
    """

    user = create_test_user(
        db,
        user_id=9162,
        username="previewuser",
        email="previewuser@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs/preview",
        headers=authenticated_headers(user),
    )

    assert response.status_code in (401, 403)


def test_audit_log_preview_respects_shared_filters(
    client: TestClient,
    db: Session,
):
    """
    Preview uses the same action-category, success, actor, subject,
    resource, and date-range filters as the audit-log listing endpoint.
    """

    admin = create_admin(
        db,
        user_id=9163,
        username="previewfilteradmin",
        email="previewfilteradmin@example.com",
    )

    subject = create_test_user(
        db,
        user_id=9164,
        username="previewsubject",
        email="previewsubject@example.com",
    )

    matching_one = datetime(
        2026,
        9,
        1,
        10,
        0,
        tzinfo=timezone.utc,
    )

    matching_two = datetime(
        2026,
        9,
        2,
        10,
        0,
        tzinfo=timezone.utc,
    )

    outside_range = datetime(
        2026,
        8,
        30,
        10,
        0,
        tzinfo=timezone.utc,
    )

    create_audit_log(
        db,
        action="login_failure",
        success=False,
        user_id=admin.id,
        subject_user_id=subject.id,
        resource_type="user",
        resource_id=subject.id,
        created_at=matching_one,
    )

    create_audit_log(
        db,
        action="password_reset_failure",
        success=False,
        user_id=admin.id,
        subject_user_id=subject.id,
        resource_type="user",
        resource_id=subject.id,
        created_at=matching_two,
    )

    create_audit_log(
        db,
        action="login_failure",
        success=False,
        user_id=admin.id,
        subject_user_id=subject.id,
        resource_type="user",
        resource_id=subject.id,
        created_at=outside_range,
    )

    create_audit_log(
        db,
        action="item_created",
        success=False,
        user_id=admin.id,
        subject_user_id=subject.id,
        resource_type="user",
        resource_id=subject.id,
        created_at=matching_one + timedelta(minutes=5),
    )

    response = client.get(
        "/api/profile/admin/audit-logs/preview",
        params={
            "category": " AUTHENTICATION ",
            "success": "false",
            "user_id": admin.id,
            "subject_user_id": subject.id,
            "resource_type": " user ",
            "resource_id": subject.id,
            "created_from": "2026-09-01T00:00:00+00:00",
            "created_to": "2026-09-03T00:00:00+00:00",
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2
    assert data["action"] is None
    assert data["category"] == "authentication"
    assert data["success"] is False
    assert data["user_id"] == admin.id
    assert data["subject_user_id"] == subject.id
    assert data["resource_type"] == "user"
    assert data["resource_id"] == subject.id
    assert data["created_from"] == "2026-09-01T00:00:00Z"
    assert data["created_to"] == "2026-09-03T00:00:00Z"


def test_audit_log_preview_normalizes_blank_filters(
    client: TestClient,
    db: Session,
):
    """
    Blank action and resource-type values are normalized to no filter,
    while blank category is also treated as unspecified.
    """

    admin = create_admin(
        db,
        user_id=9165,
        username="previewblankadmin",
        email="previewblankadmin@example.com",
    )

    create_audit_log(
        db,
        action="preview_blank_test",
        user_id=admin.id,
        resource_type="item",
        resource_id=1,
    )

    response = client.get(
        "/api/profile/admin/audit-logs/preview",
        params={
            "action": "",
            "category": "",
            "resource_type": "",
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] >= 1
    assert data["action"] is None
    assert data["category"] is None
    assert data["resource_type"] is None


def test_audit_log_preview_invalid_category_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    Unknown categories are rejected by the shared audit-filter validation.
    """

    admin = create_admin(
        db,
        user_id=9166,
        username="previewinvalidcategory",
        email="previewinvalidcategory@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs/preview",
        params={"category": "not-a-real-category"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Unknown audit-log category."


def test_audit_log_preview_invalid_date_range_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    The preview preserves the same timezone-aware date-range validation
    used by the audit-log listing endpoint.
    """

    admin = create_admin(
        db,
        user_id=9167,
        username="previewinvaliddate",
        email="previewinvaliddate@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs/preview",
        params={
            "created_from": "2026-09-03T00:00:00+00:00",
            "created_to": "2026-09-01T00:00:00+00:00",
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "created_from must be earlier than created_to."
    )


# ============================================================================
# AUDIT LOG EXPORT
# ============================================================================


def test_audit_log_export_csv(
    client: TestClient,
    db: Session,
):
    """
    Administrators can export audit logs as security-safe CSV.
    """

    admin = create_admin(
        db,
        user_id=9180,
        username="exportcsvadmin",
        email="exportcsvadmin@example.com",
    )

    create_audit_log(
        db,
        action="login_success",
        success=True,
        details="Successful login.",
        user_id=admin.id,
        resource_type="user",
        resource_id=admin.id,
        ip_address="10.20.30.40",
        user_agent="Secret-Test-Agent",
    )

    create_audit_log(
        db,
        action="login_failure",
        success=False,
        details="Failed login.",
        user_id=admin.id,
    )

    response = client.get(
        "/api/profile/admin/audit-logs/export",
        params={
            "format": "csv",
            "action": "login_success",
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="trackit-audit-logs.csv"'
    )

    lines = response.text.splitlines()

    assert len(lines) == 2

    header = lines[0].split(",")

    assert header == [
        "id",
        "action",
        "category",
        "success",
        "details",
        "resource_type",
        "resource_id",
        "user_id",
        "subject_user_id",
        "actor_id",
        "actor_username",
        "created_at",
    ]

    assert "ip_address" not in response.text
    assert "user_agent" not in response.text
    assert "10.20.30.40" not in response.text
    assert "Secret-Test-Agent" not in response.text

    assert "login_success" in response.text
    assert "login_failure" not in response.text


def test_audit_log_export_json(
    client: TestClient,
    db: Session,
):
    """
    Administrators can export audit logs as security-safe JSON.
    """

    admin = create_admin(
        db,
        user_id=9181,
        username="exportjsonadmin",
        email="exportjsonadmin@example.com",
    )

    create_audit_log(
        db,
        action="item_created",
        success=True,
        details="Item created.",
        user_id=admin.id,
        resource_type="item",
        resource_id=123,
        ip_address="172.16.0.10",
        user_agent="Secret-JSON-Agent",
    )

    response = client.get(
        "/api/profile/admin/audit-logs/export",
        params={
            "format": "json",
            "action": "item_created",
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "application/json"
    )
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="trackit-audit-logs.json"'
    )

    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1

    item = data[0]

    assert item["action"] == "item_created"
    assert item["category"] == "items"
    assert item["success"] is True
    assert item["details"] == "Item created."
    assert item["resource_type"] == "item"
    assert item["resource_id"] == 123
    assert item["user_id"] == admin.id
    assert item["actor_id"] == admin.id
    assert item["actor_username"] == admin.username
    assert item["created_at"] is not None

    assert "ip_address" not in item
    assert "user_agent" not in item


def test_audit_log_export_uses_shared_filters(
    client: TestClient,
    db: Session,
):
    """
    Export filters use the same category, success, actor, subject,
    resource, and date-range semantics as the listing and preview.
    """

    admin = create_admin(
        db,
        user_id=9182,
        username="exportfilteradmin",
        email="exportfilteradmin@example.com",
    )

    subject = create_test_user(
        db,
        user_id=9183,
        username="exportfilteruser",
        email="exportfilteruser@example.com",
    )

    create_audit_log(
        db,
        action="login_failure",
        success=False,
        user_id=admin.id,
        subject_user_id=subject.id,
        resource_type="user",
        resource_id=subject.id,
        created_at=datetime(
            2026,
            9,
            10,
            10,
            0,
            tzinfo=timezone.utc,
        ),
    )

    create_audit_log(
        db,
        action="password_reset_failure",
        success=False,
        user_id=admin.id,
        subject_user_id=subject.id,
        resource_type="user",
        resource_id=subject.id,
        created_at=datetime(
            2026,
            9,
            11,
            10,
            0,
            tzinfo=timezone.utc,
        ),
    )

    create_audit_log(
        db,
        action="item_created",
        success=False,
        user_id=admin.id,
        subject_user_id=subject.id,
        resource_type="user",
        resource_id=subject.id,
        created_at=datetime(
            2026,
            9,
            10,
            11,
            0,
            tzinfo=timezone.utc,
        ),
    )

    response = client.get(
        "/api/profile/admin/audit-logs/export",
        params={
            "format": "json",
            "category": " AUTHENTICATION ",
            "success": "false",
            "user_id": admin.id,
            "subject_user_id": subject.id,
            "resource_type": " user ",
            "resource_id": subject.id,
            "created_from": "2026-09-10T00:00:00+00:00",
            "created_to": "2026-09-12T00:00:00+00:00",
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 2
    assert {
        item["action"]
        for item in data
    } == {
        "login_failure",
        "password_reset_failure",
    }

    assert all(
        item["category"] == "authentication"
        for item in data
    )

    assert all(
        item["success"] is False
        and item["user_id"] == admin.id
        and item["subject_user_id"] == subject.id
        and item["resource_type"] == "user"
        and item["resource_id"] == subject.id
        for item in data
    )


def test_audit_log_export_denies_moderator(
    client: TestClient,
    db: Session,
):
    """
    Moderators cannot use the administrator-only audit export.
    """

    moderator = create_moderator(
        db,
        user_id=9184,
        username="exportmoderator",
        email="exportmoderator@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs/export",
        headers=authenticated_headers(moderator),
    )

    assert response.status_code in (401, 403)


def test_audit_log_export_denies_normal_user(
    client: TestClient,
    db: Session,
):
    """
    Normal users cannot use the administrator-only audit export.
    """

    user = create_test_user(
        db,
        user_id=9185,
        username="exportnormaluser",
        email="exportnormaluser@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs/export",
        headers=authenticated_headers(user),
    )

    assert response.status_code in (401, 403)


def test_audit_log_export_invalid_format_returns_unprocessable_entity(
    client: TestClient,
    db: Session,
):
    """
    Export format is restricted to the supported CSV and JSON values.
    """

    admin = create_admin(
        db,
        user_id=9186,
        username="exportinvalidformat",
        email="exportinvalidformat@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs/export",
        params={"format": "xml"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 422


def test_audit_log_export_invalid_category_returns_bad_request(
    client: TestClient,
    db: Session,
):
    """
    Export uses the same category validation as listing and preview.
    """

    admin = create_admin(
        db,
        user_id=9187,
        username="exportinvalidcategory",
        email="exportinvalidcategory@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs/export",
        params={"category": "not-a-real-category"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Unknown audit-log category."


def test_audit_log_export_empty_result_is_valid(
    client: TestClient,
    db: Session,
):
    """
    A valid filter producing no rows still returns a valid empty export.
    """

    admin = create_admin(
        db,
        user_id=9188,
        username="exportempty",
        email="exportempty@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs/export",
        params={
            "format": "json",
            "action": "action-that-does-not-exist",
        },
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200
    assert response.json() == []


# ============================================================================
# MULTI-USER ACTOR FILTER
# ============================================================================


def test_audit_log_user_ids_filter(
    client: TestClient,
    db: Session,
):
    """
    user_ids accepts repeated query parameters and returns logs for
    any matching actor.
    """

    admin = create_admin(
        db,
        user_id=9190,
        username="multiuserfilteradmin",
        email="multiuserfilteradmin@example.com",
    )

    actor_one = create_test_user(
        db,
        user_id=9191,
        username="multiuserone",
        email="multiuserone@example.com",
    )

    actor_two = create_test_user(
        db,
        user_id=9192,
        username="multiusertwo",
        email="multiusertwo@example.com",
    )

    actor_three = create_test_user(
        db,
        user_id=9193,
        username="multiuserthree",
        email="multiuserthree@example.com",
    )

    create_audit_log(
        db,
        action="multi_user_one",
        user_id=actor_one.id,
    )

    create_audit_log(
        db,
        action="multi_user_two",
        user_id=actor_two.id,
    )

    create_audit_log(
        db,
        action="multi_user_three",
        user_id=actor_three.id,
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params=[
            ("user_ids", str(actor_one.id)),
            ("user_ids", str(actor_two.id)),
        ],
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2

    assert {
        item["action"]
        for item in data["items"]
    } == {
        "multi_user_one",
        "multi_user_two",
    }

    assert {
        item["user_id"]
        for item in data["items"]
    } == {
        actor_one.id,
        actor_two.id,
    }


def test_audit_log_user_ids_preview_normalizes_duplicates(
    client: TestClient,
    db: Session,
):
    """
    Preview deduplicates repeated user IDs and returns the normalized list.
    """

    admin = create_admin(
        db,
        user_id=9194,
        username="multiuserpreviewadmin",
        email="multiuserpreviewadmin@example.com",
    )

    actor_one = create_test_user(
        db,
        user_id=9195,
        username="previewmultiuserone",
        email="previewmultiuserone@example.com",
    )

    actor_two = create_test_user(
        db,
        user_id=9196,
        username="previewmultiusertwo",
        email="previewmultiusertwo@example.com",
    )

    create_audit_log(
        db,
        action="preview_multi_one",
        user_id=actor_one.id,
    )

    create_audit_log(
        db,
        action="preview_multi_two",
        user_id=actor_two.id,
    )

    response = client.get(
        "/api/profile/admin/audit-logs/preview",
        params=[
            ("user_ids", str(actor_one.id)),
            ("user_ids", str(actor_one.id)),
            ("user_ids", str(actor_two.id)),
        ],
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2
    assert data["user_id"] is None
    assert data["user_ids"] == [
        actor_one.id,
        actor_two.id,
    ]


def test_audit_log_user_ids_export(
    client: TestClient,
    db: Session,
):
    """
    CSV export supports repeated user_ids filters.
    """

    admin = create_admin(
        db,
        user_id=9197,
        username="multiuserexportadmin",
        email="multiuserexportadmin@example.com",
    )

    actor_one = create_test_user(
        db,
        user_id=9198,
        username="exportmultiuserone",
        email="exportmultiuserone@example.com",
    )

    actor_two = create_test_user(
        db,
        user_id=9199,
        username="exportmultiusertwo",
        email="exportmultiusertwo@example.com",
    )

    other_actor = create_test_user(
        db,
        user_id=9200,
        username="exportmultiuserother",
        email="exportmultiuserother@example.com",
    )

    create_audit_log(
        db,
        action="export_multi_one",
        user_id=actor_one.id,
    )

    create_audit_log(
        db,
        action="export_multi_two",
        user_id=actor_two.id,
    )

    create_audit_log(
        db,
        action="export_multi_other",
        user_id=other_actor.id,
    )

    response = client.get(
        "/api/profile/admin/audit-logs/export",
        params=[
            ("format", "csv"),
            ("user_ids", str(actor_one.id)),
            ("user_ids", str(actor_two.id)),
        ],
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    assert "export_multi_one" in response.text
    assert "export_multi_two" in response.text
    assert "export_multi_other" not in response.text


def test_audit_log_user_id_and_user_ids_cannot_be_combined(
    client: TestClient,
    db: Session,
):
    """
    The API rejects ambiguous combinations of user_id and user_ids.
    """

    admin = create_admin(
        db,
        user_id=9201,
        username="multiuserconflictadmin",
        email="multiuserconflictadmin@example.com",
    )

    actor = create_test_user(
        db,
        user_id=9202,
        username="multiuserconflictactor",
        email="multiuserconflictactor@example.com",
    )

    response = client.get(
        "/api/profile/admin/audit-logs",
        params=[
            ("user_id", str(actor.id)),
            ("user_ids", str(actor.id)),
        ],
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Use either user_id or user_ids, not both."
    )
