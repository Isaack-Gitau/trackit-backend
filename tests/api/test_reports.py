"""
TRACKIT Report API Integration Tests.

Tests the HTTP/API layer for:
- report creation
- moderator/admin report queues
- moderator/admin report review
- moderator/admin report resolution
- authorization
"""

from app.core.security import create_access_token
from app.models.item import Item
from app.models.report import Report
from app.models.user import User
from app.services.report import review_report


# ============================================================================
# HELPERS
# ============================================================================


def create_user(
    db,
    *,
    user_id: int,
    username: str,
    role: str = "user",
):
    user = User(
        id=user_id,
        username=username,
        first_name="Test",
        last_name="User",
        email=f"{username}@trackit.test",
        password_hash="test-password-hash",
        role=role,
        is_active=True,
        is_verified=True,
        token_version=0,
    )

    db.add(user)
    db.flush()

    return user


def create_item(
    db,
    *,
    owner_id: int,
):
    item = Item(
        user_id=owner_id,
        title="Reported Test Phone",
        description="API integration test item for reports.",
        type="found",
        category="Electronics",
        location="Main Library",
        status="approved",
    )

    db.add(item)
    db.flush()

    return item


def create_report(
    db,
    *,
    item_id: int,
    reporter_id: int,
):
    report = Report(
        item_id=item_id,
        reporter_id=reporter_id,
        reason="Suspicious item",
        description=(
            "This item appears suspicious and should be reviewed."
        ),
        status="pending",
    )

    db.add(report)
    db.flush()

    return report


def auth_headers(user):
    """
    Generate a real TRACKIT access token using
    the same JWT structure as the production login flow.
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
# PENDING REPORTS
# ============================================================================


def test_moderator_can_list_pending_reports(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2001,
        username="apireport_owner_pending_mod",
    )

    reporter = create_user(
        db,
        user_id=2002,
        username="apireport_reporter_pending_mod",
    )

    moderator = create_user(
        db,
        user_id=2003,
        username="apireport_moderator_pending",
        role="moderator",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    response = client.get(
        "/api/reports/admin/pending",
        headers=auth_headers(moderator),
    )

    assert response.status_code == 200

    reports = response.json()

    report_ids = {
        current["id"]
        for current in reports
    }

    assert report.id in report_ids

    pending_report = next(
        current
        for current in reports
        if current["id"] == report.id
    )

    assert pending_report["reporter_id"] == reporter.id
    assert pending_report["reporter"] == {
        "id": reporter.id,
        "username": reporter.username,
    }


def test_admin_can_list_pending_reports(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2004,
        username="apireport_owner_pending_admin",
    )

    reporter = create_user(
        db,
        user_id=2005,
        username="apireport_reporter_pending_admin",
    )

    admin = create_user(
        db,
        user_id=2006,
        username="apireport_admin_pending",
        role="admin",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    response = client.get(
        "/api/reports/admin/pending",
        headers=auth_headers(admin),
    )

    assert response.status_code == 200

    report_ids = {
        current["id"]
        for current in response.json()
    }

    assert report.id in report_ids


def test_normal_user_cannot_list_pending_reports(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2007,
        username="apireport_normal_pending",
    )

    response = client.get(
        "/api/reports/admin/pending",
        headers=auth_headers(user),
    )

    assert response.status_code == 403


def test_unauthenticated_user_cannot_list_pending_reports(
    client,
    db,
):
    response = client.get(
        "/api/reports/admin/pending",
    )

    assert response.status_code == 401


# ============================================================================
# REVIEWED REPORTS
# ============================================================================


def test_moderator_can_list_reviewed_reports(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2008,
        username="apireport_owner_reviewed_mod",
    )

    reporter = create_user(
        db,
        user_id=2009,
        username="apireport_reporter_reviewed_mod",
    )

    reviewer = create_user(
        db,
        user_id=2010,
        username="apireport_reviewer_reviewed_mod",
        role="admin",
    )

    moderator = create_user(
        db,
        user_id=2011,
        username="apireport_moderator_reviewed",
        role="moderator",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    response = client.get(
        "/api/reports/admin/reviewed",
        headers=auth_headers(moderator),
    )

    assert response.status_code == 200

    reports = response.json()

    report_ids = {
        current["id"]
        for current in reports
    }

    assert report.id in report_ids

    reviewed_report = next(
        current
        for current in reports
        if current["id"] == report.id
    )

    assert reviewed_report["reporter_id"] == reporter.id
    assert reviewed_report["reporter"] == {
        "id": reporter.id,
        "username": reporter.username,
    }


def test_admin_can_list_reviewed_reports(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2012,
        username="apireport_owner_reviewed_admin",
    )

    reporter = create_user(
        db,
        user_id=2013,
        username="apireport_reporter_reviewed_admin",
    )

    admin = create_user(
        db,
        user_id=2014,
        username="apireport_admin_reviewed",
        role="admin",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    review_report(
        db,
        report=report,
        reviewer_id=admin.id,
    )

    response = client.get(
        "/api/reports/admin/reviewed",
        headers=auth_headers(admin),
    )

    assert response.status_code == 200

    report_ids = {
        current["id"]
        for current in response.json()
    }

    assert report.id in report_ids


def test_normal_user_cannot_list_reviewed_reports(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2015,
        username="apireport_normal_reviewed",
    )

    response = client.get(
        "/api/reports/admin/reviewed",
        headers=auth_headers(user),
    )

    assert response.status_code == 403


# ============================================================================
# REVIEW REPORT
# ============================================================================


def test_moderator_can_review_pending_report(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2016,
        username="apireport_owner_review_mod",
    )

    reporter = create_user(
        db,
        user_id=2017,
        username="apireport_reporter_review_mod",
    )

    moderator = create_user(
        db,
        user_id=2018,
        username="apireport_moderator_review",
        role="moderator",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    response = client.patch(
        f"/api/reports/admin/{report.id}/review",
        headers=auth_headers(moderator),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == report.id
    assert data["status"] == "reviewed"
    assert data["reviewed_by"] == moderator.id
    assert data["reporter_id"] == reporter.id
    assert data["reporter"] == {
        "id": reporter.id,
        "username": reporter.username,
    }


def test_admin_can_review_pending_report(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2019,
        username="apireport_owner_review_admin",
    )

    reporter = create_user(
        db,
        user_id=2020,
        username="apireport_reporter_review_admin",
    )

    admin = create_user(
        db,
        user_id=2021,
        username="apireport_admin_review",
        role="admin",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    response = client.patch(
        f"/api/reports/admin/{report.id}/review",
        headers=auth_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == report.id
    assert data["status"] == "reviewed"
    assert data["reviewed_by"] == admin.id


def test_normal_user_cannot_review_pending_report(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2022,
        username="apireport_owner_review_user",
    )

    reporter = create_user(
        db,
        user_id=2023,
        username="apireport_reporter_review_user",
    )

    user = create_user(
        db,
        user_id=2024,
        username="apireport_normal_review",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    response = client.patch(
        f"/api/reports/admin/{report.id}/review",
        headers=auth_headers(user),
    )

    assert response.status_code == 403

    db.refresh(report)

    assert report.status == "pending"


def test_moderator_cannot_review_own_report(
    client,
    db,
):
    """
    A moderator cannot review a report they submitted themselves.
    The API must return 403 rather than an internal server error.
    """

    owner = create_user(
        db,
        user_id=2034,
        username="apireport_owner_self_review",
    )

    moderator = create_user(
        db,
        user_id=2035,
        username="apireport_moderator_self_review",
        role="moderator",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=moderator.id,
    )

    response = client.patch(
        f"/api/reports/admin/{report.id}/review",
        headers=auth_headers(moderator),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "You cannot moderate your own report."
    )

    db.refresh(report)

    assert report.status == "pending"
    assert report.reviewed_by is None
    assert report.reviewed_at is None


def test_unauthenticated_user_cannot_review_pending_report(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2025,
        username="apireport_owner_review_anon",
    )

    reporter = create_user(
        db,
        user_id=2026,
        username="apireport_reporter_review_anon",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    response = client.patch(
        f"/api/reports/admin/{report.id}/review",
    )

    assert response.status_code == 401

    db.refresh(report)

    assert report.status == "pending"


# ============================================================================
# RESOLVE REPORT
# ============================================================================


def test_moderator_can_resolve_reviewed_report(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2027,
        username="apireport_owner_resolve_mod",
    )

    reporter = create_user(
        db,
        user_id=2028,
        username="apireport_reporter_resolve_mod",
    )

    moderator = create_user(
        db,
        user_id=2029,
        username="apireport_moderator_resolve",
        role="moderator",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    review_report(
        db,
        report=report,
        reviewer_id=moderator.id,
    )

    response = client.patch(
        f"/api/reports/admin/{report.id}/resolve",
        headers=auth_headers(moderator),
        json={
            "resolution_note": "Report investigated and resolved.",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == report.id
    assert data["status"] == "resolved"
    assert data["reviewed_by"] == moderator.id
    assert data["reporter_id"] == reporter.id
    assert data["reporter"] == {
        "id": reporter.id,
        "username": reporter.username,
    }
    assert (
        data["resolution_note"]
        == "Report investigated and resolved."
    )


def test_admin_can_resolve_reviewed_report(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2030,
        username="apireport_owner_resolve_admin",
    )

    reporter = create_user(
        db,
        user_id=2031,
        username="apireport_reporter_resolve_admin",
    )

    admin = create_user(
        db,
        user_id=2032,
        username="apireport_admin_resolve",
        role="admin",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    review_report(
        db,
        report=report,
        reviewer_id=admin.id,
    )

    response = client.patch(
        f"/api/reports/admin/{report.id}/resolve",
        headers=auth_headers(admin),
        json={
            "resolution_note": "Report investigated and resolved.",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == report.id
    assert data["status"] == "resolved"
    assert data["reviewed_by"] == admin.id
    assert (
        data["resolution_note"]
        == "Report investigated and resolved."
    )


def test_normal_user_cannot_resolve_reviewed_report(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2033,
        username="apireport_owner_resolve_user",
    )

    reporter = create_user(
        db,
        user_id=2034,
        username="apireport_reporter_resolve_user",
    )

    reviewer = create_user(
        db,
        user_id=2035,
        username="apireport_reviewer_resolve_user",
        role="admin",
    )

    user = create_user(
        db,
        user_id=2036,
        username="apireport_normal_resolve",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    response = client.patch(
        f"/api/reports/admin/{report.id}/resolve",
        headers=auth_headers(user),
        json={
            "resolution_note": "This should not be allowed.",
        },
    )

    assert response.status_code == 403

    db.refresh(report)

    assert report.status == "reviewed"


def test_moderator_cannot_resolve_own_report(
    client,
    db,
):
    """
    A moderator cannot resolve a report they submitted themselves.
    The API must return 403 rather than an internal server error.
    """

    owner = create_user(
        db,
        user_id=2040,
        username="apireport_owner_self_resolve",
    )

    moderator = create_user(
        db,
        user_id=2041,
        username="apireport_moderator_self_resolve",
        role="moderator",
    )

    reviewer = create_user(
        db,
        user_id=2042,
        username="apireport_admin_review_self_resolve",
        role="admin",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=moderator.id,
    )

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    response = client.patch(
        f"/api/reports/admin/{report.id}/resolve",
        headers=auth_headers(moderator),
        json={
            "resolution_note": "This should not be allowed.",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "You cannot moderate your own report."
    )

    db.refresh(report)

    assert report.status == "reviewed"


def test_unauthenticated_user_cannot_resolve_reviewed_report(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2037,
        username="apireport_owner_resolve_anon",
    )

    reporter = create_user(
        db,
        user_id=2038,
        username="apireport_reporter_resolve_anon",
    )

    reviewer = create_user(
        db,
        user_id=2039,
        username="apireport_reviewer_resolve_anon",
        role="admin",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    report = create_report(
        db,
        item_id=item.id,
        reporter_id=reporter.id,
    )

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    response = client.patch(
        f"/api/reports/admin/{report.id}/resolve",
        json={
            "resolution_note": "This should not be allowed.",
        },
    )

    assert response.status_code == 401

    db.refresh(report)

    assert report.status == "reviewed"
