"""
TRACKIT Report Service Tests.

Tests:

- Report creation
- Report validation
- Duplicate active reports
- Report retrieval
- User/item report filtering
- Pending/reviewed report queues
- Report review
- Report resolution
- Invalid lifecycle transitions
- Reviewer tracking
- Audit logging
"""

from datetime import datetime

import pytest
from sqlalchemy import select

from app.models.audit_log import AuditLog
from app.models.item import Item
from app.models.user import User
from app.services.report import (
    REPORT_STATUS_PENDING,
    REPORT_STATUS_REVIEWED,
    REPORT_STATUS_RESOLVED,
    create_report,
    get_report,
    list_item_reports,
    list_pending_reports,
    list_reviewed_reports,
    list_user_reports,
    resolve_report,
    review_report,
)


# ============================================================================
# TEST CONSTANTS
# ============================================================================

TEST_ITEM_OWNER_ID = 1001
TEST_REPORTER_ID = 1002
TEST_SECOND_REPORTER_ID = 1003
TEST_REVIEWER_ID = 1004
TEST_SECOND_REVIEWER_ID = 1005


# ============================================================================
# TEST HELPERS
# ============================================================================


def create_test_user(
    db,
    *,
    user_id: int,
    role: str = "user",
):
    """
    Create a minimal valid User required by foreign keys.
    """

    user = db.get(User, user_id)

    if user is not None:
        return user

    user = User(
        id=user_id,
        username=f"reportuser{user_id}",
        first_name="Report",
        last_name="User",
        email=f"reportuser{user_id}@trackit.test",
        password_hash="test-password-hash",
        role=role,
        is_active=True,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    return user


def create_test_reviewer(
    db,
    *,
    user_id: int = TEST_REVIEWER_ID,
):
    """
    Create a valid administrator/reviewer.
    """

    return create_test_user(
        db,
        user_id=user_id,
        role="admin",
    )


def create_test_item(
    db,
    *,
    user_id: int = TEST_ITEM_OWNER_ID,
    title: str = "Reported Phone",
):
    """
    Create a minimal valid item.
    """

    create_test_user(
        db,
        user_id=user_id,
    )

    item = Item(
        user_id=user_id,
        title=title,
        description="A valid test item for TRACKIT report testing.",
        type="found",
        category="Electronics",
        location="Main Library",
        status="approved",
    )

    db.add(item)
    db.flush()

    return item


def create_test_report(
    db,
    *,
    item_user_id: int = TEST_ITEM_OWNER_ID,
    reporter_id: int = TEST_REPORTER_ID,
    title: str = "Reported Phone",
    reason: str = "Suspicious item",
    description: str = (
        "This item appears suspicious and should be reviewed."
    ),
):
    """
    Create a valid report through the service layer.
    """

    item = create_test_item(
        db,
        user_id=item_user_id,
        title=title,
    )

    create_test_user(
        db,
        user_id=reporter_id,
    )

    report = create_report(
        db,
        item=item,
        reporter_id=reporter_id,
        reason=reason,
        description=description,
    )

    return item, report


def get_audit_logs(db):
    """
    Return all audit logs in the current test transaction.
    """

    return list(
        db.scalars(
            select(AuditLog)
        ).all()
    )


# ============================================================================
# CREATE REPORT
# ============================================================================


def test_create_report_successfully(db):
    """
    A valid report should be created in pending state.
    """

    item, report = create_test_report(db)

    assert report.id is not None
    assert report.item_id == item.id
    assert report.reporter_id == TEST_REPORTER_ID
    assert report.reason == "Suspicious item"
    assert report.description.startswith(
        "This item appears suspicious"
    )
    assert report.status == REPORT_STATUS_PENDING


def test_create_report_strips_reason_whitespace(db):
    """
    Report reasons should be normalized.
    """

    item = create_test_item(db)

    create_test_user(
        db,
        user_id=TEST_REPORTER_ID,
    )

    report = create_report(
        db,
        item=item,
        reporter_id=TEST_REPORTER_ID,
        reason="   Suspicious item   ",
        description="   This item requires administrative review.   ",
    )

    assert report.reason == "Suspicious item"


def test_create_report_strips_description_whitespace(db):
    """
    Report descriptions should be normalized.
    """

    item = create_test_item(db)

    create_test_user(
        db,
        user_id=TEST_REPORTER_ID,
    )

    report = create_report(
        db,
        item=item,
        reporter_id=TEST_REPORTER_ID,
        reason="Suspicious item",
        description="   This item requires review.   ",
    )

    assert report.description == "This item requires review."


def test_report_reason_cannot_be_empty(db):
    """
    Empty report reasons must be rejected.
    """

    item = create_test_item(db)

    create_test_user(
        db,
        user_id=TEST_REPORTER_ID,
    )

    with pytest.raises(
        ValueError,
        match="Report reason cannot be empty",
    ):
        create_report(
            db,
            item=item,
            reporter_id=TEST_REPORTER_ID,
            reason="   ",
            description="This report contains enough detail.",
        )


def test_report_description_cannot_be_empty(db):
    """
    Empty report descriptions must be rejected.
    """

    item = create_test_item(db)

    create_test_user(
        db,
        user_id=TEST_REPORTER_ID,
    )

    with pytest.raises(
        ValueError,
        match="Report description cannot be empty",
    ):
        create_report(
            db,
            item=item,
            reporter_id=TEST_REPORTER_ID,
            reason="Suspicious item",
            description="   ",
        )


def test_user_cannot_report_own_item(db):
    """
    Item owners must not be allowed to report their own items.
    """

    item = create_test_item(
        db,
        user_id=TEST_ITEM_OWNER_ID,
    )

    with pytest.raises(
        PermissionError,
        match="cannot report your own item",
    ):
        create_report(
            db,
            item=item,
            reporter_id=TEST_ITEM_OWNER_ID,
            reason="Suspicious item",
            description="I am reporting this item.",
        )


def test_duplicate_pending_report_is_rejected(db):
    """
    A user cannot have multiple active reports for the same item.
    """

    item, first_report = create_test_report(db)

    assert first_report.status == REPORT_STATUS_PENDING

    with pytest.raises(
        ValueError,
        match="already have an active report",
    ):
        create_report(
            db,
            item=item,
            reporter_id=TEST_REPORTER_ID,
            reason="Another reason",
            description="This is another report for the same item.",
        )


# ============================================================================
# GET REPORT
# ============================================================================


def test_get_report_returns_existing_report(db):
    """
    Existing reports should be retrievable by ID.
    """

    _, report = create_test_report(db)

    result = get_report(
        db,
        report_id=report.id,
    )

    assert result is not None
    assert result.id == report.id


def test_get_report_returns_none_for_missing_report(db):
    """
    Missing reports should return None.
    """

    result = get_report(
        db,
        report_id=999999,
    )

    assert result is None


# ============================================================================
# LIST USER REPORTS
# ============================================================================


def test_list_user_reports_returns_only_users_reports(db):
    """
    A user should receive only reports they submitted.
    """

    _, first_report = create_test_report(
        db,
        reporter_id=TEST_REPORTER_ID,
        title="Reported Phone",
    )

    _, second_report = create_test_report(
        db,
        reporter_id=TEST_SECOND_REPORTER_ID,
        title="Reported Laptop",
    )

    reports = list_user_reports(
        db,
        reporter_id=TEST_REPORTER_ID,
    )

    report_ids = {
        report.id
        for report in reports
    }

    assert first_report.id in report_ids
    assert second_report.id not in report_ids

    assert all(
        report.reporter_id == TEST_REPORTER_ID
        for report in reports
    )


def test_list_user_reports_empty_for_user_without_reports(db):
    """
    A user without reports should receive an empty list.
    """

    create_test_user(
        db,
        user_id=TEST_REPORTER_ID,
    )

    reports = list_user_reports(
        db,
        reporter_id=TEST_REPORTER_ID,
    )

    assert reports == []


# ============================================================================
# LIST ITEM REPORTS
# ============================================================================


def test_list_item_reports_returns_only_item_reports(db):
    """
    Listing reports for an item should not return reports
    belonging to another item.
    """

    item_one, report_one = create_test_report(
        db,
        title="Reported Phone",
    )

    item_two, report_two = create_test_report(
        db,
        reporter_id=TEST_SECOND_REPORTER_ID,
        title="Reported Laptop",
    )

    reports = list_item_reports(
        db,
        item_id=item_one.id,
    )

    report_ids = {
        report.id
        for report in reports
    }

    assert report_one.id in report_ids
    assert report_two.id not in report_ids

    assert all(
        report.item_id == item_one.id
        for report in reports
    )


def test_list_item_reports_empty_for_item_without_reports(db):
    """
    An item without reports should return an empty list.
    """

    item = create_test_item(db)

    reports = list_item_reports(
        db,
        item_id=item.id,
    )

    assert reports == []


# ============================================================================
# LIST PENDING REPORTS
# ============================================================================


def test_list_pending_reports(db):
    """
    Pending reports should be returned for administrative review.
    """

    _, first_report = create_test_report(
        db,
        reporter_id=TEST_REPORTER_ID,
        title="Pending Phone",
    )

    _, second_report = create_test_report(
        db,
        reporter_id=TEST_SECOND_REPORTER_ID,
        title="Pending Laptop",
    )

    reports = list_pending_reports(db)

    report_ids = {
        report.id
        for report in reports
    }

    assert first_report.id in report_ids
    assert second_report.id in report_ids

    assert all(
        report.status == REPORT_STATUS_PENDING
        for report in reports
    )


def test_reviewed_report_is_not_pending(db):
    """
    Reviewed reports must not remain in the pending queue.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    pending = list_pending_reports(db)

    assert all(
        pending_report.id != report.id
        for pending_report in pending
    )


# ============================================================================
# LIST REVIEWED REPORTS
# ============================================================================


def test_reviewed_report_is_returned_by_reviewed_queue(db):
    """
    Reviewed reports should appear in the reviewed queue.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    reviewed = review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    reports = list_reviewed_reports(db)

    report_ids = {
        current.id
        for current in reports
    }

    assert reviewed.id in report_ids

    assert all(
        current.status == REPORT_STATUS_REVIEWED
        for current in reports
    )


def test_resolved_report_is_not_in_reviewed_queue(db):
    """
    Resolved reports should leave the reviewed queue.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    resolve_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
        resolution_note="Report investigated and resolved.",
    )

    reports = list_reviewed_reports(db)

    assert all(
        current.id != report.id
        for current in reports
    )


# ============================================================================
# REVIEW REPORT
# ============================================================================


def test_pending_report_can_be_reviewed(db):
    """
    A pending report can transition to reviewed.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    result = review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    assert result.status == REPORT_STATUS_REVIEWED
    assert result.reviewed_by == reviewer.id
    assert result.reviewed_at is not None
    assert isinstance(result.reviewed_at, datetime)


def test_reviewed_report_cannot_be_reviewed_again(db):
    """
    A reviewed report cannot be reviewed a second time.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    with pytest.raises(
        ValueError,
        match="Only pending reports can be reviewed",
    ):
        review_report(
            db,
            report=report,
            reviewer_id=TEST_SECOND_REVIEWER_ID,
        )


def test_resolved_report_cannot_be_reviewed(db):
    """
    A resolved report cannot return to reviewed state.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    resolve_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
        resolution_note="Report was resolved after investigation.",
    )

    with pytest.raises(
        ValueError,
        match="Only pending reports can be reviewed",
    ):
        review_report(
            db,
            report=report,
            reviewer_id=reviewer.id,
        )


# ============================================================================
# RESOLVE REPORT
# ============================================================================


def test_reviewed_report_can_be_resolved(db):
    """
    A reviewed report can transition to resolved.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    result = resolve_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
        resolution_note="The report was investigated and resolved.",
    )

    assert result.status == REPORT_STATUS_RESOLVED
    assert result.reviewed_by == reviewer.id
    assert result.resolution_note == (
        "The report was investigated and resolved."
    )


def test_resolution_note_is_stripped(db):
    """
    Resolution notes should be normalized.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    result = resolve_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
        resolution_note="   Resolved after investigation.   ",
    )

    assert result.resolution_note == (
        "Resolved after investigation."
    )


def test_resolution_requires_note(db):
    """
    Resolution notes are mandatory.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    with pytest.raises(
        ValueError,
        match="Resolution note cannot be empty",
    ):
        resolve_report(
            db,
            report=report,
            reviewer_id=reviewer.id,
            resolution_note="   ",
        )


def test_pending_report_cannot_be_resolved_directly(db):
    """
    Pending reports must be reviewed before resolution.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    with pytest.raises(
        ValueError,
        match="Only reviewed reports can be resolved",
    ):
        resolve_report(
            db,
            report=report,
            reviewer_id=reviewer.id,
            resolution_note="Attempted direct resolution.",
        )


def test_resolved_report_cannot_be_resolved_again(db):
    """
    A resolved report cannot be resolved twice.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    resolve_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
        resolution_note="Initial resolution.",
    )

    with pytest.raises(
        ValueError,
        match="Only reviewed reports can be resolved",
    ):
        resolve_report(
            db,
            report=report,
            reviewer_id=reviewer.id,
            resolution_note="Second resolution attempt.",
        )


# ============================================================================
# ACTIVE REPORT BEHAVIOR
# ============================================================================


def test_reviewed_report_remains_active(db):
    """
    A reviewed report should continue blocking duplicate reports.
    """

    item, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    with pytest.raises(
        ValueError,
        match="already have an active report",
    ):
        create_report(
            db,
            item=item,
            reporter_id=TEST_REPORTER_ID,
            reason="Duplicate report",
            description="This should be blocked while reviewed.",
        )


def test_resolved_report_no_longer_blocks_new_report(db):
    """
    Once a report is resolved, the reporter may submit a new report
    for the same item.
    """

    item, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    resolve_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
        resolution_note="Original report resolved.",
    )

    new_report = create_report(
        db,
        item=item,
        reporter_id=TEST_REPORTER_ID,
        reason="New issue",
        description="A new issue has now been identified.",
    )

    assert new_report.id != report.id
    assert new_report.status == REPORT_STATUS_PENDING


# ============================================================================
# REVIEWER TRACKING
# ============================================================================


def test_review_records_reviewer(db):
    """
    Review must record the administrator who performed it.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    result = review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    assert result.reviewed_by == reviewer.id
    assert result.reviewed_at is not None


def test_resolution_records_reviewer(db):
    """
    Resolution must preserve the reviewer identity.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    result = resolve_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
        resolution_note="Resolution completed.",
    )

    assert result.reviewed_by == reviewer.id
    assert result.reviewed_at is not None


# ============================================================================
# AUDIT LOGGING
# ============================================================================


def test_create_report_creates_audit_log(db):
    """
    Creating a report must create an audit record.
    """

    item, report = create_test_report(db)

    audit_logs = get_audit_logs(db)

    matching = [
        log
        for log in audit_logs
        if log.user_id == TEST_REPORTER_ID
        and report.id is not None
        and f"Report {report.id} created" in (
            log.description or ""
        )
    ]

    assert len(matching) == 1
    assert matching[0].success is True


def test_review_report_creates_audit_log(db):
    """
    Reviewing a report must create an audit record.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    audit_logs = get_audit_logs(db)

    matching = [
        log
        for log in audit_logs
        if log.user_id == reviewer.id
        and f"Report {report.id} reviewed" in (
            log.description or ""
        )
    ]

    assert len(matching) == 1
    assert matching[0].success is True


def test_resolve_report_creates_audit_log(db):
    """
    Resolving a report must create an audit record.
    """

    _, report = create_test_report(db)

    reviewer = create_test_reviewer(db)

    review_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
    )

    resolve_report(
        db,
        report=report,
        reviewer_id=reviewer.id,
        resolution_note="Resolution completed.",
    )

    audit_logs = get_audit_logs(db)

    matching = [
        log
        for log in audit_logs
        if log.user_id == reviewer.id
        and f"Report {report.id} resolved" in (
            log.description or ""
        )
    ]

    assert len(matching) == 1
    assert matching[0].success is True
