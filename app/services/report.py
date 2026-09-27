"""
TRACKIT Report Service.

Business logic for creating, retrieving, and moderator/admin
reviewing reports against items.

Architecture:

Router
    ↓
Schema / Validation
    ↓
Service / Business Rules
    ↓
Repository / Database Access
    ↓
Model

Security principles:

- Reporter identity always comes from the authenticated user.
- Reviewer identity always comes from the authenticated moderator or administrator.
- Clients cannot directly choose report status.
- Clients cannot directly choose reviewer fields.
- Reports can only be submitted against existing items.
- Users cannot report their own items.
- Duplicate active reports are prevented.
- Only pending reports may be reviewed.
- Only reviewed reports may be resolved.
- Moderators/admins cannot review or resolve their own reports.
- Only the reporter may withdraw their own pending report.
- Withdrawn reports are no longer active.
- Security-relevant actions are audited.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.constants import ReportStatus
from app.models.item import Item
from app.models.report import Report
from app.repositories.reports import (
    create_report as repository_create_report,
    get_active_report_by_user_and_item,
    get_pending_reports,
    get_report_by_id,
    get_reports_by_item,
    get_reports_by_user,
    get_reviewed_reports,
    update_report as repository_update_report,
)
from app.services.audit_log import (
    AUDIT_ADMIN_ACTION,
    create_audit_log,
)


# ============================================================================
# CONSTANTS
# ============================================================================

REPORT_STATUS_PENDING = ReportStatus.PENDING
REPORT_STATUS_REVIEWED = ReportStatus.REVIEWED
REPORT_STATUS_RESOLVED = ReportStatus.RESOLVED
REPORT_STATUS_WITHDRAWN = ReportStatus.WITHDRAWN

ACTIVE_REPORT_STATUSES = {
    REPORT_STATUS_PENDING,
    REPORT_STATUS_REVIEWED,
}


# ============================================================================
# CREATE
# ============================================================================


def create_report(
    db: Session,
    *,
    item: Item,
    reporter_id: int,
    reason: str,
    description: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Report:
    """
    Create a report against an item.

    Business rules:

    - Item must exist.
    - Reporter cannot report their own item.
    - Reason must not be empty.
    - Description must not be empty.
    - Reporter cannot already have an active report against
      the same item.
    - Report starts as pending.
    - Report creation is audited.

    The reporter ID must come from the authenticated user.
    """

    if item.user_id == reporter_id:
        raise PermissionError(
            "You cannot report your own item."
        )

    normalized_reason = reason.strip()

    if not normalized_reason:
        raise ValueError(
            "Report reason cannot be empty."
        )

    normalized_description = description.strip()

    if not normalized_description:
        raise ValueError(
            "Report description cannot be empty."
        )

    existing_report = get_active_report_by_user_and_item(
        db,
        reporter_id=reporter_id,
        item_id=item.id,
    )

    if existing_report is not None:
        raise ValueError(
            "You already have an active report for this item."
        )

    report = repository_create_report(
        db,
        item_id=item.id,
        reporter_id=reporter_id,
        reason=normalized_reason,
        description=normalized_description,
    )

    create_audit_log(
        db,
        event_type=AUDIT_ADMIN_ACTION,
        success=True,
        description=(
            f"Report {report.id} created for item {item.id}."
        ),
        user_id=reporter_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return report


# ============================================================================
# READ — SINGLE REPORT
# ============================================================================


def get_report(
    db: Session,
    *,
    report_id: int,
) -> Report | None:
    """
    Retrieve a report by ID.
    """

    return get_report_by_id(
        db,
        report_id,
    )


# ============================================================================
# READ — USER REPORTS
# ============================================================================


def list_user_reports(
    db: Session,
    *,
    reporter_id: int,
) -> list[Report]:
    """
    Retrieve reports belonging to the authenticated user.
    """

    return get_reports_by_user(
        db,
        reporter_id=reporter_id,
    )


# ============================================================================
# READ — ITEM REPORTS
# ============================================================================


def list_item_reports(
    db: Session,
    *,
    item_id: int,
) -> list[Report]:
    """
    Retrieve reports associated with an item.

    Authorization for who may view these reports belongs to
    the router/service boundary.
    """

    return get_reports_by_item(
        db,
        item_id=item_id,
    )


# ============================================================================
# READ — PENDING REPORTS
# ============================================================================


def list_pending_reports(
    db: Session,
) -> list[Report]:
    """
    Retrieve pending reports for moderator/admin review.

    Moderator/admin authorization must be enforced by the caller.
    """

    return get_pending_reports(db)


# ============================================================================
# READ — REVIEWED REPORTS
# ============================================================================


def list_reviewed_reports(
    db: Session,
) -> list[Report]:
    """
    Retrieve reviewed reports awaiting resolution.

    Moderator/admin authorization must be enforced by the caller.
    """

    return get_reviewed_reports(db)


# ============================================================================
# WITHDRAW
# ============================================================================


def withdraw_report(
    db: Session,
    *,
    report: Report,
    reporter_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Report:
    """
    Withdraw a pending report submitted by the authenticated reporter.

    Business rules:

    - Only the reporter who created the report may withdraw it.
    - Only pending reports may be withdrawn.
    - Reviewed and resolved reports cannot be withdrawn.
    - Withdrawn reports remain available in report history.
    - Withdrawal removes the report from the active-report workflow.
    - The withdrawal is audited.

    The reporter ID must come from the authenticated user.
    """

    if report.reporter_id != reporter_id:
        raise PermissionError(
            "You can only withdraw your own reports."
        )

    if report.status != REPORT_STATUS_PENDING:
        raise ValueError(
            "Only pending reports can be withdrawn."
        )

    updated_report = repository_update_report(
        db,
        report,
        status=REPORT_STATUS_WITHDRAWN,
    )

    create_audit_log(
        db,
        event_type=AUDIT_ADMIN_ACTION,
        success=True,
        description=(
            f"Report {report.id} withdrawn."
        ),
        user_id=reporter_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return updated_report


# ============================================================================
# REVIEW
# ============================================================================


def review_report(
    db: Session,
    *,
    report: Report,
    reviewer_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Report:
    """
    Mark a pending report as reviewed.

    Only pending reports may be reviewed.

    A moderator or administrator cannot review a report
    that they submitted themselves.

    The caller is responsible for ensuring that reviewer_id
    belongs to an authorized moderator or administrator.
    """

    if report.status != REPORT_STATUS_PENDING:
        raise ValueError(
            "Only pending reports can be reviewed."
        )

    if report.reporter_id == reviewer_id:
        raise PermissionError(
            "You cannot moderate your own report."
        )

    reviewed_at = datetime.now(timezone.utc)

    updated_report = repository_update_report(
        db,
        report,
        status=REPORT_STATUS_REVIEWED,
        reviewed_by=reviewer_id,
        reviewed_at=reviewed_at,
    )

    create_audit_log(
        db,
        event_type=AUDIT_ADMIN_ACTION,
        success=True,
        description=(
            f"Report {report.id} reviewed."
        ),
        user_id=reviewer_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return updated_report


# ============================================================================
# RESOLVE
# ============================================================================


def resolve_report(
    db: Session,
    *,
    report: Report,
    reviewer_id: int,
    resolution_note: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Report:
    """
    Resolve a reviewed report.

    A resolution note is mandatory for accountability.

    Only reviewed reports may be resolved.

    A moderator or administrator cannot resolve a report
    that they originally submitted themselves.

    The caller is responsible for ensuring that reviewer_id
    belongs to an authorized moderator or administrator.
    """

    if report.status != REPORT_STATUS_REVIEWED:
        raise ValueError(
            "Only reviewed reports can be resolved."
        )

    if report.reporter_id == reviewer_id:
        raise PermissionError(
            "You cannot moderate your own report."
        )

    normalized_note = resolution_note.strip()

    if not normalized_note:
        raise ValueError(
            "Resolution note cannot be empty."
        )

    updated_report = repository_update_report(
        db,
        report,
        status=REPORT_STATUS_RESOLVED,
        reviewed_by=reviewer_id,
        resolution_note=normalized_note,
    )

    create_audit_log(
        db,
        event_type=AUDIT_ADMIN_ACTION,
        success=True,
        description=(
            f"Report {report.id} resolved."
        ),
        user_id=reviewer_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return updated_report
