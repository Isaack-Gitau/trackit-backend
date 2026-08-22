"""
TRACKIT Report Repository.

Database access layer for reports against items.

Business rules, authorization, and report lifecycle decisions
belong in the service layer.

This module is responsible only for querying and persisting
Report records.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.report import Report


# ============================================================================
# CREATE
# ============================================================================


def create_report(
    db: Session,
    *,
    item_id: int,
    reporter_id: int,
    reason: str,
    description: str,
) -> Report:
    """
    Create and persist a new report.

    The repository does not decide whether the reporter is
    allowed to report the item. That belongs to the service layer.
    """

    report = Report(
        item_id=item_id,
        reporter_id=reporter_id,
        reason=reason,
        description=description,
        status="pending",
    )

    db.add(report)
    db.flush()

    return report


# ============================================================================
# READ — SINGLE REPORT
# ============================================================================


def get_report_by_id(
    db: Session,
    report_id: int,
) -> Report | None:
    """
    Retrieve a report by its primary key.
    """

    return db.scalar(
        select(Report).where(Report.id == report_id)
    )


# ============================================================================
# READ — REPORTER
# ============================================================================


def get_reports_by_user(
    db: Session,
    *,
    reporter_id: int,
) -> list[Report]:
    """
    Retrieve all reports submitted by a specific user.

    Results are returned newest first.
    """

    statement = (
        select(Report)
        .where(Report.reporter_id == reporter_id)
        .order_by(Report.created_at.desc())
    )

    return list(db.scalars(statement).all())


# ============================================================================
# READ — ITEM
# ============================================================================


def get_reports_by_item(
    db: Session,
    *,
    item_id: int,
) -> list[Report]:
    """
    Retrieve all reports associated with an item.

    Results are returned newest first.
    """

    statement = (
        select(Report)
        .where(Report.item_id == item_id)
        .order_by(Report.created_at.desc())
    )

    return list(db.scalars(statement).all())


# ============================================================================
# READ — ACTIVE REPORT
# ============================================================================


def get_active_report_by_user_and_item(
    db: Session,
    *,
    reporter_id: int,
    item_id: int,
) -> Report | None:
    """
    Retrieve an existing active report submitted by a user
    against an item.

    Active states are:

        pending
        reviewed

    Resolved reports are historical and therefore do not
    prevent a future report unless the service layer imposes
    an additional business rule.
    """

    statement = (
        select(Report)
        .where(
            Report.reporter_id == reporter_id,
            Report.item_id == item_id,
            Report.status.in_(("pending", "reviewed")),
        )
        .order_by(Report.created_at.desc())
        .limit(1)
    )

    return db.scalar(statement)


# ============================================================================
# READ — PENDING REPORTS
# ============================================================================


def get_pending_reports(
    db: Session,
) -> list[Report]:
    """
    Retrieve all pending reports.

    Intended primarily for administrative review.
    """

    statement = (
        select(Report)
        .where(Report.status == "pending")
        .order_by(Report.created_at.asc())
    )

    return list(db.scalars(statement).all())


# ============================================================================
# READ — REVIEWED REPORTS
# ============================================================================


def get_reviewed_reports(
    db: Session,
) -> list[Report]:
    """
    Retrieve all reports currently marked as reviewed.

    Intended primarily for administrative workflows.
    """

    statement = (
        select(Report)
        .where(Report.status == "reviewed")
        .order_by(Report.reviewed_at.asc())
    )

    return list(db.scalars(statement).all())


# ============================================================================
# UPDATE — REPORT
# ============================================================================


def update_report(
    db: Session,
    report: Report,
    *,
    status: str | None = None,
    reviewed_by: int | None = None,
    reviewed_at=None,
    resolution_note: str | None = None,
) -> Report:
    """
    Update supplied report fields.

    Authorization and lifecycle validation must be performed
    by the service layer before this function is called.
    """

    if status is not None:
        report.status = status

    if reviewed_by is not None:
        report.reviewed_by = reviewed_by

    if reviewed_at is not None:
        report.reviewed_at = reviewed_at

    if resolution_note is not None:
        report.resolution_note = resolution_note

    db.flush()

    return report