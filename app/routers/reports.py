
"""
TRACKIT Report API Router.

Provides endpoints for:

- creating reports against items
- viewing the authenticated user's reports
- viewing individual reports
- withdrawing pending reports
- administrative report review
- administrative report resolution
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import (
    get_current_moderator,
    get_current_verified_user,
)
from app.db.dependencies import get_db
from app.models.user import User
from app.repositories.items import get_item_by_id
from app.schemas.report import (
    ModerationReportResponse,
    ReportCreate,
    ReportResolve,
    ReportResponse,
)
from app.services.report import (
    create_report,
    get_report,
    list_pending_reports,
    list_reviewed_reports,
    list_user_reports,
    resolve_report,
    review_report,
    withdraw_report,
)


# ============================================================================
# ROUTER
# ============================================================================

router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)


# ============================================================================
# CREATE REPORT
# ============================================================================


@router.post(
    "/items/{item_id}",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Report an item",
)
def create_report_endpoint(
    item_id: int,
    payload: ReportCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Submit a report against an item.

    The reporter identity is taken from the authenticated JWT.
    """

    item = get_item_by_id(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    try:
        return create_report(
            db,
            item=item,
            reporter_id=current_user.id,
            reason=payload.reason,
            description=payload.description,
        )

    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


# ============================================================================
# MY REPORTS
# ============================================================================


@router.get(
    "/me",
    response_model=list[ReportResponse],
    summary="List the authenticated user's reports",
)
def list_my_reports_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Return all reports submitted by the authenticated user.
    """

    return list_user_reports(
        db,
        reporter_id=current_user.id,
    )


# ============================================================================
# GET REPORT
# ============================================================================


@router.get(
    "/{report_id}",
    response_model=ReportResponse,
    summary="Get a report",
)
def get_report_endpoint(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Retrieve a report.

    Only the reporter or an administrator may view it.
    """

    report = get_report(
        db,
        report_id=report_id,
    )

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found.",
        )

    user_role = (current_user.role or "").strip().lower()

    if (
        report.reporter_id != current_user.id
        and user_role != "admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to view this report.",
        )

    return report


# ============================================================================
# WITHDRAW REPORT
# ============================================================================


@router.post(
    "/{report_id}/withdraw",
    response_model=ReportResponse,
    summary="Withdraw a pending report",
)
def withdraw_report_endpoint(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Withdraw a pending report submitted by the authenticated user.
    """

    report = get_report(
        db,
        report_id=report_id,
    )

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found.",
        )

    try:
        return withdraw_report(
            db,
            report=report,
            reporter_id=current_user.id,
        )

    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


# ============================================================================
# MODERATOR / ADMIN: LIST PENDING REPORTS
# ============================================================================


@router.get(
    "/admin/pending",
    response_model=list[ModerationReportResponse],
    summary="List pending reports for review",
)
def list_pending_reports_endpoint(
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
):
    """
    Return pending reports awaiting moderator or administrator review.
    """

    return list_pending_reports(db)


# ============================================================================
# MODERATOR / ADMIN: LIST REVIEWED REPORTS
# ============================================================================


@router.get(
    "/admin/reviewed",
    response_model=list[ModerationReportResponse],
    summary="List reviewed reports awaiting resolution",
)
def list_reviewed_reports_endpoint(
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
):
    """
    Return reviewed reports awaiting moderator or administrator resolution.
    """

    return list_reviewed_reports(db)


# ============================================================================
# MODERATOR / ADMIN: REVIEW REPORT
# ============================================================================


@router.patch(
    "/admin/{report_id}/review",
    response_model=ModerationReportResponse,
    summary="Review a pending report",
)
def review_report_endpoint(
    report_id: int,
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
):
    """
    Mark a pending report as reviewed.

    Moderator or administrator authorization is required.
    """

    report = get_report(
        db,
        report_id=report_id,
    )

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found.",
        )

    try:
        return review_report(
            db,
            report=report,
            reviewer_id=current_moderator.id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


# ============================================================================
# MODERATOR / ADMIN: RESOLVE REPORT
# ============================================================================


@router.patch(
    "/admin/{report_id}/resolve",
    response_model=ModerationReportResponse,
    summary="Resolve a reviewed report",
)
def resolve_report_endpoint(
    report_id: int,
    payload: ReportResolve,
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
):
    """
    Resolve a reviewed report.

    Moderator or administrator authorization is required.
    A resolution note is required.
    """

    report = get_report(
        db,
        report_id=report_id,
    )

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found.",
        )

    try:
        return resolve_report(
            db,
            report=report,
            reviewer_id=current_moderator.id,
            resolution_note=payload.resolution_note,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

