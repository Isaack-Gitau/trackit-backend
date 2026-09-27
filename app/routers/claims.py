"""
TRACKIT Claim API Router.

Provides endpoints for:

- creating claims against found items
- viewing the authenticated user's claims
- viewing individual claims
- withdrawing pending claims
- moderator and administrator claim review
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
from app.schemas.claim import (
    ClaimCreate,
    ClaimReject,
    ClaimResponse,
    ModerationClaimResponse,
)
from app.services.claim import (
    approve_claim,
    create_claim,
    get_claim,
    list_pending_claims,
    list_user_claims,
    reject_claim,
    withdraw_claim,
)


# ============================================================================
# ROUTER
# ============================================================================

router = APIRouter(
    prefix="/claims",
    tags=["Claims"],
)


# ============================================================================
# CREATE CLAIM
# ============================================================================


@router.post(
    "/items/{item_id}",
    response_model=ClaimResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Claim a found item",
)
def create_claim_endpoint(
    item_id: int,
    payload: ClaimCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Submit a claim against a found item.

    The claimant identity is taken from the authenticated JWT.
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
        return create_claim(
            db,
            item=item,
            claimant_id=current_user.id,
            reason=payload.reason,
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
# MY CLAIMS
# ============================================================================


@router.get(
    "/me",
    response_model=list[ClaimResponse],
    summary="List the authenticated user's claims",
)
def list_my_claims_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Return all claims submitted by the authenticated user.
    """

    return list_user_claims(
        db,
        claimant_id=current_user.id,
    )


# ============================================================================
# GET CLAIM
# ============================================================================


@router.get(
    "/{claim_id}",
    response_model=ClaimResponse,
    summary="Get a claim",
)
def get_claim_endpoint(
    claim_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Retrieve a claim.

    Claimants may view their own claims.
    Moderators and administrators may view any claim.
    """

    claim = get_claim(
        db,
        claim_id=claim_id,
    )

    if claim is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Claim not found.",
        )

    user_role = (current_user.role or "").strip().lower()

    if (
        claim.claimant_id != current_user.id
        and user_role not in {"moderator", "admin"}
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to view this claim.",
        )

    return claim


# ============================================================================
# WITHDRAW CLAIM
# ============================================================================


@router.post(
    "/{claim_id}/withdraw",
    response_model=ClaimResponse,
    summary="Withdraw a pending claim",
)
def withdraw_claim_endpoint(
    claim_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Withdraw the authenticated user's pending claim.
    """

    claim = get_claim(
        db,
        claim_id=claim_id,
    )

    if claim is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Claim not found.",
        )

    try:
        return withdraw_claim(
            db,
            claim=claim,
            claimant_id=current_user.id,
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
# MODERATOR / ADMIN: LIST PENDING CLAIMS
# ============================================================================


@router.get(
    "/admin/pending",
    response_model=list[ModerationClaimResponse],
    summary="List pending claims for moderation",
)
def list_pending_claims_endpoint(
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
):
    """
    Return pending claims awaiting moderation.

    Both moderators and administrators are authorized.

    Moderation responses expose only the claimant's ID and
    username. Private profile and contact information is not exposed.
    """

    return list_pending_claims(db)


# ============================================================================
# MODERATOR / ADMIN: APPROVE CLAIM
# ============================================================================


@router.patch(
    "/admin/{claim_id}/approve",
    response_model=ModerationClaimResponse,
    summary="Approve a pending claim",
)
def approve_claim_endpoint(
    claim_id: int,
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
):
    """
    Approve a pending claim.

    Both moderators and administrators are authorized.

    Moderation responses expose only the claimant's ID and
    username. Private profile and contact information is not exposed.
    """

    claim = get_claim(
        db,
        claim_id=claim_id,
    )

    if claim is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Claim not found.",
        )

    try:
        return approve_claim(
            db,
            claim=claim,
            reviewer_id=current_moderator.id,
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
# MODERATOR / ADMIN: REJECT CLAIM
# ============================================================================


@router.patch(
    "/admin/{claim_id}/reject",
    response_model=ModerationClaimResponse,
    summary="Reject a pending claim",
)
def reject_claim_endpoint(
    claim_id: int,
    payload: ClaimReject,
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
):
    """
    Reject a pending claim.

    Both moderators and administrators are authorized.
    A rejection reason is required.

    Moderation responses expose only the claimant's ID and
    username. Private profile and contact information is not exposed.
    """

    claim = get_claim(
        db,
        claim_id=claim_id,
    )

    if claim is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Claim not found.",
        )

    try:
        return reject_claim(
            db,
            claim=claim,
            reviewer_id=current_moderator.id,
            rejection_reason=payload.rejection_reason,
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
