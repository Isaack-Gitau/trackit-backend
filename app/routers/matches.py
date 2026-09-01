"""
TRACKIT Match API Router.

Provides endpoints for:

- viewing matches involving the authenticated user's items
- viewing one authorized match
- viewing matches for one owned item
- dismissing a match
- restoring a dismissed match

Security principles:

- Every endpoint requires an authenticated, verified user.
- User identity always comes from the authentication context.
- Match ownership is enforced by the match service.
- Clients cannot create or modify match scoring information directly.
- An inaccessible match is returned as not found to avoid exposing
  another user's match information.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_verified_user
from app.db.dependencies import get_db
from app.models.user import User
from app.repositories.items import get_item_by_id
from app.schemas.match import MatchResponse
from app.services.match import (
    dismiss_match,
    get_found_item_matches,
    get_user_match,
    get_lost_item_matches,
    list_user_matches,
    restore_match,
)


router = APIRouter(
    prefix="/matches",
    tags=["Matches"],
)


# ============================================================================
# MATCH LISTING
# ============================================================================


@router.get(
    "",
    response_model=list[MatchResponse],
    summary="List matches for the authenticated user's items",
)
def list_my_matches_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    return list_user_matches(
        db,
        user_id=current_user.id,
    )


# ============================================================================
# SINGLE MATCH
# ============================================================================


@router.get(
    "/{match_id}",
    response_model=MatchResponse,
    summary="Get an authorized match",
)
def get_match_endpoint(
    match_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    match = get_user_match(
        db,
        match_id=match_id,
        user_id=current_user.id,
    )

    if match is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Match not found.",
        )

    return match


# ============================================================================
# ITEM MATCHES
# ============================================================================


@router.get(
    "/items/{item_id}",
    response_model=list[MatchResponse],
    summary="List matches for an owned item",
)
def list_item_matches_endpoint(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
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
        if item.type == "lost":
            return get_lost_item_matches(
                db,
                lost_item=item,
                user_id=current_user.id,
            )

        return get_found_item_matches(
            db,
            found_item=item,
            user_id=current_user.id,
        )

    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        ) from None

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


# ============================================================================
# DISMISS MATCH
# ============================================================================


@router.patch(
    "/{match_id}/dismiss",
    response_model=MatchResponse,
    summary="Dismiss an authorized match",
)
def dismiss_match_endpoint(
    match_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    match = get_user_match(
        db,
        match_id=match_id,
        user_id=current_user.id,
    )

    if match is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Match not found.",
        )

    return dismiss_match(
        db,
        match=match,
        user_id=current_user.id,
    )


# ============================================================================
# RESTORE MATCH
# ============================================================================


@router.patch(
    "/{match_id}/restore",
    response_model=MatchResponse,
    summary="Restore an authorized match",
)
def restore_match_endpoint(
    match_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    match = get_user_match(
        db,
        match_id=match_id,
        user_id=current_user.id,
    )

    if match is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Match not found.",
        )

    return restore_match(
        db,
        match=match,
        user_id=current_user.id,
    )