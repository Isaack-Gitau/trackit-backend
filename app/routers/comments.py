"""
TRACKIT Comment API Router.

Provides endpoints for:

- creating comments on publicly visible items
- viewing comments on publicly visible items
- viewing individual public comments
- editing owned comments
- deleting owned comments
- moderator/admin comment moderation

Security principles:

- Comment authorship always comes from the authenticated JWT.
- Clients cannot provide or override user_id.
- Clients cannot provide or override item_id during creation.
- Verified users are required to create, edit, or delete comments.
- Comment ownership is enforced by the service layer.
- Anonymous users may only read comments belonging to public items.
- Pending and rejected items are never publicly exposed through comments.
- Moderators and administrators may delete comments for moderation purposes.
- Comment content is validated as untrusted plain text.
- IDs are validated by the service layer.
- Comment-related actions are audit logged.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import (
    get_current_moderator,
    get_current_verified_user,
)
from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.comment import (
    CommentCreate,
    CommentResponse,
    CommentUpdate,
)
from app.services.comment import (
    admin_delete_comment,
    create_comment,
    delete_comment,
    get_comment,
    list_item_comments,
    serialize_comment,
    update_comment,
)


# ============================================================================
# ROUTER
# ============================================================================

router = APIRouter(
    tags=["Comments"],
)


# ============================================================================
# CREATE COMMENT
# ============================================================================


@router.post(
    "/items/{item_id}/comments",
    response_model=CommentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a comment on an item",
)
def create_comment_endpoint(
    item_id: int,
    payload: CommentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Create a comment on a publicly visible item.

    The authenticated user's ID comes exclusively from the JWT.
    The target item ID comes exclusively from the URL path.
    """

    try:
        comment = create_comment(
            db,
            item_id=item_id,
            user_id=current_user.id,
            content=payload.content,
        )

        return serialize_comment(
            comment,
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
# LIST ITEM COMMENTS
# ============================================================================


@router.get(
    "/items/{item_id}/comments",
    response_model=list[CommentResponse],
    summary="List comments for a public item",
)
def list_item_comments_endpoint(
    item_id: int,
    db: Session = Depends(get_db),
):
    """
    Return comments belonging to a publicly visible item.

    This endpoint intentionally does not require authentication.

    The service layer verifies that the target item exists and is
    publicly visible before returning any comments.
    """

    try:
        comments = list_item_comments(
            db,
            item_id=item_id,
        )

        return [
            serialize_comment(comment)
            for comment in comments
        ]

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
# GET COMMENT
# ============================================================================


@router.get(
    "/comments/{comment_id}",
    response_model=CommentResponse,
    summary="Get a public comment",
)
def get_comment_endpoint(
    comment_id: int,
    db: Session = Depends(get_db),
):
    """
    Retrieve an individual comment.

    A comment is publicly readable only when its associated item is
    publicly visible.

    This prevents comment IDs from being used to discover comments
    attached to pending or rejected items.
    """

    try:
        comment = get_comment(
            db,
            comment_id=comment_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    if comment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Comment not found.",
        )

    item = comment.item

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Comment not found.",
        )

    item_status = (item.status or "").strip().lower()

    if item_status not in {
        "approved",
        "claimed",
    }:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Comment not found.",
        )

    return serialize_comment(
        comment,
    )


# ============================================================================
# UPDATE COMMENT
# ============================================================================


@router.patch(
    "/comments/{comment_id}",
    response_model=CommentResponse,
    summary="Update your comment",
)
def update_comment_endpoint(
    comment_id: int,
    payload: CommentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Update a comment owned by the authenticated user.

    Ownership is checked by the service layer against the authenticated
    user's ID. A client cannot transfer ownership by modifying request data.
    """

    comment = get_comment(
        db,
        comment_id=comment_id,
    )

    if comment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Comment not found.",
        )

    try:
        updated_comment = update_comment(
            db,
            comment=comment,
            user_id=current_user.id,
            content=payload.content,
        )

        return serialize_comment(
            updated_comment,
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
# DELETE COMMENT
# ============================================================================


@router.delete(
    "/comments/{comment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete your comment",
)
def delete_comment_endpoint(
    comment_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Delete a comment owned by the authenticated user.

    Ownership is verified by the service layer.
    """

    comment = get_comment(
        db,
        comment_id=comment_id,
    )

    if comment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Comment not found.",
        )

    try:
        delete_comment(
            db,
            comment=comment,
            user_id=current_user.id,
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

    return None


# ============================================================================
# MODERATOR / ADMIN: DELETE COMMENT
# ============================================================================


@router.delete(
    "/admin/comments/{comment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a comment as moderator or administrator",
)
def admin_delete_comment_endpoint(
    comment_id: int,
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
):
    """
    Delete any comment as a moderator or administrator.

    Moderator/admin authorization is enforced by get_current_moderator().
    The service layer also records the administrative action in the
    audit log.
    """

    comment = get_comment(
        db,
        comment_id=comment_id,
    )

    if comment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Comment not found.",
        )

    try:
        admin_delete_comment(
            db,
            comment=comment,
            admin_id=current_moderator.id,
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

    return None
