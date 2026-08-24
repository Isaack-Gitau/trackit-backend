
"""
TRACKIT Item API Routes.

HTTP endpoints for the lost-and-found item system.

Architecture:

    Request
        ↓
    Router
        ↓
    Authentication / Authorization
        ↓
    Pydantic Validation
        ↓
    Item Service
        ↓
    Item Repository
        ↓
    PostgreSQL

Security principles:
- Authenticated identity comes from the JWT.
- Clients cannot provide or override user_id.
- Verified accounts are required for item management.
- Ownership checks remain in the service layer.
- Public item browsing does not expose private account data.
- Request parameters are validated before reaching business logic.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import (
    get_current_admin,
    get_current_verified_user,
)

from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.item import (
    ItemCreate,
    ItemReject,
    ItemResponse,
    ItemUpdate,

)
from app.services.item import (
    approve_item,
    create_item,
    delete_item,
    get_item,
    list_items,
    list_user_items,
    reject_item,
    update_item,
)


router = APIRouter(
    prefix="/items",
    tags=["Items"],
)


# ============================================================================
# CREATE
# ============================================================================


@router.post(
    "",
    response_model=ItemResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a lost or found item",
)
def create_item_endpoint(
    payload: ItemCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Create a new lost or found item.

    The authenticated user automatically becomes the owner.

    user_id is deliberately NOT accepted from the request body.
    """

    return create_item(
        db,
        user_id=current_user.id,
        title=payload.title,
        description=payload.description,
        item_type=payload.type,
        category=payload.category,
        location=payload.location,
        image=payload.image,
    )


# ============================================================================
# LIST ITEMS
# ============================================================================


@router.get(
    "",
    response_model=list[ItemResponse],
    summary="List lost and found items",
)
def list_items_endpoint(
    search: str | None = Query(
        default=None,
        max_length=100,
        description="Search item title or description.",
    ),
    item_type: str | None = Query(
        default=None,
        alias="type",
        pattern="^(lost|found)$",
        description="Filter by item type.",
    ),
    category: str | None = Query(
        default=None,
        max_length=100,
        description="Filter by category.",
    ),
    location: str | None = Query(
        default=None,
        max_length=255,
        description="Filter by location.",
    ),
    item_status: str | None = Query(
        default=None,
        alias="status",
        pattern="^(pending|approved|rejected)$",
        description="Filter by moderation status.",
    ),
    page: int = Query(
        default=1,
        ge=1,
        description="Page number.",
    ),
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Number of items per page.",
    ),
    db: Session = Depends(get_db),
):
    """
    Retrieve lost/found items with filtering and pagination.

    Browsing items is public.

    Authentication is not required for this endpoint.
    """

    return list_items(
        db,
        search=search,
        item_type=item_type,
        category=category,
        location=location,
        status=item_status,
        page=page,
        limit=limit,
    )


# ============================================================================
# CURRENT USER ITEMS
# ============================================================================


@router.get(
    "/me/items",
    response_model=list[ItemResponse],
    summary="List the authenticated user's items",
)
def list_my_items_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Retrieve all items belonging to the authenticated user.

    The user identity comes from the authenticated JWT.
    """

    return list_user_items(
        db,
        user_id=current_user.id,
    )


# ============================================================================
# ADMIN MODERATION
# ============================================================================


@router.patch(
    "/{item_id}/approve",
    response_model=ItemResponse,
    summary="Approve an item",
)
def approve_item_endpoint(
    item_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """
    Approve a pending item.

    Administrator authorization is required.
    """

    item = get_item(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    try:
        return approve_item(
            db,
            item=item,
            reviewer_id=current_admin.id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.patch(
    "/{item_id}/reject",
    response_model=ItemResponse,
    summary="Reject an item",
)
def reject_item_endpoint(
    item_id: int,
    payload: ItemReject,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """
    Reject a pending item.

    Administrator authorization is required.
    A rejection reason is mandatory.
    """

    item = get_item(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    try:
        return reject_item(
            db,
            item=item,
            reviewer_id=current_admin.id,
            rejection_reason=payload.reason,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

# ============================================================================
# GET SINGLE ITEM
# ============================================================================


@router.get(
    "/{item_id}",
    response_model=ItemResponse,
    summary="Get an item",
)
def get_item_endpoint(
    item_id: int,
    db: Session = Depends(get_db),
):
    """
    Retrieve a single item by ID.
    """

    item = get_item(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    return item


# ============================================================================
# UPDATE
# ============================================================================


@router.patch(
    "/{item_id}",
    response_model=ItemResponse,
    summary="Update an owned item",
)
def update_item_endpoint(
    item_id: int,
    payload: ItemUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Update an item belonging to the authenticated user.

    Ownership authorization is enforced by the service layer.
    """

    item = get_item(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    try:
        return update_item(
            db,
            item=item,
            user_id=current_user.id,
            title=payload.title,
            description=payload.description,
            item_type=payload.type,
            category=payload.category,
            location=payload.location,
            image=payload.image,
        )

    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to modify this item.",
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


# ============================================================================
# DELETE
# ============================================================================


@router.delete(
    "/{item_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an owned item",
)
def delete_item_endpoint(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Delete an item belonging to the authenticated user.

    Ownership authorization is enforced by the service layer.
    """

    item = get_item(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    try:
        delete_item(
            db,
            item=item,
            user_id=current_user.id,
        )

    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to delete this item.",
        )

    return None

