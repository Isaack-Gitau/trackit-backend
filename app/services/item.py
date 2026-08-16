"""
TRACKIT Item Service.

Business logic for creating, retrieving, updating,
and deleting lost and found items.

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
"""

from sqlalchemy.orm import Session

from app.models.item import Item
from app.repositories.items import (
    create_item as repository_create_item,
    delete_item as repository_delete_item,
    get_item_by_id,
    get_items,
    get_items_by_user,
    update_item as repository_update_item,
)


# ============================================================================
# CREATE
# ============================================================================


def create_item(
    db: Session,
    *,
    user_id: int,
    title: str,
    description: str,
    item_type: str,
    category: str,
    location: str,
    image: str | None = None,
) -> Item:
    """
    Create a new TRACKIT item.

    New items always begin with pending status.
    """

    if item_type not in {"lost", "found"}:
        raise ValueError("Item type must be 'lost' or 'found'.")

    return repository_create_item(
        db,
        user_id=user_id,
        title=title,
        description=description,
        item_type=item_type,
        category=category,
        location=location,
        image=image,
    )


# ============================================================================
# READ
# ============================================================================


def get_item(
    db: Session,
    *,
    item_id: int,
) -> Item | None:
    """
    Retrieve an item by ID.
    """

    return get_item_by_id(
        db,
        item_id,
    )


def list_items(
    db: Session,
    *,
    search: str | None = None,
    item_type: str | None = None,
    category: str | None = None,
    location: str | None = None,
    status: str | None = None,
    page: int = 1,
    limit: int = 20,
) -> list[Item]:
    """
    Retrieve items with filtering and pagination.
    """

    if page < 1:
        raise ValueError("Page must be greater than or equal to 1.")

    if limit < 1 or limit > 100:
        raise ValueError("Limit must be between 1 and 100.")

    offset = (page - 1) * limit

    return get_items(
        db,
        search=search,
        item_type=item_type,
        category=category,
        location=location,
        status=status,
        offset=offset,
        limit=limit,
    )


def list_user_items(
    db: Session,
    *,
    user_id: int,
) -> list[Item]:
    """
    Retrieve all items belonging to a specific user.
    """

    return get_items_by_user(
        db,
        user_id=user_id,
    )


# ============================================================================
# UPDATE
# ============================================================================


def update_item(
    db: Session,
    *,
    item: Item,
    user_id: int,
    title: str | None = None,
    description: str | None = None,
    item_type: str | None = None,
    category: str | None = None,
    location: str | None = None,
    image: str | None = None,
) -> Item:
    """
    Update an item belonging to the authenticated user.

    Ownership is enforced here rather than in the repository.
    """

    if item.user_id != user_id:
        raise PermissionError(
            "You are not authorized to modify this item."
        )

    if item_type is not None and item_type not in {"lost", "found"}:
        raise ValueError(
            "Item type must be 'lost' or 'found'."
        )

    return repository_update_item(
        db,
        item,
        title=title,
        description=description,
        item_type=item_type,
        category=category,
        location=location,
        image=image,
    )


# ============================================================================
# DELETE
# ============================================================================


def delete_item(
    db: Session,
    *,
    item: Item,
    user_id: int,
) -> None:
    """
    Delete an item belonging to the authenticated user.
    """

    if item.user_id != user_id:
        raise PermissionError(
            "You are not authorized to delete this item."
        )

    repository_delete_item(
        db,
        item,
    )