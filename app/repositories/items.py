"""
TRACKIT Item Repository.

Database access layer for lost and found items.

Business rules and authorization decisions belong in the service layer.
This module is responsible only for querying and persisting Item records.
"""

from typing import Final

from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.item import Item


# ============================================================================
# UPDATE SENTINEL
# ============================================================================

IMAGE_UNSET: Final = object()


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
    Create a new item.

    The image value is expected to be a server-generated storage key
    produced by the image sanitization layer.
    """

    item = Item(
        user_id=user_id,
        title=title,
        description=description,
        type=item_type,
        category=category,
        location=location,
        image=image,
    )

    db.add(item)
    db.flush()

    return item


# ============================================================================
# READ — SINGLE ITEM
# ============================================================================


def get_item_by_id(
    db: Session,
    item_id: int,
) -> Item | None:
    """
    Retrieve an item by primary key.

    This function deliberately does not apply visibility rules.
    Public visibility belongs in the service layer.
    """

    return db.scalar(
        select(Item).where(
            Item.id == item_id,
        )
    )


def get_item_by_id_for_update(
    db: Session,
    item_id: int,
) -> Item | None:
    """
    Retrieve an item by primary key and lock its row for update.

    The lock is held until the current database transaction commits
    or rolls back. This is intended for operations that must serialize
    state changes involving a specific item.
    """

    return db.scalar(
        select(Item)
        .where(
            Item.id == item_id,
        )
        .with_for_update()
    )

# ============================================================================
# READ — USER ITEMS
# ============================================================================


def get_items_by_user(
    db: Session,
    *,
    user_id: int,
) -> list[Item]:
    """
    Retrieve all items belonging to a specific user.
    """

    statement = (
        select(Item)
        .where(
            Item.user_id == user_id,
        )
        .order_by(
            Item.created_at.desc(),
        )
    )

    return list(
        db.scalars(statement).all()
    )


# ============================================================================
# READ — PUBLIC ITEMS
# ============================================================================


def get_public_items(
    db: Session,
    *,
    search: str | None = None,
    item_type: str | None = None,
    category: str | None = None,
    location: str | None = None,
    offset: int = 0,
    limit: int = 20,
) -> list[Item]:
    """
    Retrieve publicly visible items.

    Only approved and claimed items are exposed.
    """

    statement = select(Item).where(
        Item.status.in_(
            [
                "approved",
                "claimed",
            ]
        )
    )

    if search:
        search_pattern = f"%{search}%"

        statement = statement.where(
            or_(
                Item.title.ilike(search_pattern),
                Item.description.ilike(search_pattern),
                Item.category.ilike(search_pattern),
                Item.location.ilike(search_pattern),
            )
        )

    if item_type:
        statement = statement.where(
            Item.type == item_type,
        )

    if category:
        statement = statement.where(
            Item.category.ilike(category),
        )

    if location:
        statement = statement.where(
            Item.location.ilike(location),
        )

    statement = (
        statement
        .order_by(
            Item.created_at.desc(),
        )
        .offset(offset)
        .limit(limit)
    )

    return list(
        db.scalars(statement).all()
    )


# ============================================================================
# READ — APPROVED ITEMS BY TYPE
# ============================================================================


def get_approved_items_by_type(
    db: Session,
    *,
    item_type: str,
) -> list[Item]:
    """
    Retrieve approved items of a specific type.

    Used by the matching service when generating potential matches.
    """

    statement = (
        select(Item)
        .where(
            Item.type == item_type,
            Item.status == "approved",
        )
        .order_by(
            Item.created_at.desc(),
        )
    )

    return list(
        db.scalars(statement).all()
    )


# ============================================================================
# READ — ALL ITEMS
# ============================================================================


def get_items(
    db: Session,
    *,
    search: str | None = None,
    item_type: str | None = None,
    category: str | None = None,
    location: str | None = None,
    status: str | None = None,
    offset: int = 0,
    limit: int = 20,
) -> list[Item]:
    """
    Retrieve items with optional filters.

    This is an unrestricted/internal query and may return items
    in any moderation status.
    """

    statement = select(Item)

    if search:
        search_pattern = f"%{search}%"

        statement = statement.where(
            or_(
                Item.title.ilike(search_pattern),
                Item.description.ilike(search_pattern),
                Item.category.ilike(search_pattern),
                Item.location.ilike(search_pattern),
            )
        )

    if item_type:
        statement = statement.where(
            Item.type == item_type,
        )

    if category:
        statement = statement.where(
            Item.category.ilike(category),
        )

    if location:
        statement = statement.where(
            Item.location.ilike(location),
        )

    if status:
        statement = statement.where(
            Item.status == status,
        )

    statement = (
        statement
        .order_by(
            Item.created_at.desc(),
        )
        .offset(offset)
        .limit(limit)
    )

    return list(
        db.scalars(statement).all()
    )


# ============================================================================
# UPDATE
# ============================================================================


def update_item(
    db: Session,
    item: Item,
    *,
    title: str | None = None,
    description: str | None = None,
    item_type: str | None = None,
    category: str | None = None,
    location: str | None = None,
    image: str | None | object = IMAGE_UNSET,
) -> Item:
    """
    Update an existing item.

    Image semantics:

        image=IMAGE_UNSET
            Leave the current image unchanged.

        image=None
            Explicitly remove the current image.

        image="items/..."
            Replace the current image with the supplied storage key.

    The service layer is responsible for authorization and for
    ensuring that supplied image storage keys were generated by
    the trusted image-processing layer.
    """

    if title is not None:
        item.title = title

    if description is not None:
        item.description = description

    if item_type is not None:
        item.type = item_type

    if category is not None:
        item.category = category

    if location is not None:
        item.location = location

    if image is not IMAGE_UNSET:
        item.image = image  # type: ignore[assignment]

    db.flush()

    return item


# ============================================================================
# UPDATE STATUS
# ============================================================================

def update_item_status(
    db: Session,
    item: Item,
    *,
    status: str,
    rejection_reason: str | None = None,
    reviewed_by: int | None = None,
    reviewed_at: datetime | None = None,
) -> Item:
    item.status = status
    item.rejection_reason = rejection_reason
    item.reviewed_by = reviewed_by
    item.reviewed_at = reviewed_at

    db.flush()
    db.refresh(item)

    return item

# ============================================================================
# DELETE
# ============================================================================


def delete_item(
    db: Session,
    item: Item,
) -> None:
    """
    Delete an item.

    Database cascade rules handle related records according
    to the Item model configuration.
    """

    db.delete(item)

    db.flush()
