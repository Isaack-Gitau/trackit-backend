"""
TRACKIT Item Repository.

Database access layer for lost and found items.

Business rules and authorization decisions belong in the service layer.
This module is responsible only for querying and persisting Item records.
"""

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.item import Item


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
    Create and persist a new item.

    The repository does not decide whether the user is allowed
    to create the item. That belongs to the service layer.
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
    Retrieve an item by its primary key.
    """

    return db.scalar(
        select(Item).where(Item.id == item_id)
    )


# ============================================================================
# READ — OWNER
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
        .where(Item.user_id == user_id)
        .order_by(Item.created_at.desc())
    )

    return list(db.scalars(statement).all())


# ============================================================================
# SEARCH / FILTER / PAGINATION
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
    Retrieve items using optional filters and pagination.

    Search currently checks:
        - title
        - description
        - category
        - location

    Results are newest first.
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
            Item.type == item_type
        )

    if category:
        statement = statement.where(
            Item.category.ilike(category)
        )

    if location:
        statement = statement.where(
            Item.location.ilike(location)
        )

    if status:
        statement = statement.where(
            Item.status == status
        )

    statement = (
        statement
        .order_by(Item.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    return list(db.scalars(statement).all())


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
    image: str | None = None,
) -> Item:
    """
    Update supplied item fields.

    Authorization must be performed before this function is called.
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

    if image is not None:
        item.image = image

    db.flush()

    return item


# ============================================================================
# UPDATE — STATUS
# ============================================================================


def update_item_status(
    db: Session,
    item: Item,
    *,
    status: str,
) -> Item:
    """
    Update the status of an item.

    Authorization and business rules must be handled
    by the service layer.
    """

    item.status = status
    db.flush()

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

    Authorization must be handled by the service layer.
    """

    db.delete(item)
    db.flush()