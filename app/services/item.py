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
    update_item_status as repository_update_item_status,
)

from app.services.audit_log import (
    AUDIT_ADMIN_ACTION,
    create_audit_log
)

# ============================================================================
# ITEM STATUS
# ============================================================================

ITEM_STATUS_PENDING = "pending"
ITEM_STATUS_APPROVED = "approved"
ITEM_STATUS_REJECTED = "rejected"
ITEM_STATUS_CLAIMED = "claimed"

ITEM_MODERATABLE_STATUS = ITEM_STATUS_PENDING


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

# ============================================================================
# MODERATION
# ============================================================================


def approve_item(
    db: Session,
    *,
    item: Item,
    reviewer_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Item:
    """
    Approve a pending item.

    Business rules:

    - Only pending items may be approved.
    - Reviewer identity comes from the authenticated administrator.
    - Approval is audited.
    """

    if item.status != ITEM_STATUS_PENDING:
        raise ValueError(
            "Only pending items can be approved."
        )

    updated_item = repository_update_item_status(
        db,
        item,
        status=ITEM_STATUS_APPROVED,
    )

    create_audit_log(
        db,
        event_type=AUDIT_ADMIN_ACTION,
        success=True,
        description=(
            f"Item {item.id} approved by administrator."
        ),
        user_id=reviewer_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return updated_item


def reject_item(
    db: Session,
    *,
    item: Item,
    reviewer_id: int,
    rejection_reason: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Item:
    """
    Reject a pending item.

    Business rules:

    - Only pending items may be rejected.
    - Rejection requires a reason.
    - Reviewer identity comes from the authenticated administrator.
    - Rejection is audited.
    """

    if item.status != ITEM_STATUS_PENDING:
        raise ValueError(
            "Only pending items can be rejected."
        )

    normalized_reason = rejection_reason.strip()

    if not normalized_reason:
        raise ValueError(
            "Rejection reason cannot be empty."
        )

    updated_item = repository_update_item_status(
        db,
        item,
        status=ITEM_STATUS_REJECTED,
    )

    create_audit_log(
        db,
        event_type=AUDIT_ADMIN_ACTION,
        success=True,
        description=(
            f"Item {item.id} rejected by administrator. "
            f"Reason: {normalized_reason}"
        ),
        user_id=reviewer_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return updated_item