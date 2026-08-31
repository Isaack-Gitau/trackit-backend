
"""
TRACKIT Item Service.

Business logic for creating, retrieving, updating,
deleting, and administratively moderating lost and
found items.

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

Security principles:

- Item ownership is based on the authenticated user.
- Clients cannot choose another user's identity.
- Only valid item types may be created or updated.
- New items always begin as pending.
- Only pending items may be approved or rejected.
- Rejection requires a reason.
- Administrator actions are audited.
- Item moderation events generate user notifications.
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
    create_audit_log,
)

from app.services.notification import (
    NOTIFICATION_ITEM_APPROVED,
    NOTIFICATION_ITEM_REJECTED,
    create_notification,
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

    Business rules:

    - Item type must be either 'lost' or 'found'.
    - New items always begin with pending status.
    - Persistence is delegated to the repository.
    """

    if item_type not in {"lost", "found"}:
        raise ValueError(
            "Item type must be 'lost' or 'found'."
        )

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
# READ — SINGLE ITEM
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


# ============================================================================
# READ — ALL ITEMS
# ============================================================================


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
    Retrieve items with optional filtering and pagination.

    Pagination is handled at the service boundary while
    actual database querying remains in the repository.
    """

    if page < 1:
        raise ValueError(
            "Page must be greater than or equal to 1."
        )

    if limit < 1 or limit > 100:
        raise ValueError(
            "Limit must be between 1 and 100."
        )

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


# ============================================================================
# READ — USER ITEMS
# ============================================================================


def list_user_items(
    db: Session,
    *,
    user_id: int,
) -> list[Item]:
    """
    Retrieve all items belonging to a specific user.

    The caller is responsible for ensuring that user_id
    represents the authenticated user.
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

    Business rules:

    - Only the item owner may modify the item.
    - Item type, when supplied, must be 'lost' or 'found'.
    - Unspecified fields remain unchanged.
    """

    if item.user_id != user_id:
        raise PermissionError(
            "You are not authorized to modify this item."
        )

    if item_type is not None and item_type not in {
        "lost",
        "found",
    }:
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

    Ownership authorization is enforced by the service layer.
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
# MODERATION — APPROVE
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
    - The approval action is audited.
    - The item owner receives an approval notification.
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

    create_notification(
        db,
        user_id=item.user_id,
        notification_type=NOTIFICATION_ITEM_APPROVED,
        title="Item approved",
        message=(
            f"Your {item.type} item "
            f"\"{item.title}\" has been approved."
        ),
        entity_type="item",
        entity_id=item.id,
    )

    return updated_item


# ============================================================================
# MODERATION — REJECT
# ============================================================================


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
    - Rejection requires a non-empty reason.
    - Reviewer identity comes from the authenticated administrator.
    - The rejection action is audited.
    - The item owner receives a rejection notification.
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

    create_notification(
        db,
        user_id=item.user_id,
        notification_type=NOTIFICATION_ITEM_REJECTED,
        title="Item rejected",
        message=(
            f"Your {item.type} item "
            f"\"{item.title}\" was rejected. "
            f"Reason: {normalized_reason}"
        ),
        entity_type="item",
        entity_id=item.id,

    )

    return updated_item
