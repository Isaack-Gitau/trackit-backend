"""
TRACKIT Item Service.

Business logic for item creation, retrieval, updates,
deletion, and moderation.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.item import Item
from app.repositories.items import (
    IMAGE_UNSET,
    create_item as repository_create_item,
    delete_item as repository_delete_item,
    get_item_by_id as repository_get_item_by_id,
    get_items as repository_get_items,
    get_items_by_user as repository_get_items_by_user,
    get_public_items as repository_get_public_items,
    update_item as repository_update_item,
    update_item_status as repository_update_item_status,
)
from app.services.audit_log import (
    AUDIT_ADMIN_ACTION,
    create_audit_log,
)
from app.services.match import generate_matches_for_item
from app.services.notification import (
    NOTIFICATION_ITEM_APPROVED,
    create_notification,
    notify_match_found,
)
from app.utils.images import ImageUploadError, delete_stored_image


def _delete_stored_image_safely(
    storage_key: str | None,
) -> None:
    """
    Best-effort cleanup for a stored image.

    Cleanup failures must never hide the original application error.
    """

    if not storage_key:
        return

    try:
        delete_stored_image(storage_key)
    except ImageUploadError:
        pass


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

    Newly-created items begin in the repository/model's default
    moderation state.
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


def get_item(
    db: Session,
    *,
    item_id: int,
) -> Item | None:
    """Return an item by ID."""

    return repository_get_item_by_id(
        db,
        item_id,
    )


def get_public_item(
    db: Session,
    *,
    item_id: int,
) -> Item | None:
    """
    Return an item only when it is publicly visible.

    Pending and rejected items are never exposed through the public
    item lookup.
    """

    item = repository_get_item_by_id(
        db,
        item_id,
    )

    if item is None:
        return None

    if item.status not in {"approved", "claimed"}:
        return None

    return item


def list_public_items(
    db: Session,
    *,
    search: str | None = None,
    item_type: str | None = None,
    category: str | None = None,
    location: str | None = None,
    page: int = 1,
    limit: int = 20,
) -> list[Item]:
    """Return paginated publicly visible items."""

    if page < 1:
        raise ValueError("Page must be at least 1.")

    if limit < 1:
        raise ValueError("Limit must be at least 1.")

    if limit > 100:
        raise ValueError("Limit must not exceed 100.")

    offset = (page - 1) * limit

    return repository_get_public_items(
        db,
        search=search,
        item_type=item_type,
        category=category,
        location=location,
        offset=offset,
        limit=limit,
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
    """Return paginated items for administrative/internal use."""

    if page < 1:
        raise ValueError("Page must be at least 1.")

    if limit < 1:
        raise ValueError("Limit must be at least 1.")

    if limit > 100:
        raise ValueError("Limit must not exceed 100.")

    offset = (page - 1) * limit

    return repository_get_items(
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
    """Return all items owned by a user."""

    return repository_get_items_by_user(
        db,
        user_id=user_id,
    )


def list_items_for_admin(
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
    """Return paginated items for administrator review."""

    return list_items(
        db,
        search=search,
        item_type=item_type,
        category=category,
        location=location,
        status=status,
        page=page,
        limit=limit,
    )


def _has_substantive_change(
    item: Item,
    *,
    title: str | None,
    description: str | None,
    item_type: str | None,
    category: str | None,
    location: str | None,
    image: str | None | object,
) -> bool:
    """
    Determine whether an update changes information that requires
    moderation again.

    IMAGE_UNSET means that the image field was not supplied.
    """

    if title is not None and title != item.title:
        return True

    if description is not None and description != item.description:
        return True

    if item_type is not None and item_type != item.type:
        return True

    if category is not None and category != item.category:
        return True

    if location is not None and location != item.location:
        return True

    if image is not IMAGE_UNSET and image != item.image:
        return True

    return False


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
    image: str | None | object = IMAGE_UNSET,
) -> Item:
    """
    Update an item owned by the current user.

    Substantive changes to approved or rejected items return the item
    to pending moderation and clear previous moderation metadata.

    Claimed items cannot be modified.
    """

    if item.user_id != user_id:
        raise PermissionError(
            "You are not authorized to update this item."
        )

    if item.status == "claimed":
        raise PermissionError(
            "Claimed items cannot be modified."
        )

    if item_type is not None and item_type not in {"lost", "found"}:
        raise ValueError(
            "Item type must be 'lost' or 'found'."
        )

    substantive_change = _has_substantive_change(
        item,
        title=title,
        description=description,
        item_type=item_type,
        category=category,
        location=location,
        image=image,
    )

    old_image = item.image
    previous_status = item.status

    updated_item = repository_update_item(
        db,
        item,
        title=title,
        description=description,
        item_type=item_type,
        category=category,
        location=location,
        image=image,
    )

    if (
        substantive_change
        and previous_status in {"approved", "rejected"}
    ):
        updated_item = repository_update_item_status(
            db,
            updated_item,
            status="pending",
            rejection_reason=None,
            reviewed_by=None,
            reviewed_at=None,
        )

    if (
        image is not IMAGE_UNSET
        and image != old_image
        and old_image is not None
    ):
        _delete_stored_image_safely(old_image)

    return updated_item


def delete_item(
    db: Session,
    *,
    item: Item,
    user_id: int,
) -> None:
    """
    Delete an item owned by the current user.

    Claimed items cannot be deleted because they may have
    associated claim, match, report, and comment records.
    """

    if item.user_id != user_id:
        raise PermissionError(
            "You are not authorized to delete this item."
        )

    if item.status == "claimed":
        raise PermissionError(
            "Claimed items cannot be deleted."
        )

    stored_image = item.image

    repository_delete_item(
        db,
        item,
    )

    _delete_stored_image_safely(stored_image)


def _resolve_reviewer_id(
    *,
    reviewer_id: int | None,
    admin_user_id: int | None,
) -> int:
    """
    Resolve the administrator ID used for moderation.

    reviewer_id is the preferred name. admin_user_id is retained as a
    compatibility alias for existing callers.
    """

    if (
        reviewer_id is not None
        and admin_user_id is not None
        and reviewer_id != admin_user_id
    ):
        raise ValueError(
            "reviewer_id and admin_user_id must refer to the same administrator."
        )

    resolved_id = (
        reviewer_id
        if reviewer_id is not None
        else admin_user_id
    )

    if resolved_id is None:
        raise ValueError(
            "A reviewer_id is required."
        )

    return resolved_id


def approve_item(
    db: Session,
    *,
    item: Item,
    reviewer_id: int | None = None,
    admin_user_id: int | None = None,
) -> Item:
    """
    Approve a pending item.

    Approval performs the complete moderation workflow:

    1. Mark the item approved.
    2. Record reviewer metadata.
    3. Notify the item owner.
    4. Write an administrator audit log.
    5. Generate qualifying matches.
    6. Notify the owners involved in those matches.

    This function never creates a claim automatically.
    """

    if item.status != "pending":
        raise ValueError(
            "Only pending items can be approved."
        )

    resolved_reviewer_id = _resolve_reviewer_id(
        reviewer_id=reviewer_id,
        admin_user_id=admin_user_id,
    )

    reviewed_at = datetime.now(timezone.utc)

    approved_item = repository_update_item_status(
        db,
        item,
        status="approved",
        rejection_reason=None,
        reviewed_by=resolved_reviewer_id,
        reviewed_at=reviewed_at,
    )

    create_notification(
        db,
        user_id=approved_item.user_id,
        notification_type=NOTIFICATION_ITEM_APPROVED,
        title="Item Approved",
        message=(
            f'Your item "{approved_item.title}" '
            "has been approved and is now visible to other users."
        ),
        entity_type="item",
        entity_id=approved_item.id,
    )

    create_audit_log(
        db,
        event_type=AUDIT_ADMIN_ACTION,
        success=True,
        description=(
            f"Item {approved_item.id} approved by administrator."
        ),
        user_id=resolved_reviewer_id,
    )

    matches = generate_matches_for_item(
        db,
        item=approved_item,
    )

    for match in matches:
        notify_match_found(
            db,
            match=match,
        )

    return approved_item


def reject_item(
    db: Session,
    *,
    item: Item,
    reviewer_id: int | None = None,
    admin_user_id: int | None = None,
    rejection_reason: str | None = None,
    reason: str | None = None,
) -> Item:
    """
    Reject a pending item.

    rejection_reason is the preferred argument name. reason is retained
    as a compatibility alias for existing callers.
    """

    if item.status != "pending":
        raise ValueError(
            "Only pending items can be rejected."
        )

    resolved_reviewer_id = _resolve_reviewer_id(
        reviewer_id=reviewer_id,
        admin_user_id=admin_user_id,
    )

    if (
        rejection_reason is not None
        and reason is not None
        and rejection_reason.strip() != reason.strip()
    ):
        raise ValueError(
            "rejection_reason and reason must contain the same reason."
        )

    resolved_reason = (
        rejection_reason
        if rejection_reason is not None
        else reason
    )

    if resolved_reason is None:
        raise ValueError(
            "Rejection reason is required."
        )

    resolved_reason = resolved_reason.strip()

    if not resolved_reason:
        raise ValueError(
            "Rejection reason is required."
        )

    reviewed_at = datetime.now(timezone.utc)

    return repository_update_item_status(
        db,
        item,
        status="rejected",
        rejection_reason=resolved_reason,
        reviewed_by=resolved_reviewer_id,
        reviewed_at=reviewed_at,
    )
