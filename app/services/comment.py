"""
TRACKIT Comment Service.

Business logic for comments attached to publicly visible items.

Security principles:
- Comment authorship is derived from the authenticated user.
- Comment item ownership/visibility is derived from the route and database.
- Only verified users may create, edit, or delete comments.
- Public comments expose only safe author identity information.
- Author profile-picture visibility follows the user's public-profile
  privacy settings.
- Comment content is treated as untrusted plain text.
- Comment actions are audit logged.
"""

from sqlalchemy.orm import Session

from app.models.comment import Comment
from app.models.item import Item
from app.models.user import User

from app.repositories.comments import (
    create_comment as repository_create_comment,
    delete_comment as repository_delete_comment,
    get_comment_by_id,
    get_comments_by_item,
    update_comment as repository_update_comment,
)

from app.repositories.items import (
    get_item_by_id,
)

from app.services.audit_log import (
    AUDIT_ADMIN_COMMENT_DELETED,
    AUDIT_COMMENT_CREATED,
    AUDIT_COMMENT_DELETED,
    AUDIT_COMMENT_UPDATED,
    create_audit_log,
)


# ============================================================================
# CONSTANTS
# ============================================================================

COMMENT_MAX_LENGTH = 2000

PUBLIC_ITEM_STATUSES = {
    "approved",
    "claimed",
}


DEFAULT_PUBLIC_PROFILE_PRIVACY = {
    "profile_picture": True,
    "bio": True,
    "first_name": False,
    "last_name": False,
    "email": False,
    "phone_number": False,
    "social_links": False,
}


# ============================================================================
# VALIDATION HELPERS
# ============================================================================


def _validate_positive_id(
    value: int,
    field_name: str,
) -> None:
    """
    Ensure an ID is a positive integer.
    """

    if not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"{field_name} must be a positive integer."
        )


def _normalize_content(
    content: str,
) -> str:
    """
    Normalize and validate comment content.
    """

    if not isinstance(content, str):
        raise ValueError(
            "Comment content must be a string."
        )

    normalized = content.strip()

    if not normalized:
        raise ValueError(
            "Comment content cannot be empty."
        )

    if len(normalized) > COMMENT_MAX_LENGTH:
        raise ValueError(
            f"Comment content cannot exceed {COMMENT_MAX_LENGTH} characters."
        )

    return normalized


def _get_public_item(
    db: Session,
    item_id: int,
) -> Item:
    """
    Retrieve an item only when it is publicly visible.

    A nonexistent item is a bad request for the comments API and is
    represented as ValueError so the router returns HTTP 400.

    An existing but non-public item is deliberately represented as
    PermissionError so the router returns HTTP 403.
    """

    _validate_positive_id(
        item_id,
        "item_id",
    )

    item = get_item_by_id(
        db,
        item_id,
    )

    if item is None:
        raise ValueError(
            "Item not found."
        )

    item_status = (item.status or "").strip().lower()

    if item_status not in PUBLIC_ITEM_STATUSES:
        raise PermissionError(
            "Comments are only available for publicly visible items."
        )

    return item


# ============================================================================
# PUBLIC PROFILE PRIVACY
# ============================================================================


def _get_public_profile_privacy(
    user: User,
) -> dict[str, bool]:
    """
    Resolve the effective public-profile privacy settings for a user.

    This follows the same defaults and stored preference semantics used
    by the public-profile service.

    Invalid or missing preference values fall back to the documented
    TrackIt defaults.
    """

    privacy = dict(
        DEFAULT_PUBLIC_PROFILE_PRIVACY
    )

    preferences = user.preferences

    if not isinstance(preferences, dict):
        return privacy

    stored_privacy = preferences.get("privacy")

    if not isinstance(stored_privacy, dict):
        return privacy

    for field in DEFAULT_PUBLIC_PROFILE_PRIVACY:
        value = stored_privacy.get(field)

        if isinstance(value, bool):
            privacy[field] = value

    return privacy


# ============================================================================
# COMMENT RESPONSE SERIALIZATION
# ============================================================================


def serialize_comment(
    comment: Comment,
) -> dict[str, object]:
    """
    Convert a Comment ORM object into the public API representation.

    Only safe author identity information is exposed.

    The author's profile picture is included only when the author has
    enabled public visibility for that field.
    """

    author = comment.user

    if author is None:
        raise ValueError(
            "Comment author could not be loaded."
        )

    privacy = _get_public_profile_privacy(
        author,
    )

    return {
        "id": comment.id,
        "item_id": comment.item_id,
        "user_id": comment.user_id,
        "author": {
            "id": author.id,
            "username": author.username,
            "profile_picture": (
                author.profile_picture
                if privacy["profile_picture"]
                else None
            ),
        },
        "content": comment.content,
        "created_at": comment.created_at,
        "updated_at": comment.updated_at,
    }


# ============================================================================
# CREATE
# ============================================================================


def create_comment(
    db: Session,
    *,
    item_id: int,
    user_id: int,
    content: str,
) -> Comment:
    """
    Create a comment on a publicly visible item.
    """

    _validate_positive_id(
        item_id,
        "item_id",
    )

    _validate_positive_id(
        user_id,
        "user_id",
    )

    _get_public_item(
        db,
        item_id,
    )

    normalized_content = _normalize_content(
        content,
    )

    comment = repository_create_comment(
        db,
        item_id=item_id,
        user_id=user_id,
        content=normalized_content,
    )

    create_audit_log(
        db,
        event_type=AUDIT_COMMENT_CREATED,
        success=True,
        description=(
            f"Comment {comment.id} created on item {item_id}."
        ),
        user_id=user_id,
        resource_type="comment",
        resource_id=comment.id,
    )

    return comment


# ============================================================================
# READ — SINGLE COMMENT
# ============================================================================


def get_comment(
    db: Session,
    *,
    comment_id: int,
) -> Comment | None:
    """
    Retrieve a comment by ID.
    """

    _validate_positive_id(
        comment_id,
        "comment_id",
    )

    return get_comment_by_id(
        db,
        comment_id,
    )


# ============================================================================
# READ — ITEM COMMENTS
# ============================================================================


def list_item_comments(
    db: Session,
    *,
    item_id: int,
) -> list[Comment]:
    """
    Retrieve comments belonging to a publicly visible item.
    """

    _get_public_item(
        db,
        item_id,
    )

    return get_comments_by_item(
        db,
        item_id=item_id,
    )


# ============================================================================
# UPDATE
# ============================================================================


def update_comment(
    db: Session,
    *,
    comment: Comment,
    user_id: int,
    content: str,
) -> Comment:
    """
    Update a comment owned by the authenticated user.
    """

    _validate_positive_id(
        user_id,
        "user_id",
    )

    if comment.user_id != user_id:
        raise PermissionError(
            "You do not have permission to edit this comment."
        )

    normalized_content = _normalize_content(
        content,
    )

    updated_comment = repository_update_comment(
        db,
        comment,
        content=normalized_content,
    )

    create_audit_log(
        db,
        event_type=AUDIT_COMMENT_UPDATED,
        success=True,
        description=(
            f"Comment {comment.id} updated."
        ),
        user_id=user_id,
        resource_type="comment",
        resource_id=comment.id,
    )

    return updated_comment


# ============================================================================
# DELETE
# ============================================================================


def delete_comment(
    db: Session,
    *,
    comment: Comment,
    user_id: int,
) -> None:
    """
    Delete a comment owned by the authenticated user.
    """

    _validate_positive_id(
        user_id,
        "user_id",
    )

    if comment.user_id != user_id:
        raise PermissionError(
            "You do not have permission to delete this comment."
        )

    comment_id = comment.id

    repository_delete_comment(
        db,
        comment,
    )

    create_audit_log(
        db,
        event_type=AUDIT_COMMENT_DELETED,
        success=True,
        description=(
            f"Comment {comment_id} deleted."
        ),
        user_id=user_id,
        resource_type="comment",
        resource_id=comment_id,
    )


# ============================================================================
# ADMIN DELETE
# ============================================================================


def admin_delete_comment(
    db: Session,
    *,
    comment: Comment,
    admin_id: int,
) -> None:
    """
    Delete any comment as an administrator.
    """

    _validate_positive_id(
        admin_id,
        "admin_id",
    )

    comment_id = comment.id

    repository_delete_comment(
        db,
        comment,
    )

    create_audit_log(
        db,
        event_type=AUDIT_ADMIN_COMMENT_DELETED,
        success=True,
        description=(
            f"Comment {comment_id} deleted by administrator."
        ),
        user_id=admin_id,
        resource_type="comment",
        resource_id=comment_id,
    )