"""
TRACKIT Comment Service.

Business logic for creating, retrieving, updating, and deleting
comments attached to publicly visible item posts.

Architecture:

    Router
        ↓
    Authentication / Authorization
        ↓
    Comment Service
        ↓
    Comment Repository
        ↓
    Comment Model
        ↓
    PostgreSQL

Security principles:

- Comment ownership is determined from the persisted Comment.user_id.
- Clients cannot choose or change comment ownership.
- Only verified users may create comments.
- Comments may only be created on publicly visible items.
- Only the comment owner may edit or delete their own comment.
- Positive integer IDs are required.
- Comment content is treated as untrusted plain text.
- Whitespace-only comments are rejected.
- Content length is enforced before persistence.
- Authorization is enforced in the service layer rather than relying
  solely on router-level checks.
- Security-relevant mutations are auditable.
- Database persistence is delegated to the repository layer.
"""

from sqlalchemy.orm import Session

from app.models.comment import Comment
from app.models.item import Item

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


# ============================================================================
# INTERNAL VALIDATION HELPERS
# ============================================================================


def _validate_positive_id(
    value: int,
    *,
    field_name: str,
) -> None:
    """
    Validate an application/database identifier.

    IDs must always be positive integers. This prevents meaningless
    zero/negative identifiers from reaching repository queries.
    """

    if value <= 0:
        raise ValueError(
            f"{field_name} must be a positive integer."
        )


def _normalize_content(
    content: str,
) -> str:
    """
    Normalize and validate comment content.

    Content is treated as untrusted plain text.

    Leading and trailing whitespace is removed, while internal
    whitespace is preserved.

    HTML, JavaScript, or other markup is not interpreted here.
    Output encoding remains the responsibility of the presentation layer.
    """

    normalized_content = content.strip()

    if not normalized_content:
        raise ValueError(
            "Comment content cannot be empty."
        )

    if len(normalized_content) > COMMENT_MAX_LENGTH:
        raise ValueError(
            f"Comment content cannot exceed "
            f"{COMMENT_MAX_LENGTH} characters."
        )

    return normalized_content


def _get_public_item(
    db: Session,
    *,
    item_id: int,
) -> Item:
    """
    Retrieve an item that is publicly visible.

    Public comments must never expose or attach themselves to
    pending/rejected/private item posts.

    The service deliberately performs the visibility check here rather
    than trusting the router or repository.
    """

    _validate_positive_id(
        item_id,
        field_name="Item ID",
    )

    item = get_item_by_id(
        db,
        item_id,
    )

    if item is None:
        raise ValueError(
            "Item not found."
        )

    if item.status not in PUBLIC_ITEM_STATUSES:
        raise PermissionError(
            "Comments are only available for publicly visible items."
        )

    return item


# ============================================================================
# CREATE
# ============================================================================


def create_comment(
    db: Session,
    *,
    item_id: int,
    user_id: int,
    content: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Comment:
    """
    Create a comment on a publicly visible item.

    Business rules:

    - User ID must be positive.
    - Item must exist.
    - Item must be publicly visible.
    - Content cannot be empty.
    - Content cannot exceed COMMENT_MAX_LENGTH.
    - Comment ownership comes exclusively from user_id.
    - Creation is audited.

    The router/dependency layer is expected to require a verified
    authenticated user before calling this function.
    """

    _validate_positive_id(
        user_id,
        field_name="User ID",
    )

    item = _get_public_item(
        db,
        item_id=item_id,
    )

    normalized_content = _normalize_content(content)

    comment = repository_create_comment(
        db,
        item_id=item.id,
        user_id=user_id,
        content=normalized_content,
    )

    create_audit_log(
        db,
        event_type=AUDIT_COMMENT_CREATED,
        success=True,
        description=(
            f"Comment {comment.id} created on item {item.id}."
        ),
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
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

    Public visibility/authorization decisions for displaying the
    comment should be performed by the caller using the associated
    item state where appropriate.
    """

    _validate_positive_id(
        comment_id,
        field_name="Comment ID",
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

    Pending and rejected items are intentionally inaccessible through
    the public comment service.
    """

    item = _get_public_item(
        db,
        item_id=item_id,
    )

    return get_comments_by_item(
        db,
        item_id=item.id,
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
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Comment:
    """
    Update a comment owned by the authenticated user.

    Security rules:

    - User ID must be positive.
    - The comment must belong to the authenticated user.
    - Content is normalized and validated.
    - The client cannot change comment ownership.
    - The comment's item association cannot be changed.
    - The update is audited.

    Ownership is checked against the persisted comment record.
    """

    _validate_positive_id(
        user_id,
        field_name="User ID",
    )

    if comment.id is None or comment.id <= 0:
        raise ValueError(
            "Comment must be persisted before it can be updated."
        )

    if comment.user_id != user_id:
        raise PermissionError(
            "You are not authorized to edit this comment."
        )

    normalized_content = _normalize_content(content)

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
        ip_address=ip_address,
        user_agent=user_agent,
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
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """
    Delete a comment owned by the authenticated user.

    Security rules:

    - User ID must be positive.
    - The comment must belong to the authenticated user.
    - The client cannot delete another user's comment.
    - The item association cannot be changed.
    - The deletion is audited.

    Authorization is checked before the repository is allowed to
    perform the deletion.
    """

    _validate_positive_id(
        user_id,
        field_name="User ID",
    )

    if comment.id is None or comment.id <= 0:
        raise ValueError(
            "Comment must be persisted before it can be deleted."
        )

    if comment.user_id != user_id:
        raise PermissionError(
            "You are not authorized to delete this comment."
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
        ip_address=ip_address,
        user_agent=user_agent,
    )


# ============================================================================
# ADMIN DELETE
# ============================================================================


def admin_delete_comment(
    db: Session,
    *,
    comment: Comment,
    admin_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """
    Delete a comment as an administrator.

    Administrator authorization must be established by the router/
    dependency layer before this function is called.

    The service still validates the administrator ID and performs the
    mutation/audit itself so that administrative deletion cannot
    accidentally bypass the service layer.
    """

    _validate_positive_id(
        admin_id,
        field_name="Admin ID",
    )

    if comment.id is None or comment.id <= 0:
        raise ValueError(
            "Comment must be persisted before it can be deleted."
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
            f"Administrator {admin_id} deleted comment "
            f"{comment_id}."
        ),
        user_id=admin_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )
