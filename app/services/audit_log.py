"""
TRACKIT Audit Logging Service.

Provides centralized creation and administrative listing of
security and system audit logs.

Security principles:

- Never store passwords.
- Never store JWTs.
- Never store password-reset tokens.
- Never store email-verification tokens.
- Never store authentication secrets.
- Keep audit records structured and consistent.
- Support anonymous events where no user is authenticated.
- Administrative listing does not expose IP addresses or user-agent
  strings through the normal audit-log response.
"""

from collections.abc import Iterator
from datetime import datetime
from typing import TypedDict

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.repositories.audit_logs import (
    count_audit_logs,
    get_audit_logs,
    iter_audit_logs,
)


# ============================================================================
# AUDIT EVENT TYPES
# ============================================================================

AUDIT_LOGIN_SUCCESS = "login_success"
AUDIT_LOGIN_FAILURE = "login_failure"

AUDIT_REGISTER_SUCCESS = "register_success"
AUDIT_REGISTER_FAILURE = "register_failure"

AUDIT_EMAIL_VERIFICATION_SUCCESS = "email_verification_success"
AUDIT_EMAIL_VERIFICATION_FAILURE = "email_verification_failure"

AUDIT_PASSWORD_RESET_REQUEST = "password_reset_request"
AUDIT_PASSWORD_RESET_SUCCESS = "password_reset_success"
AUDIT_PASSWORD_RESET_FAILURE = "password_reset_failure"

AUDIT_ACCOUNT_DISABLED = "account_disabled"
AUDIT_ACCOUNT_ENABLED = "account_enabled"

AUDIT_LOGOUT = "logout"

AUDIT_ITEM_CREATED = "item_created"
AUDIT_ITEM_UPDATED = "item_updated"
AUDIT_ITEM_DELETED = "item_deleted"

AUDIT_CLAIM_CREATED = "claim_created"
AUDIT_CLAIM_UPDATED = "claim_updated"

AUDIT_COMMENT_CREATED = "comment_created"
AUDIT_COMMENT_UPDATED = "comment_updated"
AUDIT_COMMENT_DELETED = "comment_deleted"
AUDIT_ADMIN_COMMENT_DELETED = "admin_comment_deleted"

AUDIT_ADMIN_ACTION = "admin_action"


AUDIT_ACTION_CATEGORIES = {
    AUDIT_LOGIN_SUCCESS: "authentication",
    AUDIT_LOGIN_FAILURE: "authentication",
    AUDIT_REGISTER_SUCCESS: "authentication",
    AUDIT_REGISTER_FAILURE: "authentication",
    AUDIT_EMAIL_VERIFICATION_SUCCESS: "authentication",
    AUDIT_EMAIL_VERIFICATION_FAILURE: "authentication",
    AUDIT_PASSWORD_RESET_REQUEST: "authentication",
    AUDIT_PASSWORD_RESET_SUCCESS: "authentication",
    AUDIT_PASSWORD_RESET_FAILURE: "authentication",
    AUDIT_ACCOUNT_DISABLED: "account",
    AUDIT_ACCOUNT_ENABLED: "account",
    AUDIT_LOGOUT: "account",
    AUDIT_ITEM_CREATED: "items",
    AUDIT_ITEM_UPDATED: "items",
    AUDIT_ITEM_DELETED: "items",
    AUDIT_CLAIM_CREATED: "claims",
    AUDIT_CLAIM_UPDATED: "claims",
    AUDIT_COMMENT_CREATED: "comments",
    AUDIT_COMMENT_UPDATED: "comments",
    AUDIT_COMMENT_DELETED: "comments",
    AUDIT_ADMIN_COMMENT_DELETED: "comments",
    AUDIT_ADMIN_ACTION: "administration",
}


def get_audit_actions_for_category(
    category: str | None,
) -> list[str]:
    """
    Return all known audit actions assigned to a category.

    Unknown and blank categories return an empty list.

    The ``other`` category is intentionally handled separately by
    repository filtering because it represents actions outside the
    known category mapping.
    """

    if not isinstance(category, str):
        return []

    normalized_category = category.strip()

    if not normalized_category or normalized_category == "other":
        return []

    return [
        action
        for action, action_category in AUDIT_ACTION_CATEGORIES.items()
        if action_category == normalized_category
    ]


def get_audit_action_category(action: str | None) -> str:
    """
    Return the application-level category for an audit action.

    Unknown or blank actions intentionally fall back to ``other`` so
    custom and future audit events remain valid.
    """

    if not isinstance(action, str):
        return "other"

    normalized_action = action.strip()

    if not normalized_action:
        return "other"

    return AUDIT_ACTION_CATEGORIES.get(
        normalized_action,
        "other",
    )


class AuditLogFilterSet(TypedDict):
    action: str | None
    category: str | None
    actions: list[str] | None
    exclude_actions: list[str] | None
    user_id: int | None
    user_ids: list[int] | None
    subject_user_id: int | None
    resource_type: str | None
    resource_id: int | None
    created_from: datetime | None
    created_to: datetime | None


def _prepare_audit_log_filters(
    *,
    action: str | None,
    category: str | None,
    user_id: int | None,
    user_ids: list[int] | None,
    subject_user_id: int | None,
    resource_type: str | None,
    resource_id: int | None,
    created_from: datetime | None,
    created_to: datetime | None,
) -> AuditLogFilterSet:
    """
    Normalize and validate shared administrative audit filters.

    This helper contains filter rules that must remain identical across
    paginated listings, previews, and exports.

    Pagination is intentionally excluded because listings and exports
    have different retrieval strategies.
    """

    normalized_action = (
        action.strip()
        if action is not None
        else None
    )

    if normalized_action == "":
        normalized_action = None

    if (
        normalized_action is not None
        and len(normalized_action) > 100
    ):
        raise ValueError(
            "Audit action cannot exceed 100 characters."
        )

    normalized_category = (
        category.strip().lower()
        if category is not None
        else None
    )

    if normalized_category == "":
        normalized_category = None

    valid_categories = set(
        AUDIT_ACTION_CATEGORIES.values()
    ) | {"other"}

    if (
        normalized_category is not None
        and normalized_category not in valid_categories
    ):
        raise ValueError(
            "Unknown audit-log category."
        )

    category_actions: list[str] | None = None
    category_exclude_actions: list[str] | None = None

    if normalized_category is not None:
        if normalized_category == "other":
            category_exclude_actions = list(
                AUDIT_ACTION_CATEGORIES
            )
        else:
            category_actions = get_audit_actions_for_category(
                normalized_category
            )

    normalized_resource_type = (
        resource_type.strip()
        if resource_type is not None
        else None
    )

    if normalized_resource_type == "":
        normalized_resource_type = None

    if (
        normalized_resource_type is not None
        and len(normalized_resource_type) > 100
    ):
        raise ValueError(
            "Resource type cannot exceed 100 characters."
        )

    if user_id is not None:
        if (
            not isinstance(user_id, int)
            or isinstance(user_id, bool)
        ):
            raise ValueError(
                "User ID must be a whole number."
            )

        if user_id < 1:
            raise ValueError(
                "User ID must be at least 1."
            )

    if user_ids is not None:
        if not isinstance(user_ids, list):
            raise ValueError(
                "User IDs must be provided as a list."
            )

        if not user_ids:
            raise ValueError(
                "User IDs cannot be empty."
            )

        normalized_user_ids: list[int] | None = []

        for candidate_user_id in user_ids:
            if (
                not isinstance(candidate_user_id, int)
                or isinstance(candidate_user_id, bool)
            ):
                raise ValueError(
                    "User IDs must be whole numbers."
                )

            if candidate_user_id < 1:
                raise ValueError(
                    "User IDs must be at least 1."
                )

            if candidate_user_id not in normalized_user_ids:
                normalized_user_ids.append(candidate_user_id)

    else:
        normalized_user_ids = None

    if (
        user_id is not None
        and normalized_user_ids is not None
    ):
        raise ValueError(
            "Use either user_id or user_ids, not both."
        )

    if subject_user_id is not None:
        if (
            not isinstance(subject_user_id, int)
            or isinstance(subject_user_id, bool)
        ):
            raise ValueError(
                "Subject user ID must be a whole number."
            )

        if subject_user_id < 1:
            raise ValueError(
                "Subject user ID must be at least 1."
            )

    if resource_id is not None:
        if (
            not isinstance(resource_id, int)
            or isinstance(resource_id, bool)
        ):
            raise ValueError(
                "Resource ID must be a whole number."
            )

        if resource_id < 1:
            raise ValueError(
                "Resource ID must be at least 1."
            )

    if created_from is not None and created_from.tzinfo is None:
        raise ValueError(
            "created_from must include a timezone."
        )

    if created_to is not None and created_to.tzinfo is None:
        raise ValueError(
            "created_to must include a timezone."
        )

    if (
        created_from is not None
        and created_to is not None
        and created_from >= created_to
    ):
        raise ValueError(
            "created_from must be earlier than created_to."
        )

    return {
        "action": normalized_action,
        "category": normalized_category,
        "actions": category_actions,
        "exclude_actions": category_exclude_actions,
        "user_id": user_id,
        "user_ids": normalized_user_ids,
        "subject_user_id": subject_user_id,
        "resource_type": normalized_resource_type,
        "resource_id": resource_id,
        "created_from": created_from,
        "created_to": created_to,
    }


# ============================================================================
# CREATE AUDIT LOG
# ============================================================================


def create_audit_log(
    db: Session,
    *,
    event_type: str,
    success: bool = True,
    description: str | None = None,
    user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: int | None = None,
    subject_user_id: int | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditLog:
    """
    Create an audit-log record.

    This function intentionally accepts only safe metadata.

    Do NOT pass:

    - passwords
    - JWTs
    - refresh tokens
    - verification tokens
    - password-reset tokens
    - secret keys
    - authorization headers

    The record is added to the current SQLAlchemy transaction.
    The caller controls when the transaction is committed.

    Args:
        db:
            Active SQLAlchemy session.

        event_type:
            Type of audit event being recorded.

        success:
            Whether the audited operation succeeded.

        description:
            Safe human-readable description of the event.

        user_id:
            ID of the authenticated user responsible for the event,
            when applicable. May be None for anonymous or automated
            system events.

        resource_type:
            Type of resource affected by the event, for example
            "user", "item", "claim", or "report".

        resource_id:
            ID of the affected resource, when applicable.

        ip_address:
            Request source IP address, when available.

        user_agent:
            Request user-agent string, when available.

        subject_user_id:
            ID of the user affected by the event, when applicable.
            This is distinct from user_id, which identifies the actor.

    Returns:
        The newly created AuditLog instance.

    Security note:

        Automated system actions should leave user_id as None when
        there is no authenticated human actor. The affected object
        should instead be represented by resource_type/resource_id.
    """

    audit_log = AuditLog(
        event_type=event_type,
        success=success,
        description=description,
        user_id=user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        subject_user_id=subject_user_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.add(audit_log)
    db.flush()

    return audit_log


# ============================================================================
# LIST AUDIT LOGS
# ============================================================================


def list_audit_logs_for_admin(
    db: Session,
    *,
    action: str | None = None,
    category: str | None = None,
    success: bool | None = None,
    user_id: int | None = None,
    user_ids: list[int] | None = None,
    subject_user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: int | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    page: int = 1,
    limit: int = 20,
) -> tuple[list[AuditLog], int]:
    """
    Retrieve a paginated administrative audit-log listing.

    Business rules:

    - Page numbers start at 1.
    - Limits must be between 1 and 100.
    - Action values are limited to the AuditLog action column size.
    - Resource types are limited to the AuditLog resource_type size.
    - User IDs and resource IDs must be positive when supplied.
    - Blank action/resource-type values are treated as no filter.
    - The returned total represents the complete filtered population,
      not just the current page.

    The operation performs database reads only and does not modify
    the transaction.
    """

    if not isinstance(page, int) or isinstance(page, bool):
        raise ValueError(
            "Page must be a whole number."
        )

    if page < 1:
        raise ValueError(
            "Page must be at least 1."
        )

    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ValueError(
            "Limit must be a whole number."
        )

    if limit < 1:
        raise ValueError(
            "Limit must be at least 1."
        )

    if limit > 100:
        raise ValueError(
            "Limit cannot exceed 100."
        )

    filters = _prepare_audit_log_filters(
        action=action,
        category=category,
        user_id=user_id,
        user_ids=user_ids,
        subject_user_id=subject_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        created_from=created_from,
        created_to=created_to,
    )

    offset = (page - 1) * limit

    audit_logs = get_audit_logs(
        db,
        action=filters["action"],
        actions=filters["actions"],
        exclude_actions=filters["exclude_actions"],
        success=success,
        user_id=filters["user_id"],
        user_ids=filters["user_ids"],
        subject_user_id=filters["subject_user_id"],
        resource_type=filters["resource_type"],
        resource_id=filters["resource_id"],
        created_from=filters["created_from"],
        created_to=filters["created_to"],
        offset=offset,
        limit=limit,
    )

    total = count_audit_logs(
        db,
        action=filters["action"],
        actions=filters["actions"],
        exclude_actions=filters["exclude_actions"],
        success=success,
        user_id=filters["user_id"],
        user_ids=filters["user_ids"],
        subject_user_id=filters["subject_user_id"],
        resource_type=filters["resource_type"],
        resource_id=filters["resource_id"],
        created_from=filters["created_from"],
        created_to=filters["created_to"],
    )

    return audit_logs, total

# ============================================================================
# PREVIEW AUDIT LOGS
# ============================================================================


def preview_audit_logs_for_admin(
    db: Session,
    *,
    action: str | None = None,
    category: str | None = None,
    success: bool | None = None,
    user_id: int | None = None,
    user_ids: list[int] | None = None,
    subject_user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: int | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> tuple[int, AuditLogFilterSet]:
    """
    Return the number of audit logs matching administrative filters.

    The same normalization and validation used by the paginated listing
    is applied here so previews and listings cannot silently diverge.

    The preview performs only a count query and does not retrieve
    individual audit-log records.

    Returns:
        A tuple containing the filtered total and the normalized
        shared filters.
    """

    filters = _prepare_audit_log_filters(
        action=action,
        category=category,
        user_id=user_id,
        user_ids=user_ids,
        subject_user_id=subject_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        created_from=created_from,
        created_to=created_to,
    )

    total = count_audit_logs(
        db,
        action=filters["action"],
        actions=filters["actions"],
        exclude_actions=filters["exclude_actions"],
        success=success,
        user_id=filters["user_id"],
        user_ids=filters["user_ids"],
        subject_user_id=filters["subject_user_id"],
        resource_type=filters["resource_type"],
        resource_id=filters["resource_id"],
        created_from=filters["created_from"],
        created_to=filters["created_to"],
    )

    return total, filters


# ============================================================================
# EXPORT AUDIT LOGS
# ============================================================================


def export_audit_logs_for_admin(
    db: Session,
    *,
    action: str | None = None,
    category: str | None = None,
    success: bool | None = None,
    user_id: int | None = None,
    user_ids: list[int] | None = None,
    subject_user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: int | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> Iterator[AuditLog]:
    """
    Return a streaming iterator for administrative audit-log exports.

    The same shared filter preparation used by listing and preview
    is applied before database rows are streamed.
    """

    filters = _prepare_audit_log_filters(
        action=action,
        category=category,
        user_id=user_id,
        user_ids=user_ids,
        subject_user_id=subject_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        created_from=created_from,
        created_to=created_to,
    )

    return iter_audit_logs(
        db,
        action=filters["action"],
        actions=filters["actions"],
        exclude_actions=filters["exclude_actions"],
        success=success,
        user_id=filters["user_id"],
        user_ids=filters["user_ids"],
        subject_user_id=filters["subject_user_id"],
        resource_type=filters["resource_type"],
        resource_id=filters["resource_id"],
        created_from=filters["created_from"],
        created_to=filters["created_to"],
    )
