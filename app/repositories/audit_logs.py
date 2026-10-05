"""
TRACKIT Audit Log Repository.

Provides database-access functions for AuditLog entities.

Responsibilities:

- Retrieve paginated audit logs.
- Count audit logs matching administrative filters.
- Eagerly load the optional actor relationship.

Business rules and filter validation belong in the service layer.
Sensitive request metadata such as IP addresses and user-agent
strings are intentionally not transformed or exposed here.
"""

from collections.abc import Iterator
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.audit_log import AuditLog


# ============================================================================
# AUDIT LOG LISTING
# ============================================================================


def get_audit_logs(
    db: Session,
    *,
    action: str | None = None,
    actions: list[str] | None = None,
    exclude_actions: list[str] | None = None,
    success: bool | None = None,
    user_id: int | None = None,
    user_ids: list[int] | None = None,
    subject_user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: int | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    offset: int = 0,
    limit: int = 20,
) -> list[AuditLog]:
    """
    Retrieve a paginated set of audit logs.

    Only database filtering, ordering, pagination, and relationship
    loading belong in this repository.

    Audit logs are ordered newest-first. ID is used as a secondary
    ordering key to keep ordering deterministic when timestamps match.

    Date filtering uses:

    - created_from: created_at >= created_from
    - created_to: created_at < created_to

    The exclusive upper bound makes it possible to represent complete
    calendar periods cleanly without relying on a final microsecond.
    """

    query = select(AuditLog).options(
        selectinload(AuditLog.user),
    )

    filters = []

    if action is not None:
        filters.append(AuditLog.action == action)

    if actions is not None:
        filters.append(AuditLog.action.in_(actions))

    if exclude_actions is not None:
        filters.append(~AuditLog.action.in_(exclude_actions))

    if success is not None:
        filters.append(AuditLog.success.is_(success))

    if user_id is not None:
        filters.append(AuditLog.user_id == user_id)

    if user_ids is not None:
        filters.append(AuditLog.user_id.in_(user_ids))

    if subject_user_id is not None:
        filters.append(
            AuditLog.subject_user_id == subject_user_id
        )

    if resource_type is not None:
        filters.append(
            AuditLog.resource_type == resource_type
        )

    if resource_id is not None:
        filters.append(
            AuditLog.resource_id == resource_id
        )

    if created_from is not None:
        filters.append(
            AuditLog.created_at >= created_from
        )

    if created_to is not None:
        filters.append(
            AuditLog.created_at < created_to
        )

    if filters:
        query = query.where(*filters)

    query = (
        query
        .order_by(
            AuditLog.created_at.desc(),
            AuditLog.id.desc(),
        )
        .offset(offset)
        .limit(limit)
    )

    result = db.execute(query)

    return list(result.scalars().all())


# -----------------------------------------------------------------------------


# ============================================================================
# AUDIT LOG STREAMING
# ============================================================================


def iter_audit_logs(
    db: Session,
    *,
    action: str | None = None,
    actions: list[str] | None = None,
    exclude_actions: list[str] | None = None,
    success: bool | None = None,
    user_id: int | None = None,
    user_ids: list[int] | None = None,
    subject_user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: int | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    batch_size: int = 500,
) -> Iterator[AuditLog]:
    """
    Stream audit logs matching the supplied filters.

    Results use the same filtering and newest-first deterministic ordering
    as the normal administrative listing, but without offset/limit
    pagination.

    Database results are consumed incrementally so large exports do not
    require materializing the full audit-log population in memory.
    """

    if batch_size < 1:
        raise ValueError(
            "batch_size must be at least 1."
        )

    query = select(AuditLog).options(
        selectinload(AuditLog.user),
    )

    filters = []

    if action is not None:
        filters.append(AuditLog.action == action)

    if actions is not None:
        filters.append(AuditLog.action.in_(actions))

    if exclude_actions is not None:
        filters.append(~AuditLog.action.in_(exclude_actions))

    if success is not None:
        filters.append(AuditLog.success.is_(success))

    if user_id is not None:
        filters.append(AuditLog.user_id == user_id)

    if user_ids is not None:
        filters.append(AuditLog.user_id.in_(user_ids))

    if subject_user_id is not None:
        filters.append(
            AuditLog.subject_user_id == subject_user_id
        )

    if resource_type is not None:
        filters.append(
            AuditLog.resource_type == resource_type
        )

    if resource_id is not None:
        filters.append(
            AuditLog.resource_id == resource_id
        )

    if created_from is not None:
        filters.append(
            AuditLog.created_at >= created_from
        )

    if created_to is not None:
        filters.append(
            AuditLog.created_at < created_to
        )

    if filters:
        query = query.where(*filters)

    query = query.order_by(
        AuditLog.created_at.desc(),
        AuditLog.id.desc(),
    )

    result = db.execute(
        query.execution_options(
            stream_results=True,
            yield_per=batch_size,
        )
    )

    yield from result.scalars().yield_per(batch_size)


# ============================================================================


def count_audit_logs(
    db: Session,
    *,
    action: str | None = None,
    actions: list[str] | None = None,
    exclude_actions: list[str] | None = None,
    success: bool | None = None,
    user_id: int | None = None,
    user_ids: list[int] | None = None,
    subject_user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: int | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> int:
    """
    Count audit logs matching the supplied filters.

    The count represents the complete filtered population rather
    than only the current page.
    """

    query = select(func.count(AuditLog.id))

    filters = []

    if action is not None:
        filters.append(AuditLog.action == action)

    if actions is not None:
        filters.append(AuditLog.action.in_(actions))

    if exclude_actions is not None:
        filters.append(~AuditLog.action.in_(exclude_actions))

    if success is not None:
        filters.append(AuditLog.success.is_(success))

    if user_id is not None:
        filters.append(AuditLog.user_id == user_id)

    if user_ids is not None:
        filters.append(AuditLog.user_id.in_(user_ids))

    if subject_user_id is not None:
        filters.append(
            AuditLog.subject_user_id == subject_user_id
        )

    if resource_type is not None:
        filters.append(
            AuditLog.resource_type == resource_type
        )

    if resource_id is not None:
        filters.append(
            AuditLog.resource_id == resource_id
        )

    if created_from is not None:
        filters.append(
            AuditLog.created_at >= created_from
        )

    if created_to is not None:
        filters.append(
            AuditLog.created_at < created_to
        )

    if filters:
        query = query.where(*filters)

    result = db.execute(query)

    return int(result.scalar_one())
