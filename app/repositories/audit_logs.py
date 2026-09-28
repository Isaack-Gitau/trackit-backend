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
    success: bool | None = None,
    user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: int | None = None,
    offset: int = 0,
    limit: int = 20,
) -> list[AuditLog]:
    """
    Retrieve a paginated set of audit logs.

    Only database filtering, ordering, pagination, and relationship
    loading belong in this repository.

    Audit logs are ordered newest-first. ID is used as a secondary
    ordering key to keep ordering deterministic when timestamps match.
    """

    query = select(AuditLog).options(
        selectinload(AuditLog.user),
    )

    filters = []

    if action is not None:
        filters.append(AuditLog.action == action)

    if success is not None:
        filters.append(AuditLog.success.is_(success))

    if user_id is not None:
        filters.append(AuditLog.user_id == user_id)

    if resource_type is not None:
        filters.append(
            AuditLog.resource_type == resource_type
        )

    if resource_id is not None:
        filters.append(
            AuditLog.resource_id == resource_id
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


def count_audit_logs(
    db: Session,
    *,
    action: str | None = None,
    success: bool | None = None,
    user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: int | None = None,
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

    if success is not None:
        filters.append(AuditLog.success.is_(success))

    if user_id is not None:
        filters.append(AuditLog.user_id == user_id)

    if resource_type is not None:
        filters.append(
            AuditLog.resource_type == resource_type
        )

    if resource_id is not None:
        filters.append(
            AuditLog.resource_id == resource_id
        )

    if filters:
        query = query.where(*filters)

    result = db.execute(query)

    return int(result.scalar_one())
