
"""
TRACKIT Audit Service.

Provides a centralized and safe interface for recording
security and application audit events.

Security principles:

- Never store passwords.
- Never store password hashes.
- Never store JWTs.
- Never store verification tokens.
- Never store password-reset tokens.
- Limit request metadata to safe database sizes.
- Keep audit-event creation consistent across the application.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


# ============================================================================
# Constants
# ============================================================================

MAX_EVENT_TYPE_LENGTH = 100
MAX_DESCRIPTION_LENGTH = 5000
MAX_IP_ADDRESS_LENGTH = 45
MAX_USER_AGENT_LENGTH = 500


# ============================================================================
# Sanitization Helpers
# ============================================================================


def _sanitize_text(
    value: str | None,
    *,
    max_length: int,
) -> str | None:
    """
    Normalize optional text before storing it.

    Leading/trailing whitespace is removed and the value
    is truncated to the maximum supported database length.
    """

    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    return value[:max_length]


def _sanitize_event_type(
    event_type: str,
) -> str:
    """
    Normalize an audit-event type.

    Event types are intentionally kept compact and predictable.
    """

    normalized = event_type.strip().upper()

    if not normalized:
        raise ValueError(
            "Audit event type cannot be empty."
        )

    return normalized[:MAX_EVENT_TYPE_LENGTH]


# ============================================================================
# Audit Event Creation
# ============================================================================


def record_audit_event(
    db: Session,
    *,
    event_type: str,
    success: bool = True,
    description: str | None = None,
    user_id: int | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditLog:
    """
    Record a TRACKIT audit event.

    This function stores only security-relevant metadata.

    IMPORTANT:
        Callers must never place passwords, JWTs, authentication
        tokens, verification tokens, password-reset tokens, or
        other secrets inside `description`.

    Args:
        db:
            SQLAlchemy database session.

        event_type:
            Short identifier describing the event.

        success:
            Whether the event was successful.

        description:
            Safe human-readable description.

        user_id:
            Associated user ID when known.

        ip_address:
            Client IP address.

        user_agent:
            Client User-Agent header.

    Returns:
        The newly created AuditLog instance.

    Raises:
        ValueError:
            If the event type is empty.
    """

    normalized_event_type = _sanitize_event_type(
        event_type
    )

    audit_log = AuditLog(
        event_type=normalized_event_type,
        success=bool(success),
        description=_sanitize_text(
            description,
            max_length=MAX_DESCRIPTION_LENGTH,
        ),
        user_id=user_id,
        ip_address=_sanitize_text(
            ip_address,
            max_length=MAX_IP_ADDRESS_LENGTH,
        ),
        user_agent=_sanitize_text(
            user_agent,
            max_length=MAX_USER_AGENT_LENGTH,
        ),
    )

    db.add(audit_log)
    db.flush()

    return audit_log

