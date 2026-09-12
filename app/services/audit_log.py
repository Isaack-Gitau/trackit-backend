"""
TRACKIT Audit Logging Service.

Provides centralized creation of security and system audit logs.

Security principles:

- Never store passwords.
- Never store JWTs.
- Never store password-reset tokens.
- Never store email-verification tokens.
- Never store authentication secrets.
- Keep audit records structured and consistent.
- Support anonymous events where no user is authenticated.
"""

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


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
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.add(audit_log)
    db.flush()

    return audit_log