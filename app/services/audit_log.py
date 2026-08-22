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
    """

    audit_log = AuditLog(
        event_type=event_type,
        success=success,
        description=description,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.add(audit_log)
    db.flush()

    return audit_log