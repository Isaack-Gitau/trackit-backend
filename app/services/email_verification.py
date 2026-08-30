"""
TRACKIT Email Verification Service.

Handles:

- Creating email verification tokens
- Validating verification tokens
- Verifying user accounts
- Resending verification tokens

Security principles:

- Raw tokens are never stored in PostgreSQL.
- Only SHA-256 token hashes are stored.
- Tokens are short-lived.
- Tokens are single-use.
- Previous unused verification tokens are invalidated.
- Token consumption is atomic.
"""

from sqlalchemy.orm import Session

from app.models.user import User
from app.services.tokens import (
    EMAIL_VERIFICATION_TOKEN_MINUTES,
    EMAIL_VERIFICATION_TOKEN_TYPE,
    consume_token,
    create_auth_token,
    get_valid_token,
)


# ============================================================================
# CREATE VERIFICATION TOKEN
# ============================================================================


def create_verification_token(
    db: Session,
    user: User,
) -> str:
    """
    Create a new email verification token.

    create_auth_token() already invalidates previous unused
    verification tokens, so duplicate invalidation is avoided.
    """

    return create_auth_token(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
        expires_minutes=EMAIL_VERIFICATION_TOKEN_MINUTES,
    )


# ============================================================================
# VERIFY EMAIL
# ============================================================================


def verify_email(
    db: Session,
    raw_token: str,
) -> User | None:
    """
    Verify a user's email using a valid verification token.

    Returns:
        User when verification succeeds.
        None when the token is invalid, expired, or already consumed.

    Token consumption is atomic and the transaction is intentionally
    left uncommitted so the caller can commit or roll back the entire
    operation.
    """

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    if token is None:
        return None

    user = db.get(
        User,
        token.user_id,
    )

    if user is None:
        return None

    # ------------------------------------------------------------------
    # Atomically consume the token
    # ------------------------------------------------------------------

    consumed = consume_token(
        db,
        token,
    )

    if not consumed:
        return None

    # ------------------------------------------------------------------
    # Verify account
    # ------------------------------------------------------------------

    if not user.is_verified:
        user.is_verified = True

        db.add(user)
        db.flush()

    return user
