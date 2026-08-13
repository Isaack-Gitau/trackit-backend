"""
TRACKIT Email Verification Service.

Handles:

- Creating email verification tokens
- Validating verification tokens
- Verifying user accounts
- Resending verification tokens

Raw tokens are never stored in PostgreSQL.
Only SHA-256 token hashes are stored.
"""

from sqlalchemy.orm import Session

from app.models.user import User
from app.services.tokens import (
    EMAIL_VERIFICATION_TOKEN_MINUTES,
    EMAIL_VERIFICATION_TOKEN_TYPE,
    consume_token,
    create_auth_token,
    get_valid_token,
    invalidate_user_tokens,
)


# ============================================================================
# Create verification token
# ============================================================================

def create_verification_token(
    db: Session,
    user: User,
) -> str:
    """
    Create a new email verification token.

    Any previous unused verification tokens for the
    same user are invalidated first.
    """

    invalidate_user_tokens(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    return create_auth_token(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
        expires_minutes=EMAIL_VERIFICATION_TOKEN_MINUTES,
    )


# ============================================================================
# Verify email
# ============================================================================

def verify_email(
    db: Session,
    raw_token: str,
) -> User | None:
    """
    Verify a user's email using a valid verification token.

    Returns:
        User when verification succeeds.
        None when the token is invalid or expired.
    """

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    if token is None:
        return None

    user = db.get(User, token.user_id)

    if user is None:
        return None

    if user.is_verified:
        consume_token(db, token)
        return user

    user.is_verified = True

    db.add(user)
    db.flush()

    consume_token(
        db,
        token,
    )

    return user