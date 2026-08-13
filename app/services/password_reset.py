"""
TRACKIT Password Reset Service.

Handles:

- Creating password-reset tokens
- Validating password-reset tokens
- Retrieving the associated user
- Resetting user passwords
- Invalidating used/previous reset tokens

Security principles:

- Raw tokens are never stored in PostgreSQL.
- Only SHA-256 token hashes are persisted.
- Tokens are short-lived.
- Tokens are single-use.
- Previous unused reset tokens are invalidated.
- Password changes invalidate existing JWT sessions.
"""

from sqlalchemy.orm import Session

from app.core.security import validate_password_strength
from app.models.auth_token import AuthToken
from app.models.user import User
from app.services.tokens import (
    PASSWORD_RESET_TOKEN_MINUTES,
    PASSWORD_RESET_TOKEN_TYPE,
    consume_token,
    create_auth_token,
    get_valid_token,
    invalidate_user_tokens,
)
from app.services.user import change_user_password


# ============================================================================
# Create Password Reset Token
# ============================================================================


def create_password_reset_token(
    db: Session,
    user: User,
) -> str:
    """
    Create a new password-reset token for a user.

    Any previous unused password-reset tokens belonging
    to the user are invalidated first.

    Returns:
        Raw password-reset token.

    Security:
        Only the SHA-256 hash is stored in PostgreSQL.
    """

    invalidate_user_tokens(
        db,
        user_id=user.id,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    )

    return create_auth_token(
        db,
        user_id=user.id,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
        expires_minutes=PASSWORD_RESET_TOKEN_MINUTES,
    )


# ============================================================================
# Retrieve User From Reset Token
# ============================================================================


def get_password_reset_user(
    db: Session,
    raw_token: str,
) -> tuple[User, AuthToken] | None:
    """
    Validate a password-reset token and retrieve its user.

    Returns:

        (User, AuthToken)
            When the token is valid.

        None
            When the token is invalid, expired, consumed,
            or the associated user no longer exists.
    """

    token: AuthToken | None = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    )

    if token is None:
        return None

    user: User | None = db.get(
        User,
        token.user_id,
    )

    if user is None:
        return None

    return user, token


# ============================================================================
# Reset User Password
# ============================================================================


def reset_user_password(
    db: Session,
    *,
    raw_token: str,
    new_password: str,
) -> User | None:
    """
    Reset a user's password using a valid reset token.

    Security actions:

    - Validates the reset token.
    - Validates password strength.
    - Hashes the new password through the central security service.
    - Updates password_changed_at.
    - Increments token_version.
    - Invalidates existing JWT sessions.
    - Consumes the reset token.
    - Invalidates any other unused reset tokens.

    Returns:

        User
            When the password reset succeeds.

        None
            When the token is invalid or expired.
    """

    # ------------------------------------------------------------------
    # Validate password
    # ------------------------------------------------------------------

    validate_password_strength(new_password)

    # ------------------------------------------------------------------
    # Validate reset token
    # ------------------------------------------------------------------

    result = get_password_reset_user(
        db,
        raw_token,
    )

    if result is None:
        return None

    user, token = result

    # ------------------------------------------------------------------
    # Change password
    # ------------------------------------------------------------------

    user = change_user_password(
        db,
        user,
        new_password,
    )

    # ------------------------------------------------------------------
    # Consume the token
    # ------------------------------------------------------------------

    consume_token(
        db,
        token,
    )

    # ------------------------------------------------------------------
    # Invalidate any other unused reset tokens
    # ------------------------------------------------------------------

    invalidate_user_tokens(
        db,
        user_id=user.id,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    )

    return user