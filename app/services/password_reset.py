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
- Password reset is performed as one database transaction.
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
# CREATE PASSWORD RESET TOKEN
# ============================================================================


def create_password_reset_token(
    db: Session,
    user: User,
) -> str:
    """
    Create a new password-reset token for a user.

    create_auth_token() already invalidates previous unused
    password-reset tokens, so invalidation is intentionally
    performed only once.

    Returns:
        Raw password-reset token.
    """

    return create_auth_token(
        db,
        user_id=user.id,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
        expires_minutes=PASSWORD_RESET_TOKEN_MINUTES,
    )


# ============================================================================
# RETRIEVE USER FROM RESET TOKEN
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

    token = get_valid_token(
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
# RESET USER PASSWORD
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
    - Changes the password.
    - Updates password_changed_at.
    - Increments token_version.
    - Invalidates existing JWT sessions.
    - Atomically consumes the reset token.
    - Invalidates any other unused reset tokens.

    Transaction behavior:

    This function does NOT commit.

    The password change, token consumption, and token invalidation
    remain part of the caller's transaction and therefore succeed
    or roll back together.
    """

    # ------------------------------------------------------------------
    # Validate password
    # ------------------------------------------------------------------

    validate_password_strength(
        new_password
    )

    # ------------------------------------------------------------------
    # Retrieve valid reset token
    # ------------------------------------------------------------------

    result = get_password_reset_user(
        db,
        raw_token,
    )

    if result is None:
        return None

    user, token = result

    # ------------------------------------------------------------------
    # Atomically consume token BEFORE changing password
    # ------------------------------------------------------------------

    consumed = consume_token(
        db,
        token,
    )

    if not consumed:
        return None

    # ------------------------------------------------------------------
    # Change password
    # ------------------------------------------------------------------

    user = change_user_password(
        db,
        user,
        new_password,
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
