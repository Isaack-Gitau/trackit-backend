
"""
TRACKIT Authentication Token Service.

Responsible for secure, short-lived, single-use tokens used by
authentication flows such as:

- Email verification
- Password reset

Security principles:

- Raw tokens are generated with Python's cryptographically secure
  secrets module.
- Only SHA-256 token hashes are stored in PostgreSQL.
- Raw tokens are never persisted.
- Tokens are single-use.
- Expired tokens cannot be consumed.
- Previous unused tokens of the same type are invalidated.
- Token operations are scoped to the owning user.

Transaction policy:

- This service does NOT commit transactions.
- The request/database boundary owns commit and rollback behavior.
- Security-sensitive multi-step operations can therefore remain atomic.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.auth_token import AuthToken


# ============================================================================
# TOKEN TYPES
# ============================================================================


EMAIL_VERIFICATION_TOKEN_TYPE = "email_verification"
PASSWORD_RESET_TOKEN_TYPE = "password_reset"


ALLOWED_TOKEN_TYPES = {
    EMAIL_VERIFICATION_TOKEN_TYPE,
    PASSWORD_RESET_TOKEN_TYPE,
}


# ============================================================================
# TOKEN LIFETIMES
# ============================================================================


EMAIL_VERIFICATION_TOKEN_MINUTES = 30
PASSWORD_RESET_TOKEN_MINUTES = 15


# ============================================================================
# INTERNAL HELPERS
# ============================================================================


def _utc_now() -> datetime:
    """
    Return the current timezone-aware UTC datetime.
    """

    return datetime.now(timezone.utc)


def _validate_token_type(token_type: str) -> None:
    """
    Ensure that only supported authentication token types are used.
    """

    if token_type not in ALLOWED_TOKEN_TYPES:
        raise ValueError(
            "Unsupported authentication token type."
        )


# ============================================================================
# TOKEN GENERATION
# ============================================================================


def generate_raw_token() -> str:
    """
    Generate a cryptographically secure authentication token.

    64 random bytes provide a very large token space.

    Returns:
        A URL-safe random token.
    """

    return secrets.token_urlsafe(64)


def hash_token(raw_token: str) -> str:
    """
    Hash a raw authentication token using SHA-256.

    The raw token must never be stored in the database.

    Returns:
        A hexadecimal SHA-256 digest.
    """

    if not raw_token:
        raise ValueError(
            "Authentication token cannot be empty."
        )

    return hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()


# ============================================================================
# TOKEN CREATION
# ============================================================================


def create_auth_token(
    db: Session,
    *,
    user_id: int,
    token_type: str,
    expires_minutes: int,
) -> str:
    """
    Create a new authentication token.

    Previous unused tokens of the same type belonging to the
    user are invalidated before the new token is created.

    The database transaction is intentionally NOT committed here.

    The caller/request transaction owns commit and rollback behavior.

    Args:
        db: Active SQLAlchemy database session.
        user_id: ID of the token owner.
        token_type: Supported authentication token type.
        expires_minutes: Lifetime of the token in minutes.

    Returns:
        Raw authentication token.

    Security:
        Only the SHA-256 token hash is stored in PostgreSQL.
    """

    if user_id <= 0:
        raise ValueError(
            "Invalid user ID."
        )

    _validate_token_type(token_type)

    if expires_minutes <= 0:
        raise ValueError(
            "Token expiration must be greater than zero."
        )

    # Invalidate previous unused tokens of this type.
    invalidate_user_tokens(
        db,
        user_id=user_id,
        token_type=token_type,
    )

    raw_token = generate_raw_token()

    token_hash = hash_token(
        raw_token
    )

    expires_at = (
        _utc_now()
        + timedelta(minutes=expires_minutes)
    )

    auth_token = AuthToken(
        user_id=user_id,
        token_hash=token_hash,
        token_type=token_type,
        expires_at=expires_at,
        used_at=None,
    )

    db.add(auth_token)
    db.flush()

    return raw_token


# ============================================================================
# TOKEN LOOKUP
# ============================================================================


def get_valid_token(
    db: Session,
    *,
    raw_token: str,
    token_type: str,
) -> AuthToken | None:
    """
    Retrieve a valid authentication token.

    A token is valid only when:

    - the raw token is non-empty;
    - the token type is supported;
    - the SHA-256 hash matches;
    - the token has not been consumed;
    - the token has not expired.

    Returns:
        AuthToken when valid, otherwise None.
    """

    if not raw_token:
        return None

    _validate_token_type(
        token_type
    )

    normalized_token = raw_token.strip()

    if not normalized_token:
        return None

    token_hash = hash_token(
        normalized_token
    )

    statement = select(AuthToken).where(
        AuthToken.token_hash == token_hash,
        AuthToken.token_type == token_type,
        AuthToken.used_at.is_(None),
    )

    token = db.scalar(
        statement
    )

    if token is None:
        return None

    if token.expires_at <= _utc_now():
        return None

    return token


# ============================================================================
# TOKEN CONSUMPTION
# ============================================================================


def consume_token(
    db: Session,
    token: AuthToken,
) -> bool:
    """
    Atomically consume an authentication token.

    The update succeeds only when the token is still unused.

    This is important for concurrent password-reset or verification
    requests. Two requests can no longer both successfully consume
    the same token.

    The database transaction is intentionally NOT committed here.

    Returns:

        True:
            The token was consumed by this call.

        False:
            The token had already been consumed.
    """

    if token.used_at is not None:
        return False

    consumed_at = _utc_now()

    statement = (
        update(AuthToken)
        .where(
            AuthToken.id == token.id,
            AuthToken.used_at.is_(None),
        )
        .values(
            used_at=consumed_at,
        )
    )

    result = db.execute(
        statement
    )

    if result.rowcount != 1:
        return False

    # Keep the ORM instance synchronized with the database state.
    token.used_at = consumed_at

    return True


# ============================================================================
# TOKEN INVALIDATION
# ============================================================================


def invalidate_user_tokens(
    db: Session,
    *,
    user_id: int,
    token_type: str,
) -> int:
    """
    Invalidate all unused tokens of a specific type belonging
    to a user.

    The database transaction is intentionally NOT committed here.

    Returns:
        Number of tokens invalidated.
    """

    if user_id <= 0:
        raise ValueError(
            "Invalid user ID."
        )

    _validate_token_type(
        token_type
    )

    now = _utc_now()

    statement = (
        update(AuthToken)
        .where(
            AuthToken.user_id == user_id,
            AuthToken.token_type == token_type,
            AuthToken.used_at.is_(None),
        )
        .values(
            used_at=now,
        )
    )

    result = db.execute(
        statement
    )

    return int(
        result.rowcount or 0
    )


# ============================================================================
# USER TOKEN CLEANUP
# ============================================================================


def invalidate_all_user_tokens(
    db: Session,
    *,
    user_id: int,
) -> int:
    """
    Invalidate all unused authentication tokens belonging to a user.

    This is useful during security-sensitive operations such as:

    - password changes;
    - account deactivation;
    - security resets.

    The database transaction is intentionally NOT committed here.

    Returns:
        Number of tokens invalidated.
    """

    if user_id <= 0:
        raise ValueError(
            "Invalid user ID."
        )

    now = _utc_now()

    statement = (
        update(AuthToken)
        .where(
            AuthToken.user_id == user_id,
            AuthToken.used_at.is_(None),
        )
        .values(
            used_at=now,
        )
    )

    result = db.execute(
        statement
    )

    return int(
        result.rowcount or 0
    )


# ============================================================================
# TOKEN EXPIRATION CHECK
# ============================================================================


def is_token_expired(
    token: AuthToken,
) -> bool:
    """
    Determine whether an authentication token has expired.
    """

    return token.expires_at <= _utc_now()


# ============================================================================
# TOKEN CONSUMPTION CHECK
# ============================================================================


def is_token_consumed(
    token: AuthToken,
) -> bool:
    """
    Determine whether an authentication token has already
    been consumed.
    """

    return token.used_at is not None
