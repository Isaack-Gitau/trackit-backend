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
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.auth_token import AuthToken


# ============================================================================
# Token Types
# ============================================================================

EMAIL_VERIFICATION_TOKEN_TYPE = "email_verification"
PASSWORD_RESET_TOKEN_TYPE = "password_reset"


ALLOWED_TOKEN_TYPES = {
    EMAIL_VERIFICATION_TOKEN_TYPE,
    PASSWORD_RESET_TOKEN_TYPE,
}


# ============================================================================
# Token Lifetimes
# ============================================================================

EMAIL_VERIFICATION_TOKEN_MINUTES = 30
PASSWORD_RESET_TOKEN_MINUTES = 15


# ============================================================================
# Internal Helpers
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
# Token Generation
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
# Token Creation
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

    Before creating the new token, all currently unused tokens
    of the same type belonging to the user are invalidated.

    Args:
        db: Active SQLAlchemy database session.
        user_id: ID of the token owner.
        token_type: Supported authentication token type.
        expires_minutes: Lifetime of the token in minutes.

    Returns:
        The raw token.

    Important:
        Only the SHA-256 hash is stored in PostgreSQL.
        The raw token is returned once to the caller.
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

    # Invalidate previous unused tokens of the same type.
    invalidate_user_tokens(
        db,
        user_id=user_id,
        token_type=token_type,
    )

    raw_token = generate_raw_token()
    token_hash = hash_token(raw_token)

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
    db.commit()
    db.refresh(auth_token)

    return raw_token


# ============================================================================
# Token Lookup
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

    - The raw token is non-empty.
    - The token type is supported.
    - The SHA-256 hash matches.
    - The token has not been consumed.
    - The token has not expired.

    Returns:
        The AuthToken object when valid, otherwise None.
    """

    if not raw_token:
        return None

    _validate_token_type(token_type)

    token_hash = hash_token(
        raw_token.strip()
    )

    result = db.execute(
        select(AuthToken).where(
            AuthToken.token_hash == token_hash,
            AuthToken.token_type == token_type,
            AuthToken.used_at.is_(None),
        )
    )

    token = result.scalar_one_or_none()

    if token is None:
        return None

    if token.expires_at <= _utc_now():
        return None

    return token


# ============================================================================
# Token Consumption
# ============================================================================


def consume_token(
    db: Session,
    token: AuthToken,
) -> None:
    """
    Permanently consume an authentication token.

    Once consumed, the token cannot be used again.
    """

    if token.used_at is not None:
        return

    token.used_at = _utc_now()

    db.add(token)
    db.commit()


# ============================================================================
# Token Invalidation
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

    Returns:
        Number of tokens invalidated.
    """

    if user_id <= 0:
        raise ValueError(
            "Invalid user ID."
        )

    _validate_token_type(token_type)

    result = db.execute(
        select(AuthToken).where(
            AuthToken.user_id == user_id,
            AuthToken.token_type == token_type,
            AuthToken.used_at.is_(None),
        )
    )

    tokens = result.scalars().all()

    if not tokens:
        return 0

    now = _utc_now()

    for token in tokens:
        token.used_at = now

    db.commit()

    return len(tokens)


# ============================================================================
# User Token Cleanup
# ============================================================================


def invalidate_all_user_tokens(
    db: Session,
    *,
    user_id: int,
) -> int:
    """
    Invalidate all unused authentication tokens belonging to a user.

    This is useful during security-sensitive operations such as:

    - Password changes
    - Account deactivation
    - Security resets
    """

    if user_id <= 0:
        raise ValueError(
            "Invalid user ID."
        )

    result = db.execute(
        select(AuthToken).where(
            AuthToken.user_id == user_id,
            AuthToken.used_at.is_(None),
        )
    )

    tokens = result.scalars().all()

    if not tokens:
        return 0

    now = _utc_now()

    for token in tokens:
        token.used_at = now

    db.commit()

    return len(tokens)


# ============================================================================
# Token Expiration Check
# ============================================================================


def is_token_expired(
    token: AuthToken,
) -> bool:
    """
    Determine whether an authentication token has expired.
    """

    return token.expires_at <= _utc_now()


def is_token_consumed(
    token: AuthToken,
) -> bool:
    """
    Determine whether an authentication token has already been consumed.
    """

    return token.used_at is not None