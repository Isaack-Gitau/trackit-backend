"""
TRACKIT Authentication & Security

Provides:

- Argon2id password hashing
- Password verification
- Password-strength validation
- JWT access-token generation
- JWT access-token validation
- JWT subject extraction

Sensitive configuration is loaded from app.core.config.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from jose import JWTError, jwt

from app.core.config import settings


# ============================================================================
# Password Security
# ============================================================================

password_hasher = PasswordHasher()


def validate_password_strength(password: str) -> None:
    """
    Validate TRACKIT password security requirements.

    Requirements:
    - At least 8 characters
    - At most 128 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character

    Raises:
        ValueError:
            If the password does not satisfy the requirements.
    """

    if len(password) < 8:
        raise ValueError(
            "Password must be at least 8 characters long."
        )

    if len(password) > 128:
        raise ValueError(
            "Password must not exceed 128 characters."
        )

    if not any(character.isupper() for character in password):
        raise ValueError(
            "Password must contain at least one uppercase letter."
        )

    if not any(character.islower() for character in password):
        raise ValueError(
            "Password must contain at least one lowercase letter."
        )

    if not any(character.isdigit() for character in password):
        raise ValueError(
            "Password must contain at least one number."
        )

    if not any(
        not character.isalnum()
        for character in password
    ):
        raise ValueError(
            "Password must contain at least one special character."
        )


def hash_password(password: str) -> str:
    """
    Hash a plain-text password using Argon2id.

    Plain-text passwords must never be stored in the database.
    """

    validate_password_strength(password)

    return password_hasher.hash(password)


def verify_password(
    password: str,
    password_hash: str,
) -> bool:
    """
    Verify a password against an existing Argon2 hash.

    Returns:
        True if the password matches.
        False otherwise.
    """

    try:
        return password_hasher.verify(
            password_hash,
            password,
        )

    except (
        VerificationError,
        InvalidHashError,
    ):
        return False


# ============================================================================
# JWT Access Tokens
# ============================================================================

def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a signed TRACKIT JWT access token.
    """

    payload = data.copy()

    now = datetime.now(timezone.utc)

    if expires_delta is None:
        expires_delta = timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    expire = now + expires_delta

    payload.update(
        {
            "iat": now,
            "exp": expire,
            "type": "access",
        }
    )

    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_access_token(
    token: str,
) -> dict[str, Any]:
    """
    Decode and validate a TRACKIT JWT access token.

    Raises:
        JWTError:
            If the token is invalid, expired, malformed,
            or has an invalid token type.
    """

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )

        token_type = payload.get("type")

        if token_type != "access":
            raise JWTError("Invalid token type.")

        subject = payload.get("sub")

        if subject is None:
            raise JWTError(
                "Token does not contain a subject."
            )

        return payload

    except JWTError:
        raise


# ============================================================================
# JWT Subject
# ============================================================================

def get_token_subject(
    token: str,
) -> str:
    """
    Extract the user ID from a valid JWT access token.
    """

    payload = decode_access_token(token)

    subject = payload.get("sub")

    if subject is None:
        raise JWTError(
            "Token does not contain a subject."
        )

    return str(subject)