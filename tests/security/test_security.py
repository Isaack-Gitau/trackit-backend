"""
TRACKIT Security Tests.

Tests:
- Argon2 password hashing
- Password verification
- Wrong password rejection
- Password strength validation
- JWT creation
- JWT decoding
- JWT subject extraction
- Invalid JWT rejection
"""

from datetime import timedelta

import pytest
from jose import JWTError

from app.core.security import (
    create_access_token,
    decode_access_token,
    get_token_subject,
    hash_password,
    validate_password_strength,
    verify_password,
)


# ============================================================================
# PASSWORD HASHING
# ============================================================================


def test_password_hashing():
    password = "Trackit@123"

    password_hash = hash_password(password)

    assert password_hash != password
    assert password_hash.startswith("$argon2id$")


def test_password_verification_success():
    password = "Trackit@123"

    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


def test_password_verification_failure():
    password_hash = hash_password("Trackit@123")

    assert verify_password("WrongPassword@123", password_hash) is False


def test_different_passwords_produce_different_hashes():
    password = "Trackit@123"

    hash_one = hash_password(password)
    hash_two = hash_password(password)

    assert hash_one != hash_two


# ============================================================================
# PASSWORD STRENGTH
# ============================================================================


def test_password_strength_accepts_valid_password():
    validate_password_strength("Trackit@123")


@pytest.mark.parametrize(
    "password",
    [
        "short",
        "password123",
        "Password123",
        "Password!",
    ],
)
def test_password_strength_rejects_weak_passwords(password):
    with pytest.raises(ValueError):
        validate_password_strength(password)


# ============================================================================
# JWT
# ============================================================================


def test_access_token_creation():
    token = create_access_token(
        {
            "sub": "123",
            "role": "user",
            "token_version": 0,
        }
    )

    assert isinstance(token, str)
    assert len(token) > 50


def test_access_token_decoding():
    token = create_access_token(
        {
            "sub": "123",
            "role": "user",
            "token_version": 0,
        }
    )

    payload = decode_access_token(token)

    assert payload["sub"] == "123"
    assert payload["role"] == "user"
    assert payload["token_version"] == 0
    assert payload["type"] == "access"


def test_access_token_subject():
    token = create_access_token(
        {
            "sub": "123",
            "role": "user",
            "token_version": 0,
        }
    )

    subject = get_token_subject(token)

    assert subject == "123"


def test_invalid_access_token_is_rejected():
    with pytest.raises(JWTError):
        decode_access_token("this-is-not-a-valid-jwt")


def test_non_access_token_is_rejected():
    token = create_access_token(
        {
            "sub": "123",
            "role": "user",
            "token_version": 0,
        }
    )

    # Create a modified payload by changing the token type.
    # This test verifies that decode_access_token enforces
    # the expected access-token type.
    from jose import jwt

    from app.core.config import settings

    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )

    payload["type"] = "refresh"

    modified_token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )

    with pytest.raises(JWTError):
        decode_access_token(modified_token)


def test_expired_access_token_is_rejected():
    token = create_access_token(
        {
            "sub": "123",
            "role": "user",
            "token_version": 0,
        },
        expires_delta=timedelta(seconds=-1),
    )

    with pytest.raises(JWTError):
        decode_access_token(token)