"""
TRACKIT Password Reset Service Tests.

Tests:
- Password-reset token creation
- Valid password reset
- Password hashing
- password_changed_at update
- JWT token_version invalidation
- Stored authentication-token invalidation
- Single-use reset tokens
- Invalid/expired tokens
- Wrong token types
- Password-strength rejection
- Transaction behavior
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import verify_password
from app.models.auth_token import AuthToken
from app.services.password_reset import (
    create_password_reset_token,
    get_password_reset_user,
    reset_user_password,
)
from app.services.tokens import (
    EMAIL_VERIFICATION_TOKEN_TYPE,
    create_auth_token,
)
from app.services.user import create_user_account


# ============================================================================
# HELPERS
# ============================================================================


def create_test_user(
    db,
    *,
    username="testuser",
    email="test@example.com",
    password="Trackit@123",
):
    """
    Create a verified active test user through the user service.
    """

    user = create_user_account(
        db,
        username=username,
        first_name="Test",
        last_name="User",
        email=email,
        password=password,
    )

    user.is_verified = True
    user.is_active = True

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


# ============================================================================
# TOKEN CREATION
# ============================================================================


def test_create_password_reset_token_returns_raw_token(db):
    user = create_test_user(db)

    token = create_password_reset_token(
        db,
        user,
    )

    assert isinstance(token, str)
    assert len(token) > 20

    # Raw token must never be stored directly.
    stored_tokens = (
        db.query(AuthToken)
        .filter(
            AuthToken.user_id == user.id,
        )
        .all()
    )

    assert len(stored_tokens) == 1
    assert stored_tokens[0].token_hash != token


def test_new_password_reset_token_invalidates_previous_token(db):
    user = create_test_user(db)

    first_token = create_password_reset_token(
        db,
        user,
    )

    db.commit()

    second_token = create_password_reset_token(
        db,
        user,
    )

    db.commit()

    assert first_token != second_token

    assert (
        get_password_reset_user(
            db,
            first_token,
        )
        is None
    )

    result = get_password_reset_user(
        db,
        second_token,
    )

    assert result is not None
    assert result[0].id == user.id


# ============================================================================
# VALID PASSWORD RESET
# ============================================================================


def test_reset_user_password_successfully_changes_password(db):
    user = create_test_user(db)

    reset_token = create_password_reset_token(
        db,
        user,
    )

    db.commit()

    old_password_hash = user.password_hash
    old_token_version = user.token_version

    result = reset_user_password(
        db,
        raw_token=reset_token,
        new_password="NewPassword@456",
    )

    assert result is not None
    assert result.id == user.id

    assert result.password_hash != old_password_hash

    assert verify_password(
        "NewPassword@456",
        result.password_hash,
    )

    assert not verify_password(
        "Trackit@123",
        result.password_hash,
    )

    assert result.password_changed_at is not None
    assert result.token_version == old_token_version + 1


def test_reset_user_password_invalidates_existing_auth_tokens(db):
    user = create_test_user(db)

    # Create an existing stored authentication token.
    existing_token = create_auth_token(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
        expires_minutes=30,
    )

    reset_token = create_password_reset_token(
        db,
        user,
    )

    db.commit()

    result = reset_user_password(
        db,
        raw_token=reset_token,
        new_password="NewPassword@456",
    )

    assert result is not None

    db.commit()

    stored_existing_token = (
        db.query(AuthToken)
        .filter(
            AuthToken.token_hash != "",
            AuthToken.user_id == user.id,
        )
        .all()
    )

    assert existing_token

    # Every unused authentication token should have been invalidated.
    for token in stored_existing_token:
        assert token.used_at is not None


def test_reset_token_is_single_use(db):
    user = create_test_user(db)

    reset_token = create_password_reset_token(
        db,
        user,
    )

    db.commit()

    first_result = reset_user_password(
        db,
        raw_token=reset_token,
        new_password="NewPassword@456",
    )

    assert first_result is not None

    db.commit()

    second_result = reset_user_password(
        db,
        raw_token=reset_token,
        new_password="AnotherPassword@789",
    )

    assert second_result is None


# ============================================================================
# INVALID TOKEN HANDLING
# ============================================================================


def test_invalid_reset_token_returns_none(db):
    user = create_test_user(db)

    old_password_hash = user.password_hash
    old_token_version = user.token_version

    result = reset_user_password(
        db,
        raw_token="not-a-real-reset-token",
        new_password="NewPassword@456",
    )

    assert result is None

    db.refresh(user)

    assert user.password_hash == old_password_hash
    assert user.token_version == old_token_version
    assert user.password_changed_at is None


def test_email_verification_token_cannot_reset_password(db):
    user = create_test_user(db)

    verification_token = create_auth_token(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
        expires_minutes=30,
    )

    db.commit()

    old_password_hash = user.password_hash
    old_token_version = user.token_version

    result = reset_user_password(
        db,
        raw_token=verification_token,
        new_password="NewPassword@456",
    )

    assert result is None

    db.refresh(user)

    assert user.password_hash == old_password_hash
    assert user.token_version == old_token_version


def test_expired_reset_token_returns_none(db):
    user = create_test_user(db)

    reset_token = create_password_reset_token(
        db,
        user,
    )

    db.commit()

    # Move the stored token into the past.
    stored_token = (
        db.query(AuthToken)
        .filter(
            AuthToken.user_id == user.id,
        )
        .one()
    )

    stored_token.expires_at = (
        datetime.now(timezone.utc)
        - timedelta(minutes=1)
    )

    db.commit()

    result = reset_user_password(
        db,
        raw_token=reset_token,
        new_password="NewPassword@456",
    )

    assert result is None


# ============================================================================
# PASSWORD VALIDATION
# ============================================================================


@pytest.mark.parametrize(
    "new_password",
    [
        "short",
        "alllowercase123!",
        "ALLUPPERCASE123!",
        "NoNumbers!",
        "NoSpecial123",
    ],
)
def test_reset_rejects_weak_password(
    db,
    new_password,
):
    user = create_test_user(db)

    reset_token = create_password_reset_token(
        db,
        user,
    )

    db.commit()

    old_password_hash = user.password_hash
    old_token_version = user.token_version

    with pytest.raises(ValueError):
        reset_user_password(
            db,
            raw_token=reset_token,
            new_password=new_password,
        )

    db.refresh(user)

    assert user.password_hash == old_password_hash
    assert user.token_version == old_token_version


def test_reset_does_not_consume_token_when_password_validation_fails(db):
    user = create_test_user(db)

    reset_token = create_password_reset_token(
        db,
        user,
    )

    db.commit()

    with pytest.raises(ValueError):
        reset_user_password(
            db,
            raw_token=reset_token,
            new_password="weak",
        )

    # The token should still be usable because password validation
    # occurs before token consumption.
    result = reset_user_password(
        db,
        raw_token=reset_token,
        new_password="StrongPassword@456",
    )

    assert result is not None


# ============================================================================
# TRANSACTION BEHAVIOR
# ============================================================================


def test_reset_does_not_commit_transaction(db):
    user = create_test_user(db)

    reset_token = create_password_reset_token(
        db,
        user,
    )

    db.commit()

    reset_user_password(
        db,
        raw_token=reset_token,
        new_password="NewPassword@456",
    )

    # Roll back the caller transaction.
    db.rollback()

    db.refresh(user)

    # The password reset must have been rolled back.
    assert verify_password(
        "Trackit@123",
        user.password_hash,
    )

    assert user.password_changed_at is None
    assert user.token_version == 0
