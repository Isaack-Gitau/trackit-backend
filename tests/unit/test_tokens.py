"""
TRACKIT Authentication Token Service Tests.

Coverage:

- Secure raw token generation
- Token hashing
- Supported token types
- Token creation
- Previous-token invalidation
- Valid token lookup
- Invalid token rejection
- Expired token rejection
- Token consumption
- Double-consumption protection
- Token-type isolation
- User token invalidation
- Expiration helpers
- Consumption helpers
"""

from datetime import timedelta

import pytest

from app.models.auth_token import AuthToken
from app.services.tokens import (
    ALLOWED_TOKEN_TYPES,
    EMAIL_VERIFICATION_TOKEN_MINUTES,
    EMAIL_VERIFICATION_TOKEN_TYPE,
    PASSWORD_RESET_TOKEN_MINUTES,
    PASSWORD_RESET_TOKEN_TYPE,
    consume_token,
    create_auth_token,
    generate_raw_token,
    get_valid_token,
    hash_token,
    invalidate_all_user_tokens,
    invalidate_user_tokens,
    is_token_consumed,
    is_token_expired,
)


# ============================================================================
# HELPERS
# ============================================================================


def create_test_user(db, *, user_id: int):
    """
    Create the minimum User record required by AuthToken.
    """

    from app.models.user import User

    user = User(
        id=user_id,
        username=f"tokentest{user_id}",
        first_name="Token",
        last_name="Test",
        email=f"tokentest{user_id}@example.com",
        password_hash="test-password-hash",
        role="user",
        is_active=True,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    return user


def create_stored_token(
    db,
    *,
    user_id: int,
    token_type: str = EMAIL_VERIFICATION_TOKEN_TYPE,
    minutes: int = EMAIL_VERIFICATION_TOKEN_MINUTES,
):
    """
    Create an authentication token through the real token service.
    """

    return create_auth_token(
        db,
        user_id=user_id,
        token_type=token_type,
        expires_minutes=minutes,
    )


# ============================================================================
# TOKEN GENERATION
# ============================================================================


def test_generate_raw_token_returns_non_empty_url_safe_token():
    token = generate_raw_token()

    assert isinstance(token, str)
    assert token
    assert len(token) > 50


def test_generate_raw_token_produces_unique_tokens():
    first = generate_raw_token()
    second = generate_raw_token()

    assert first != second


# ============================================================================
# TOKEN HASHING
# ============================================================================


def test_hash_token_returns_sha256_digest():
    token = "test-authentication-token"

    hashed = hash_token(token)

    assert isinstance(hashed, str)
    assert len(hashed) == 64

    # SHA-256 hexadecimal output contains only hexadecimal characters.
    assert all(
        character in "0123456789abcdef"
        for character in hashed
    )


def test_hash_token_is_deterministic():
    token = "same-token"

    assert hash_token(token) == hash_token(token)


def test_hash_token_different_tokens_produce_different_hashes():
    assert hash_token("token-one") != hash_token("token-two")


def test_hash_token_rejects_empty_token():
    with pytest.raises(
        ValueError,
        match="Authentication token cannot be empty",
    ):
        hash_token("")


# ============================================================================
# TOKEN CREATION
# ============================================================================


def test_create_auth_token_creates_hashed_token(db):
    user = create_test_user(
        db,
        user_id=7001,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
    )

    stored_token = db.query(AuthToken).filter(
        AuthToken.user_id == user.id,
    ).one()

    assert raw_token
    assert stored_token.token_hash == hash_token(raw_token)
    assert stored_token.token_hash != raw_token
    assert stored_token.token_type == EMAIL_VERIFICATION_TOKEN_TYPE
    assert stored_token.used_at is None
    assert stored_token.expires_at is not None


def test_create_auth_token_uses_password_reset_lifetime(db):
    user = create_test_user(
        db,
        user_id=7002,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
        minutes=PASSWORD_RESET_TOKEN_MINUTES,
    )

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    )

    assert token is not None


def test_create_auth_token_rejects_invalid_user_id(db):
    with pytest.raises(
        ValueError,
        match="Invalid user ID",
    ):
        create_auth_token(
            db,
            user_id=0,
            token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
            expires_minutes=30,
        )


def test_create_auth_token_rejects_unsupported_token_type(db):
    user = create_test_user(
        db,
        user_id=7003,
    )

    with pytest.raises(
        ValueError,
        match="Unsupported authentication token type",
    ):
        create_auth_token(
            db,
            user_id=user.id,
            token_type="unsupported",
            expires_minutes=30,
        )


def test_create_auth_token_rejects_non_positive_expiration(db):
    user = create_test_user(
        db,
        user_id=7004,
    )

    with pytest.raises(
        ValueError,
        match="Token expiration must be greater than zero",
    ):
        create_auth_token(
            db,
            user_id=user.id,
            token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
            expires_minutes=0,
        )


def test_allowed_token_types_are_only_authentication_types():
    assert ALLOWED_TOKEN_TYPES == {
        EMAIL_VERIFICATION_TOKEN_TYPE,
        PASSWORD_RESET_TOKEN_TYPE,
    }


# ============================================================================
# PREVIOUS TOKEN INVALIDATION
# ============================================================================


def test_creating_new_token_invalidates_previous_same_type_token(db):
    user = create_test_user(
        db,
        user_id=7005,
    )

    first_raw_token = create_stored_token(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    second_raw_token = create_stored_token(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    first = get_valid_token(
        db,
        raw_token=first_raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    second = get_valid_token(
        db,
        raw_token=second_raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert first is None
    assert second is not None


def test_creating_new_token_does_not_invalidate_different_token_type(db):
    user = create_test_user(
        db,
        user_id=7006,
    )

    verification_raw_token = create_stored_token(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    reset_raw_token = create_stored_token(
        db,
        user_id=user.id,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    )

    verification = get_valid_token(
        db,
        raw_token=verification_raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    reset = get_valid_token(
        db,
        raw_token=reset_raw_token,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    )

    assert verification is not None
    assert reset is not None


# ============================================================================
# TOKEN LOOKUP
# ============================================================================


def test_get_valid_token_returns_valid_token(db):
    user = create_test_user(
        db,
        user_id=7007,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
    )

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is not None
    assert token.user_id == user.id
    assert token.used_at is None


def test_get_valid_token_rejects_empty_token(db):
    token = get_valid_token(
        db,
        raw_token="",
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is None


def test_get_valid_token_rejects_whitespace_token(db):
    token = get_valid_token(
        db,
        raw_token="   ",
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is None


def test_get_valid_token_rejects_unknown_token(db):
    token = get_valid_token(
        db,
        raw_token="this-token-does-not-exist",
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is None


def test_get_valid_token_rejects_wrong_token_type(db):
    user = create_test_user(
        db,
        user_id=7008,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    )

    assert token is None


def test_get_valid_token_rejects_expired_token(db):
    user = create_test_user(
        db,
        user_id=7009,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
        minutes=1,
    )

    token = db.query(AuthToken).filter(
        AuthToken.user_id == user.id,
    ).one()

    token.expires_at = token.expires_at - timedelta(minutes=5)

    db.flush()

    result = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert result is None


# ============================================================================
# TOKEN CONSUMPTION
# ============================================================================


def test_consume_token_marks_token_as_used(db):
    user = create_test_user(
        db,
        user_id=7010,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
    )

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is not None
    assert token.used_at is None

    result = consume_token(
        db,
        token,
    )

    assert result is True
    assert token.used_at is not None
    assert is_token_consumed(token) is True


def test_consume_token_cannot_be_consumed_twice(db):
    user = create_test_user(
        db,
        user_id=7011,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
    )

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is not None

    first_result = consume_token(
        db,
        token,
    )

    second_result = consume_token(
        db,
        token,
    )

    assert first_result is True
    assert second_result is False


def test_consumed_token_is_no_longer_valid(db):
    user = create_test_user(
        db,
        user_id=7012,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
    )

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is not None

    assert consume_token(
        db,
        token,
    ) is True

    result = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert result is None


# ============================================================================
# TOKEN INVALIDATION
# ============================================================================


def test_invalidate_user_tokens_invalidates_only_requested_type(db):
    user = create_test_user(
        db,
        user_id=7013,
    )

    verification_token = create_stored_token(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    reset_token = create_stored_token(
        db,
        user_id=user.id,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    )

    count = invalidate_user_tokens(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert count == 1

    assert get_valid_token(
        db,
        raw_token=verification_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    ) is None

    assert get_valid_token(
        db,
        raw_token=reset_token,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    ) is not None


def test_invalidate_all_user_tokens_invalidates_all_types(db):
    user = create_test_user(
        db,
        user_id=7014,
    )

    verification_token = create_stored_token(
        db,
        user_id=user.id,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    reset_token = create_stored_token(
        db,
        user_id=user.id,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    )

    count = invalidate_all_user_tokens(
        db,
        user_id=user.id,
    )

    assert count == 2

    assert get_valid_token(
        db,
        raw_token=verification_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    ) is None

    assert get_valid_token(
        db,
        raw_token=reset_token,
        token_type=PASSWORD_RESET_TOKEN_TYPE,
    ) is None


def test_invalidate_all_user_tokens_does_not_affect_other_users(db):
    first_user = create_test_user(
        db,
        user_id=7015,
    )

    second_user = create_test_user(
        db,
        user_id=7016,
    )

    first_token = create_stored_token(
        db,
        user_id=first_user.id,
    )

    second_token = create_stored_token(
        db,
        user_id=second_user.id,
    )

    count = invalidate_all_user_tokens(
        db,
        user_id=first_user.id,
    )

    assert count == 1

    assert get_valid_token(
        db,
        raw_token=first_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    ) is None

    assert get_valid_token(
        db,
        raw_token=second_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    ) is not None


def test_invalidate_user_tokens_rejects_invalid_user_id(db):
    with pytest.raises(
        ValueError,
        match="Invalid user ID",
    ):
        invalidate_user_tokens(
            db,
            user_id=0,
            token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
        )


def test_invalidate_all_user_tokens_rejects_invalid_user_id(db):
    with pytest.raises(
        ValueError,
        match="Invalid user ID",
    ):
        invalidate_all_user_tokens(
            db,
            user_id=0,
        )


# ============================================================================
# TOKEN STATE HELPERS
# ============================================================================


def test_is_token_expired_returns_false_for_future_token(db):
    user = create_test_user(
        db,
        user_id=7017,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
    )

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is not None
    assert is_token_expired(token) is False


def test_is_token_expired_returns_true_for_expired_token(db):
    user = create_test_user(
        db,
        user_id=7018,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
    )

    token = db.query(AuthToken).filter(
        AuthToken.user_id == user.id,
    ).one()

    token.expires_at = token.expires_at - timedelta(hours=1)

    db.flush()

    assert is_token_expired(token) is True


def test_is_token_consumed_returns_false_for_unused_token(db):
    user = create_test_user(
        db,
        user_id=7019,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
    )

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is not None
    assert is_token_consumed(token) is False


def test_is_token_consumed_returns_true_for_consumed_token(db):
    user = create_test_user(
        db,
        user_id=7020,
    )

    raw_token = create_stored_token(
        db,
        user_id=user.id,
    )

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is not None

    consume_token(
        db,
        token,
    )

    assert is_token_consumed(token) is True
