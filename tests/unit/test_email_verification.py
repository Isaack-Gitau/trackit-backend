"""
TRACKIT Email Verification Service Tests.

Tests:
- Verification token creation
- Correct token type and expiration
- Successful email verification
- Invalid token rejection
- Consumed token rejection
- Expired token rejection
- Already verified accounts
- Atomic token consumption
"""

from datetime import timedelta

from app.models.auth_token import AuthToken
from app.services.email_verification import (
    create_verification_token,
    verify_email,
)
from app.services.tokens import (
    EMAIL_VERIFICATION_TOKEN_MINUTES,
    EMAIL_VERIFICATION_TOKEN_TYPE,
    get_valid_token,
)
from app.services.user import create_user_account


# ============================================================================
# HELPERS
# ============================================================================


def create_test_user(
    db,
    *,
    username="verifyuser",
    email="verify@example.com",
    is_verified=False,
):
    """
    Create a user for email-verification service tests.
    """

    user = create_user_account(
        db,
        username=username,
        first_name="Verify",
        last_name="User",
        email=email,
        password="Trackit@123",
    )

    user.is_verified = is_verified

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


# ============================================================================
# TOKEN CREATION
# ============================================================================


def test_create_verification_token_creates_valid_token(db):
    user = create_test_user(db)

    raw_token = create_verification_token(
        db,
        user,
    )

    assert isinstance(raw_token, str)
    assert len(raw_token) > 50

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is not None
    assert token.user_id == user.id
    assert token.token_type == EMAIL_VERIFICATION_TOKEN_TYPE
    assert token.used_at is None


def test_create_verification_token_uses_expected_expiration(db):
    user = create_test_user(db)

    before_creation = __import__(
        "datetime"
    ).datetime.now(
        __import__("datetime").timezone.utc
    )

    raw_token = create_verification_token(
        db,
        user,
    )

    after_creation = __import__(
        "datetime"
    ).datetime.now(
        __import__("datetime").timezone.utc
    )

    token = get_valid_token(
        db,
        raw_token=raw_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert token is not None

    expected_minimum = (
        before_creation
        + timedelta(
            minutes=EMAIL_VERIFICATION_TOKEN_MINUTES
        )
    )

    expected_maximum = (
        after_creation
        + timedelta(
            minutes=EMAIL_VERIFICATION_TOKEN_MINUTES
        )
    )

    assert token.expires_at >= expected_minimum
    assert token.expires_at <= expected_maximum


def test_creating_new_verification_token_invalidates_previous_token(db):
    user = create_test_user(db)

    first_token = create_verification_token(
        db,
        user,
    )

    second_token = create_verification_token(
        db,
        user,
    )

    assert first_token != second_token

    first_valid = get_valid_token(
        db,
        raw_token=first_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    second_valid = get_valid_token(
        db,
        raw_token=second_token,
        token_type=EMAIL_VERIFICATION_TOKEN_TYPE,
    )

    assert first_valid is None
    assert second_valid is not None


# ============================================================================
# SUCCESSFUL VERIFICATION
# ============================================================================


def test_verify_email_successfully_verifies_user(db):
    user = create_test_user(
        db,
        is_verified=False,
    )

    raw_token = create_verification_token(
        db,
        user,
    )

    verified_user = verify_email(
        db,
        raw_token,
    )

    assert verified_user is not None
    assert verified_user.id == user.id
    assert verified_user.is_verified is True


def test_verify_email_consumes_token(db):
    user = create_test_user(db)

    raw_token = create_verification_token(
        db,
        user,
    )

    verified_user = verify_email(
        db,
        raw_token,
    )

    assert verified_user is not None

    token_hash = __import__(
        "hashlib"
    ).sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    token = db.query(AuthToken).filter(
        AuthToken.token_hash == token_hash,
        AuthToken.token_type == EMAIL_VERIFICATION_TOKEN_TYPE,
    ).first()

    assert token is not None
    assert token.used_at is not None


def test_verify_email_cannot_reuse_token(db):
    user = create_test_user(db)

    raw_token = create_verification_token(
        db,
        user,
    )

    first_result = verify_email(
        db,
        raw_token,
    )

    second_result = verify_email(
        db,
        raw_token,
    )

    assert first_result is not None
    assert second_result is None


# ============================================================================
# INVALID VERIFICATION
# ============================================================================


def test_verify_email_invalid_token_returns_none(db):
    result = verify_email(
        db,
        "this-token-does-not-exist",
    )

    assert result is None


def test_verify_email_empty_token_returns_none(db):
    result = verify_email(
        db,
        "",
    )

    assert result is None


def test_verify_email_whitespace_token_returns_none(db):
    result = verify_email(
        db,
        "   ",
    )

    assert result is None


def test_verify_email_expired_token_returns_none(db):
    user = create_test_user(db)

    raw_token = create_verification_token(
        db,
        user,
    )

    token_hash = __import__(
        "hashlib"
    ).sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    token = db.query(AuthToken).filter(
        AuthToken.token_hash == token_hash,
        AuthToken.token_type == EMAIL_VERIFICATION_TOKEN_TYPE,
    ).first()

    assert token is not None

    token.expires_at = (
        __import__(
            "datetime"
        ).datetime.now(
            __import__("datetime").timezone.utc
        )
        - timedelta(minutes=1)
    )

    db.commit()

    result = verify_email(
        db,
        raw_token,
    )

    assert result is None


# ============================================================================
# ALREADY VERIFIED ACCOUNT
# ============================================================================


def test_verify_email_already_verified_user_still_consumes_token(db):
    user = create_test_user(
        db,
        is_verified=True,
    )

    raw_token = create_verification_token(
        db,
        user,
    )

    result = verify_email(
        db,
        raw_token,
    )

    assert result is not None
    assert result.id == user.id
    assert result.is_verified is True

    # The token must still be consumed even though the account
    # was already verified.
    assert verify_email(
        db,
        raw_token,
    ) is None


# ============================================================================
# TOKEN TYPE ISOLATION
# ============================================================================


def test_password_reset_token_cannot_verify_email(db):
    from app.services.password_reset import create_password_reset_token

    user = create_test_user(db)

    reset_token = create_password_reset_token(
        db,
        user,
    )

    result = verify_email(
        db,
        reset_token,
    )

    assert result is None
    assert user.is_verified is False
