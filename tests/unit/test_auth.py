"""
TRACKIT Authentication Service Tests.

Tests:
- User registration
- Username/email normalization
- Duplicate username rejection
- Duplicate email rejection
- Credential authentication
- Wrong-password rejection
- Login eligibility
- Unverified account rejection
- Inactive account rejection
- JWT issuance
"""

import pytest

from app.services.auth import (
    authenticate_user,
    is_login_allowed,
    login_user,
    register_user,
)
from app.services.user import (
    create_user_account,
)
from app.core.security import (
    verify_password,
)


# ============================================================================
# HELPERS
# ============================================================================


def create_test_user(
    db,
    *,
    username="testuser",
    email="test@example.com",
    password="Trackit@123",
    is_verified=True,
    is_active=True,
):
    """
    Create a user directly through the user service.

    This keeps the service tests focused on authentication
    rather than HTTP routing.
    """

    user = create_user_account(
        db,
        username=username,
        first_name="Test",
        last_name="User",
        email=email,
        password=password,
    )

    user.is_verified = is_verified
    user.is_active = is_active

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


# ============================================================================
# REGISTRATION
# ============================================================================


def test_register_user_success(db):
    user = register_user(
        db,
        username="TestUser",
        first_name="Isaack",
        last_name="Gitau",
        email="TEST@Example.COM",
        password="Trackit@123",
    )

    assert user.id is not None
    assert user.username == "testuser"
    assert user.email == "test@example.com"
    assert user.first_name == "Isaack"
    assert user.last_name == "Gitau"

    # Password must never be stored in plaintext.
    assert user.password_hash != "Trackit@123"

    # Verify that the stored value is actually a valid password hash.
    assert verify_password(
        "Trackit@123",
        user.password_hash,
    )

    # New accounts start unverified.
    assert user.is_verified is False

    # New accounts start active.
    assert user.is_active is True


def test_register_duplicate_username_is_rejected(db):
    register_user(
        db,
        username="testuser",
        first_name="Test",
        last_name="User",
        email="first@example.com",
        password="Trackit@123",
    )

    with pytest.raises(ValueError, match="Username is already registered"):
        register_user(
            db,
            username="TESTUSER",
            first_name="Another",
            last_name="User",
            email="second@example.com",
            password="Trackit@123",
        )


def test_register_duplicate_email_is_rejected(db):
    register_user(
        db,
        username="firstuser",
        first_name="First",
        last_name="User",
        email="TEST@EXAMPLE.COM",
        password="Trackit@123",
    )

    with pytest.raises(ValueError, match="Email is already registered"):
        register_user(
            db,
            username="seconduser",
            first_name="Second",
            last_name="User",
            email="test@example.com",
            password="Trackit@123",
        )


# ============================================================================
# CREDENTIAL AUTHENTICATION
# ============================================================================


def test_authenticate_user_with_username(db):
    user = create_test_user(
        db,
        username="testuser",
    )

    authenticated = authenticate_user(
        db,
        "TESTUSER",
        "Trackit@123",
    )

    assert authenticated is not None
    assert authenticated.id == user.id


def test_authenticate_user_with_email(db):
    user = create_test_user(
        db,
        username="testuser",
        email="test@example.com",
    )

    authenticated = authenticate_user(
        db,
        "TEST@EXAMPLE.COM",
        "Trackit@123",
    )

    assert authenticated is not None
    assert authenticated.id == user.id


def test_authenticate_user_wrong_password_returns_none(db):
    create_test_user(db)

    authenticated = authenticate_user(
        db,
        "testuser",
        "WrongPassword@123",
    )

    assert authenticated is None


def test_authenticate_unknown_user_returns_none(db):
    authenticated = authenticate_user(
        db,
        "doesnotexist",
        "Trackit@123",
    )

    assert authenticated is None


# ============================================================================
# LOGIN ELIGIBILITY
# ============================================================================


def test_verified_active_user_is_allowed_to_login(db):
    user = create_test_user(
        db,
        is_verified=True,
        is_active=True,
    )

    assert is_login_allowed(user) is True


def test_unverified_user_is_not_allowed_to_login(db):
    user = create_test_user(
        db,
        is_verified=False,
        is_active=True,
    )

    assert is_login_allowed(user) is False


def test_inactive_user_is_not_allowed_to_login(db):
    user = create_test_user(
        db,
        is_verified=True,
        is_active=False,
    )

    assert is_login_allowed(user) is False


# ============================================================================
# LOGIN
# ============================================================================


def test_login_user_returns_access_token(db):
    user = create_test_user(
        db,
        username="testuser",
        is_verified=True,
        is_active=True,
    )

    result = login_user(
        db,
        login="testuser",
        password="Trackit@123",
    )

    assert result is not None

    access_token, authenticated_user = result

    assert isinstance(access_token, str)
    assert len(access_token) > 50
    assert authenticated_user.id == user.id


def test_login_unverified_user_returns_none(db):
    create_test_user(
        db,
        is_verified=False,
        is_active=True,
    )

    result = login_user(
        db,
        login="testuser",
        password="Trackit@123",
    )

    assert result is None


def test_login_inactive_user_returns_none(db):
    create_test_user(
        db,
        is_verified=True,
        is_active=False,
    )

    result = login_user(
        db,
        login="testuser",
        password="Trackit@123",
    )

    assert result is None


def test_login_wrong_password_returns_none(db):
    create_test_user(
        db,
        is_verified=True,
        is_active=True,
    )

    result = login_user(
        db,
        login="testuser",
        password="WrongPassword@123",
    )

    assert result is None