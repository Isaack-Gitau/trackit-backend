"""
TRACKIT Authentication API Tests.

Coverage:

- Successful login for an active, verified user.
- Dedicated inactive-account response after valid credentials.
- Generic response for an incorrect password.
- Generic response for an unknown identifier.
- Generic response for an unverified user.
"""

import pytest
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.core.rate_limit import clear_rate_limit_store
from app.core.security import hash_password
from app.models.user import User


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """
    Reset rate-limit state before and after every authentication API test.

    Authentication API tests exercise the real login endpoint, which shares
    the application's in-memory rate-limit store with other tests.
    """

    clear_rate_limit_store()

    yield

    clear_rate_limit_store()


# ============================================================================
# TEST HELPERS
# ============================================================================


def create_login_user(
    db: Session,
    *,
    user_id: int,
    username: str,
    email: str,
    password: str = "Trackit@123",
    is_active: bool = True,
    is_verified: bool = True,
) -> User:
    """
    Create a user with a real password hash for login API tests.
    """

    user = User(
        id=user_id,
        username=username,
        first_name="Test",
        last_name="User",
        email=email,
        password_hash=hash_password(password),
        role="user",
        is_active=is_active,
        is_verified=is_verified,
    )

    db.add(user)
    db.flush()

    return user


# ============================================================================
# LOGIN
# ============================================================================


def test_login_active_verified_user_returns_token(
    client: TestClient,
    db: Session,
):
    """
    An active, verified user with valid credentials receives an access token.
    """

    create_login_user(
        db,
        user_id=6001,
        username="loginactive",
        email="loginactive@example.com",
    )

    response = client.post(
        "/api/auth/login",
        json={
            "identifier": "loginactive",
            "password": "Trackit@123",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data["access_token"], str)
    assert len(data["access_token"]) > 50
    assert data["token_type"] == "bearer"


def test_login_inactive_user_returns_dedicated_403(
    client: TestClient,
    db: Session,
):
    """
    Valid credentials for an inactive account return the dedicated
    inactive-account response.
    """

    create_login_user(
        db,
        user_id=6002,
        username="logininactive",
        email="logininactive@example.com",
        is_active=False,
    )

    response = client.post(
        "/api/auth/login",
        json={
            "identifier": "logininactive",
            "password": "Trackit@123",
        },
    )

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Your TrackIt account is currently inactive.",
    }


def test_login_wrong_password_returns_generic_401(
    client: TestClient,
    db: Session,
):
    """
    An incorrect password returns the generic authentication failure.
    """

    create_login_user(
        db,
        user_id=6003,
        username="loginwrongpassword",
        email="loginwrongpassword@example.com",
    )

    response = client.post(
        "/api/auth/login",
        json={
            "identifier": "loginwrongpassword",
            "password": "WrongPassword@123",
        },
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": (
            "Invalid credentials or account "
            "not eligible for login."
        ),
    }


def test_login_unknown_identifier_returns_generic_401(
    client: TestClient,
):
    """
    An unknown username or email returns the generic authentication failure.
    """

    response = client.post(
        "/api/auth/login",
        json={
            "identifier": "doesnotexist@example.com",
            "password": "Trackit@123",
        },
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": (
            "Invalid credentials or account "
            "not eligible for login."
        ),
    }


def test_login_unverified_user_returns_generic_401(
    client: TestClient,
    db: Session,
):
    """
    Correct credentials for an unverified user remain a generic
    authentication failure.
    """

    create_login_user(
        db,
        user_id=6004,
        username="loginunverified",
        email="loginunverified@example.com",
        is_verified=False,
    )

    response = client.post(
        "/api/auth/login",
        json={
            "identifier": "loginunverified",
            "password": "Trackit@123",
        },
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": (
            "Invalid credentials or account "
            "not eligible for login."
        ),
    }