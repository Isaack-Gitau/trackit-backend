"""
TRACKIT Authentication Endpoint Rate-Limit Tests.

Verifies that authentication endpoints actually enforce
the configured rate limits.
"""

import pytest
from fastapi.testclient import TestClient

from app.core.rate_limit import clear_rate_limit_store
from app.main import app


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """
    Reset rate limits before and after every test.
    """

    clear_rate_limit_store()

    yield

    clear_rate_limit_store()


@pytest.fixture
def client():
    """
    FastAPI test client.
    """

    return TestClient(app)


# ============================================================================
# Login
# ============================================================================


def test_login_endpoint_is_rate_limited(client):
    """
    Login should return HTTP 429 after the configured
    number of attempts from the same IP.
    """

    for _ in range(5):
        response = client.post(
            "/api/auth/login",
            json={
                "identifier": "nonexistent@example.com",
                "password": "WrongPassword1!",
            },
        )

        assert response.status_code in {
            401,
            429,
        }

    response = client.post(
        "/api/auth/login",
        json={
            "identifier": "nonexistent@example.com",
            "password": "WrongPassword1!",
        },
    )

    assert response.status_code == 429
    assert "Retry-After" in response.headers


# ============================================================================
# Registration
# ============================================================================


def test_register_endpoint_is_rate_limited(client):
    """
    Registration should return HTTP 429 after the configured
    number of requests from the same IP.
    """

    for index in range(5):
        response = client.post(
            "/api/auth/register",
            json={
                "username": f"ratelimituser{index}",
                "first_name": "Rate",
                "last_name": "Limit",
                "email": f"ratelimit{index}@example.com",
                "password": "StrongPassword1!",
            },
        )

        assert response.status_code in {
            201,
            409,
            429,
        }

    response = client.post(
        "/api/auth/register",
        json={
            "username": "ratelimitfinal",
            "first_name": "Rate",
            "last_name": "Limit",
            "email": "ratelimitfinal@example.com",
            "password": "StrongPassword1!",
        },
    )

    assert response.status_code == 429
    assert "Retry-After" in response.headers


# ============================================================================
# Forgot Password
# ============================================================================


def test_forgot_password_endpoint_is_rate_limited(client):
    """
    Forgot-password requests should be rate limited.
    """

    for _ in range(3):
        response = client.post(
            "/api/auth/forgot-password",
            json={
                "email": "unknown@example.com",
            },
        )

        assert response.status_code == 200

    response = client.post(
        "/api/auth/forgot-password",
        json={
            "email": "unknown@example.com",
        },
    )

    assert response.status_code == 429
    assert "Retry-After" in response.headers


# ============================================================================
# Verification
# ============================================================================


def test_verify_email_endpoint_is_rate_limited(client):
    """
    Email verification attempts should be rate limited.
    """

    for _ in range(3):
        response = client.post(
            "/api/auth/verify-email",
            json={
                "token": "invalid-token",
            },
        )

        assert response.status_code == 400

    response = client.post(
        "/api/auth/verify-email",
        json={
            "token": "invalid-token",
        },
    )

    assert response.status_code == 429
    assert "Retry-After" in response.headers


# ============================================================================
# Password Reset
# ============================================================================


def test_reset_password_endpoint_is_rate_limited(client):
    """
    Password-reset attempts should be rate limited.
    """

    for _ in range(3):
        response = client.post(
            "/api/auth/reset-password",
            json={
                "token": "invalid-token",
                "new_password": "NewStrongPassword1!",
            },
        )

        assert response.status_code == 400

    response = client.post(
        "/api/auth/reset-password",
        json={
            "token": "invalid-token",
            "new_password": "NewStrongPassword1!",
        },
    )

    assert response.status_code == 429
    assert "Retry-After" in response.headers