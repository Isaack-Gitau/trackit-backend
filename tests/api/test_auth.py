"""
TRACKIT Authentication API Tests.

Coverage:

- Successful login for an active, verified user.
- Dedicated inactive-account response after valid credentials.
- Generic response for an incorrect password.
- Generic response for an unknown identifier.
- Generic response for an unverified user.
"""

from unittest.mock import AsyncMock
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.core.rate_limit import clear_rate_limit_store
from app.core.security import hash_password
from app.core.security import verify_password
from app.services.tokens import hash_token
from app.models.auth_token import AuthToken
from app.models.user import User
from app.services.email_verification import create_verification_token
from app.services.password_reset import create_password_reset_token


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

# ============================================================================
# EMAIL VERIFICATION
# ============================================================================


def test_verify_email_valid_token_returns_verified_user(
    client: TestClient,
    db: Session,
):
    """
    A valid email-verification token verifies the user's account and
    returns the authenticated user representation.
    """

    user = create_login_user(
        db,
        user_id=6005,
        username="verifyvalid",
        email="verifyvalid@example.com",
        is_verified=False,
    )

    token = create_verification_token(
        db,
        user,
    )

    response = client.post(
        "/api/auth/verify-email",
        json={
            "token": token,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == user.id
    assert data["username"] == user.username
    assert data["email"] == user.email
    assert data["is_verified"] is True


def test_verify_email_invalid_token_returns_400(
    client: TestClient,
):
    """
    An invalid verification token returns a generic 400 response.
    """

    response = client.post(
        "/api/auth/verify-email",
        json={
            "token": "definitely-not-a-valid-verification-token",
        },
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Invalid or expired verification token.",
    }


def test_verify_email_token_is_single_use(
    client: TestClient,
    db: Session,
):
    """
    A successfully consumed verification token cannot be reused.
    """

    user = create_login_user(
        db,
        user_id=6006,
        username="verifyreuse",
        email="verifyreuse@example.com",
        is_verified=False,
    )

    token = create_verification_token(
        db,
        user,
    )

    first_response = client.post(
        "/api/auth/verify-email",
        json={
            "token": token,
        },
    )

    assert first_response.status_code == 200

    second_response = client.post(
        "/api/auth/verify-email",
        json={
            "token": token,
        },
    )

    assert second_response.status_code == 400
    assert second_response.json() == {
        "detail": "Invalid or expired verification token.",
    }

# ============================================================================
# RESEND VERIFICATION
# ============================================================================


def test_resend_verification_active_unverified_user_sends_email(
    client: TestClient,
    db: Session,
    monkeypatch,
):
    """
    An active, unverified account receives a new verification message.
    """

    user = create_login_user(
        db,
        user_id=6007,
        username="resendactive",
        email="resendactive@example.com",
        is_verified=False,
    )

    send_mock = AsyncMock()

    monkeypatch.setattr(
        "app.routers.auth.send_verification_email",
        send_mock,
    )

    response = client.post(
        "/api/auth/resend-verification",
        json={
            "email": user.email,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": (
            "If an account exists for this email, "
            "a verification message has been sent."
        ),
    }

    send_mock.assert_awaited_once()

    call = send_mock.await_args

    assert call.kwargs["recipient"] == user.email
    assert isinstance(call.kwargs["token"], str)
    assert call.kwargs["token"]


def test_resend_verification_unknown_email_is_generic(
    client: TestClient,
    monkeypatch,
):
    """
    An unknown email receives the same generic response and no email is sent.
    """

    send_mock = AsyncMock()

    monkeypatch.setattr(
        "app.routers.auth.send_verification_email",
        send_mock,
    )

    response = client.post(
        "/api/auth/resend-verification",
        json={
            "email": "doesnotexist@example.com",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": (
            "If an account exists for this email, "
            "a verification message has been sent."
        ),
    }

    send_mock.assert_not_awaited()


def test_resend_verification_verified_user_is_generic(
    client: TestClient,
    db: Session,
    monkeypatch,
):
    """
    An already verified account receives the same generic response and no
    verification email is sent.
    """

    user = create_login_user(
        db,
        user_id=6008,
        username="resendverified",
        email="resendverified@example.com",
        is_verified=True,
    )

    send_mock = AsyncMock()

    monkeypatch.setattr(
        "app.routers.auth.send_verification_email",
        send_mock,
    )

    response = client.post(
        "/api/auth/resend-verification",
        json={
            "email": user.email,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": (
            "If an account exists for this email, "
            "a verification message has been sent."
        ),
    }

    send_mock.assert_not_awaited()


def test_resend_verification_inactive_user_is_generic(
    client: TestClient,
    db: Session,
    monkeypatch,
):
    """
    An inactive account receives the same generic response and no
    verification email is sent.
    """

    user = create_login_user(
        db,
        user_id=6009,
        username="resendinactive",
        email="resendinactive@example.com",
        is_verified=False,
        is_active=False,
    )

    send_mock = AsyncMock()

    monkeypatch.setattr(
        "app.routers.auth.send_verification_email",
        send_mock,
    )

    response = client.post(
        "/api/auth/resend-verification",
        json={
            "email": user.email,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": (
            "If an account exists for this email, "
            "a verification message has been sent."
        ),
    }

    send_mock.assert_not_awaited()


def test_resend_verification_email_failure_remains_generic(
    client: TestClient,
    db: Session,
    monkeypatch,
):
    """
    An email-delivery failure does not expose email delivery details or account
    existence through the API response.
    """

    user = create_login_user(
        db,
        user_id=6010,
        username="resendfailure",
        email="resendfailure@example.com",
        is_verified=False,
    )

    send_mock = AsyncMock(
        side_effect=RuntimeError("Resend delivery failed"),
    )

    monkeypatch.setattr(
        "app.routers.auth.send_verification_email",
        send_mock,
    )

    response = client.post(
        "/api/auth/resend-verification",
        json={
            "email": user.email,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": (
            "If an account exists for this email, "
            "a verification message has been sent."
        ),
    }

    send_mock.assert_awaited_once()

    call = send_mock.await_args

    assert call.kwargs["recipient"] == user.email
    assert call.kwargs["token"]

# ============================================================================
# FORGOT PASSWORD
# ============================================================================


def test_forgot_password_active_user_sends_reset_email(
    client: TestClient,
    db: Session,
    monkeypatch,
):
    """
    An active account receives a password-reset message.
    """

    user = create_login_user(
        db,
        user_id=6011,
        username="forgotactive",
        email="forgotactive@example.com",
    )

    send_mock = AsyncMock()

    monkeypatch.setattr(
        "app.routers.auth.send_password_reset_email",
        send_mock,
    )

    response = client.post(
        "/api/auth/forgot-password",
        json={
            "email": user.email,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": (
            "If an account exists for this email, "
            "a password reset message has been sent."
        ),
    }

    send_mock.assert_awaited_once()

    call = send_mock.await_args

    assert call.kwargs["recipient"] == user.email
    assert isinstance(call.kwargs["token"], str)
    assert call.kwargs["token"]


def test_forgot_password_unknown_email_is_generic(
    client: TestClient,
    monkeypatch,
):
    """
    An unknown email receives the same generic response and no reset email
    is sent.
    """

    send_mock = AsyncMock()

    monkeypatch.setattr(
        "app.routers.auth.send_password_reset_email",
        send_mock,
    )

    response = client.post(
        "/api/auth/forgot-password",
        json={
            "email": "doesnotexist@example.com",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": (
            "If an account exists for this email, "
            "a password reset message has been sent."
        ),
    }

    send_mock.assert_not_awaited()


def test_forgot_password_inactive_user_is_generic(
    client: TestClient,
    db: Session,
    monkeypatch,
):
    """
    An inactive account receives the same generic response and no reset
    email is sent.
    """

    user = create_login_user(
        db,
        user_id=6012,
        username="forgotinactive",
        email="forgotinactive@example.com",
        is_active=False,
    )

    send_mock = AsyncMock()

    monkeypatch.setattr(
        "app.routers.auth.send_password_reset_email",
        send_mock,
    )

    response = client.post(
        "/api/auth/forgot-password",
        json={
            "email": user.email,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": (
            "If an account exists for this email, "
            "a password reset message has been sent."
        ),
    }

    send_mock.assert_not_awaited()


def test_forgot_password_email_failure_remains_generic(
    client: TestClient,
    db: Session,
    monkeypatch,
):
    """
    A password-reset email delivery failure does not expose email delivery details
    or account existence.
    """

    user = create_login_user(
        db,
        user_id=6013,
        username="forgotfailure",
        email="forgotfailure@example.com",
    )

    send_mock = AsyncMock(
        side_effect=RuntimeError("Resend delivery failed"),
    )

    monkeypatch.setattr(
        "app.routers.auth.send_password_reset_email",
        send_mock,
    )

    response = client.post(
        "/api/auth/forgot-password",
        json={
            "email": user.email,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": (
            "If an account exists for this email, "
            "a password reset message has been sent."
        ),
    }

    send_mock.assert_awaited_once()

    call = send_mock.await_args

    assert call.kwargs["recipient"] == user.email
    assert call.kwargs["token"]


def test_forgot_password_creates_reset_token(
    client: TestClient,
    db: Session,
    monkeypatch,
):
    """
    The forgot-password route creates and persists the exact reset token
    that it attempts to send by email.
    """

    user = create_login_user(
        db,
        user_id=6014,
        username="forgottoken",
        email="forgottoken@example.com",
    )

    send_mock = AsyncMock()

    monkeypatch.setattr(
        "app.routers.auth.send_password_reset_email",
        send_mock,
    )

    response = client.post(
        "/api/auth/forgot-password",
        json={
            "email": user.email,
        },
    )

    assert response.status_code == 200

    send_mock.assert_awaited_once()

    sent_token = send_mock.await_args.kwargs["token"]

    assert isinstance(sent_token, str)
    assert sent_token

    statement = select(AuthToken).where(
        AuthToken.user_id == user.id,
        AuthToken.token_type == "password_reset",
        AuthToken.token_hash == hash_token(sent_token),
        AuthToken.used_at.is_(None),
    )

    stored_token = db.scalar(statement)

    assert stored_token is not None

# ============================================================================
# RESET PASSWORD
# ============================================================================


def test_reset_password_valid_token_changes_password(
    client: TestClient,
    db: Session,
):
    """
    A valid password-reset token successfully changes the user's password.
    """

    user = create_login_user(
        db,
        user_id=6021,
        username="resetvalid",
        email="resetvalid@example.com",
    )

    reset_token = create_password_reset_token(
        db,
        user,
    )


    response = client.post(
        "/api/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": "NewPassword@456",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["id"] == user.id
    assert body["email"] == user.email
    assert "password_hash" not in body
    assert "token" not in body
    assert "access_token" not in body

    db.refresh(user)

    assert verify_password(
        "NewPassword@456",
        user.password_hash,
    )

    assert not verify_password(
        "Trackit@123",
        user.password_hash,
    )


def test_reset_password_invalid_token_returns_generic_400(
    client: TestClient,
):
    """
    An invalid reset token produces the generic reset-token error.
    """

    response = client.post(
        "/api/auth/reset-password",
        json={
            "token": "invalid-reset-token",
            "new_password": "NewPassword@456",
        },
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Invalid or expired password reset token.",
    }


def test_reset_password_expired_token_returns_generic_400(
    client: TestClient,
    db: Session,
):
    """
    An expired reset token produces the same generic error as an invalid token.
    """

    user = create_login_user(
        db,
        user_id=6022,
        username="resetexpired",
        email="resetexpired@example.com",
    )

    reset_token = create_password_reset_token(
        db,
        user,
    )


    token_result = db.query(AuthToken).filter(
        AuthToken.user_id == user.id,
        AuthToken.token_type == "password_reset",
    ).one()

    token_result.expires_at = datetime.now(timezone.utc) - timedelta(
        minutes=1,
    )

    db.flush()

    response = client.post(
        "/api/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": "NewPassword@456",
        },
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Invalid or expired password reset token.",
    }


def test_reset_password_token_is_single_use(
    client: TestClient,
    db: Session,
):
    """
    A successful reset consumes the token and prevents reuse.
    """

    user = create_login_user(
        db,
        user_id=6023,
        username="resetsingle",
        email="resetsingle@example.com",
    )

    reset_token = create_password_reset_token(
        db,
        user,
    )


    first_response = client.post(
        "/api/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": "NewPassword@456",
        },
    )

    assert first_response.status_code == 200

    second_response = client.post(
        "/api/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": "AnotherPassword@789",
        },
    )

    assert second_response.status_code == 400
    assert second_response.json() == {
        "detail": "Invalid or expired password reset token.",
    }


def test_reset_password_weak_password_is_rejected(
    client: TestClient,
    db: Session,
):
    """
    Password-strength validation happens at the API schema layer.
    """

    user = create_login_user(
        db,
        user_id=6024,
        username="resetweak",
        email="resetweak@example.com",
    )

    reset_token = create_password_reset_token(
        db,
        user,
    )


    response = client.post(
        "/api/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": "weak",
        },
    )

    assert response.status_code == 422

    db.refresh(user)

    assert verify_password(
        "Trackit@123",
        user.password_hash,
    )


def test_reset_password_blank_token_is_rejected(
    client: TestClient,
):
    """
    A blank reset token is rejected by request validation.
    """

    response = client.post(
        "/api/auth/reset-password",
        json={
            "token": "   ",
            "new_password": "NewPassword@456",
        },
    )

    assert response.status_code == 422
