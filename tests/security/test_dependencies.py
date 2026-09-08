"""
TRACKIT Authorization Dependency Security Tests.

Tests:

- Missing authentication
- Invalid authentication scheme
- Empty bearer token
- Invalid JWT
- Nonexistent user
- Inactive user
- Token-version mismatch
- Valid authenticated user
- Verified-user authorization
- Role-based authorization
- Moderator authorization
- Administrator authorization
- Multiple allowed roles
- Invalid role configuration
"""

import pytest
from fastapi import HTTPException
from jose import JWTError

from app.api.deps import (
    get_current_admin,
    get_current_moderator,
    get_current_user,
    get_current_verified_user,
    require_role,
)
from app.core.constants import UserRole
from app.core.security import create_access_token
from app.models.user import User


# ============================================================================
# HELPERS
# ============================================================================


def make_user(
    *,
    user_id: int = 1,
    role: str = UserRole.USER,
    is_active: bool = True,
    is_verified: bool = True,
    token_version: int = 0,
) -> User:
    """
    Create an in-memory TRACKIT user for dependency tests.
    """

    return User(
        id=user_id,
        username=f"user{user_id}",
        first_name="Test",
        last_name="User",
        email=f"user{user_id}@example.com",
        password_hash="unused-test-hash",
        role=role,
        is_active=is_active,
        is_verified=is_verified,
        token_version=token_version,
    )


def make_token(
    *,
    user_id: int = 1,
    role: str = UserRole.USER,
    token_version: int = 0,
) -> str:
    """
    Create a valid TRACKIT access token for testing.
    """

    return create_access_token(
        {
            "sub": str(user_id),
            "role": role,
            "token_version": token_version,
        }
    )


# ============================================================================
# get_current_user
# ============================================================================


def test_get_current_user_requires_credentials(db):
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=None,
            db=db,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Authentication required."


def test_get_current_user_rejects_non_bearer_scheme(db):
    from fastapi.security import HTTPAuthorizationCredentials

    credentials = HTTPAuthorizationCredentials(
        scheme="Basic",
        credentials="some-token",
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=credentials,
            db=db,
        )

    assert exc_info.value.status_code == 401


def test_get_current_user_rejects_empty_bearer_token(db):
    from fastapi.security import HTTPAuthorizationCredentials

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="   ",
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=credentials,
            db=db,
        )

    assert exc_info.value.status_code == 401


def test_get_current_user_rejects_invalid_jwt(db):
    from fastapi.security import HTTPAuthorizationCredentials

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="invalid.jwt.token",
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=credentials,
            db=db,
        )

    assert exc_info.value.status_code == 401


def test_get_current_user_rejects_nonexistent_user(db):
    from fastapi.security import HTTPAuthorizationCredentials

    token = make_token(user_id=999999)

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token,
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=credentials,
            db=db,
        )

    assert exc_info.value.status_code == 401


def test_get_current_user_rejects_inactive_user(db):
    from fastapi.security import HTTPAuthorizationCredentials

    user = make_user(
        user_id=1,
        is_active=False,
    )

    db.add(user)
    db.flush()

    token = make_token(
        user_id=user.id,
        token_version=user.token_version,
    )

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token,
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=credentials,
            db=db,
        )

    assert exc_info.value.status_code == 401


def test_get_current_user_rejects_token_version_mismatch(db):
    from fastapi.security import HTTPAuthorizationCredentials

    user = make_user(
        user_id=1,
        token_version=2,
    )

    db.add(user)
    db.flush()

    token = make_token(
        user_id=user.id,
        token_version=1,
    )

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token,
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=credentials,
            db=db,
        )

    assert exc_info.value.status_code == 401


def test_get_current_user_accepts_valid_user(db):
    from fastapi.security import HTTPAuthorizationCredentials

    user = make_user(
        user_id=1,
        is_active=True,
        token_version=0,
    )

    db.add(user)
    db.flush()

    token = make_token(
        user_id=user.id,
        token_version=user.token_version,
    )

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token,
    )

    result = get_current_user(
        credentials=credentials,
        db=db,
    )

    assert result.id == user.id
    assert result.username == user.username


# ============================================================================
# VERIFIED USER
# ============================================================================


def test_get_current_verified_user_rejects_unverified_user():
    user = make_user(
        is_verified=False,
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_verified_user(
            current_user=user,
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Email verification required."


def test_get_current_verified_user_accepts_verified_user():
    user = make_user(
        is_verified=True,
    )

    result = get_current_verified_user(
        current_user=user,
    )

    assert result is user


# ============================================================================
# ROLE AUTHORIZATION
# ============================================================================


def test_require_role_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        require_role()


def test_require_role_rejects_user_without_required_role():
    dependency = require_role(UserRole.ADMIN)

    user = make_user(
        role=UserRole.USER,
    )

    with pytest.raises(HTTPException) as exc_info:
        dependency(
            current_user=user,
        )

    assert exc_info.value.status_code == 403
    assert (
        exc_info.value.detail
        == "You do not have permission to perform this action."
    )


def test_require_role_accepts_matching_role():
    dependency = require_role(UserRole.ADMIN)

    user = make_user(
        role=UserRole.ADMIN,
    )

    result = dependency(
        current_user=user,
    )

    assert result is user


def test_require_role_supports_multiple_roles():
    dependency = require_role(
        UserRole.ADMIN,
        UserRole.MODERATOR,
    )

    user = make_user(
        role=UserRole.MODERATOR,
    )

    result = dependency(
        current_user=user,
    )

    assert result is user


def test_require_role_normalizes_roles():
    dependency = require_role(
        " ADMIN ",
    )

    user = make_user(
        role=UserRole.ADMIN,
    )

    result = dependency(
        current_user=user,
    )

    assert result is user


# ============================================================================
# MODERATOR
# ============================================================================


def test_get_current_moderator_accepts_moderator():
    user = make_user(
        role=UserRole.MODERATOR,
    )

    result = get_current_moderator(
        current_user=user,
    )

    assert result is user


def test_get_current_moderator_accepts_admin():
    user = make_user(
        role=UserRole.ADMIN,
    )

    result = get_current_moderator(
        current_user=user,
    )

    assert result is user


def test_get_current_moderator_rejects_regular_user():
    dependency = require_role(
        UserRole.MODERATOR,
        UserRole.ADMIN,
    )

    user = make_user(
        role=UserRole.USER,
    )

    with pytest.raises(HTTPException) as exc_info:
        dependency(
            current_user=user,
        )

    assert exc_info.value.status_code == 403
    assert (
        exc_info.value.detail
        == "You do not have permission to perform this action."
    )


# ============================================================================
# ADMINISTRATOR
# ============================================================================


def test_get_current_admin_accepts_admin():
    user = make_user(
        role=UserRole.ADMIN,
    )

    result = get_current_admin(
        current_user=user,
    )

    assert result is user


def test_get_current_admin_rejects_moderator():
    dependency = require_role(UserRole.ADMIN)

    user = make_user(
        role=UserRole.MODERATOR,
    )

    with pytest.raises(HTTPException) as exc_info:
        dependency(
            current_user=user,
        )

    assert exc_info.value.status_code == 403
    assert (
        exc_info.value.detail
        == "You do not have permission to perform this action."
    )


def test_get_current_admin_rejects_regular_user():
    dependency = require_role(UserRole.ADMIN)

    user = make_user(
        role=UserRole.USER,
    )

    with pytest.raises(HTTPException) as exc_info:
        dependency(
            current_user=user,
        )

    assert exc_info.value.status_code == 403
    assert (
        exc_info.value.detail
        == "You do not have permission to perform this action."
    )