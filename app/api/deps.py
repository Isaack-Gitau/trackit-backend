"""
TRACKIT API Dependencies.

Contains reusable FastAPI dependencies for:

- authenticated users
- verified users
- role-based authorization
- administrator authorization

Database sessions are provided by:
    app.db.dependencies
"""

from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.dependencies import get_db
from app.models.user import User
from app.repositories.users import get_user_by_id


# =============================================================================
# HTTP BEARER AUTHENTICATION
# =============================================================================

bearer_scheme = HTTPBearer(
    auto_error=False,
)


# =============================================================================
# CURRENT USER
# =============================================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
    db: Session = Depends(get_db),
) -> User:
    """
    Return the authenticated TRACKIT user.

    Authentication requirements:

    - Authorization header must contain a Bearer token.
    - JWT must be valid.
    - JWT must contain a valid subject.
    - User must exist.
    - User must be active.
    - JWT token_version must match the database.
    """

    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required.",
        headers={
            "WWW-Authenticate": "Bearer",
        },
    )

    # -------------------------------------------------------------------------
    # Authorization header
    # -------------------------------------------------------------------------

    if credentials is None:
        raise unauthorized

    if credentials.scheme.lower() != "bearer":
        raise unauthorized

    token = credentials.credentials.strip()

    if not token:
        raise unauthorized

    # -------------------------------------------------------------------------
    # Decode JWT
    # -------------------------------------------------------------------------

    try:
        payload = decode_access_token(token)
    except JWTError:
        raise unauthorized from None

    # -------------------------------------------------------------------------
    # Extract user ID
    # -------------------------------------------------------------------------

    subject = payload.get("sub")

    if subject is None:
        raise unauthorized

    try:
        user_id = int(subject)
    except (TypeError, ValueError):
        raise unauthorized from None

    # -------------------------------------------------------------------------
    # Load user
    # -------------------------------------------------------------------------

    user = get_user_by_id(
        db,
        user_id,
    )

    if user is None:
        raise unauthorized

    # -------------------------------------------------------------------------
    # Active account check
    # -------------------------------------------------------------------------

    if not user.is_active:
        raise unauthorized

    # -------------------------------------------------------------------------
    # Token version check
    #
    # This allows password changes, password resets, or security events
    # to invalidate previously issued JWT access tokens.
    # -------------------------------------------------------------------------

    token_version = payload.get("token_version")

    if token_version != user.token_version:
        raise unauthorized

    return user


# =============================================================================
# VERIFIED USER
# =============================================================================

def get_current_verified_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Return the authenticated user only if their email is verified.

    Use this dependency for operations that require a verified account.
    """

    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required.",
        )

    return current_user


# =============================================================================
# ROLE AUTHORIZATION
# =============================================================================

def require_role(
    *allowed_roles: str,
) -> Callable:
    """
    Create a dependency requiring one of the specified roles.

    Example:

        current_user: User = Depends(
            require_role("admin")
        )
    """

    normalized_roles = {
        role.strip().lower()
        for role in allowed_roles
        if role and role.strip()
    }

    if not normalized_roles:
        raise ValueError(
            "require_role() requires at least one valid role."
        )

    def role_dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:
        user_role = (current_user.role or "").strip().lower()

        if user_role not in normalized_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )

        return current_user

    return role_dependency


# =============================================================================
# ADMINISTRATOR
# =============================================================================

def get_current_admin(
    current_user: User = Depends(
        require_role("admin")
    ),
) -> User:
    """
    Return the authenticated TRACKIT administrator.
    """

    return current_user