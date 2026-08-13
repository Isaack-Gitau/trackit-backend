"""
TRACKIT Authentication Service.

Responsible for:

- User registration
- Credential authentication
- Account eligibility checks
- Login
- JWT access-token creation

Short-lived email verification and password-reset
tokens are handled by app.services.tokens.
"""

from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    verify_password,
)
from app.models.user import User
from app.repositories.users import (
    email_exists,
    get_user_by_email,
    get_user_by_id,
    get_user_by_login,
    get_user_by_username,
    username_exists,
)
from app.services.user import create_user_account


# ============================================================================
# User Lookup
# ============================================================================


def find_user_by_id(
    db: Session,
    user_id: int,
) -> User | None:
    """
    Find a TRACKIT user by ID.
    """

    return get_user_by_id(
        db,
        user_id,
    )


def find_user_by_username(
    db: Session,
    username: str,
) -> User | None:
    """
    Find a TRACKIT user by username.
    """

    return get_user_by_username(
        db,
        username,
    )


def find_user_by_email(
    db: Session,
    email: str,
) -> User | None:
    """
    Find a TRACKIT user by email.
    """

    return get_user_by_email(
        db,
        email,
    )


def find_user_by_login(
    db: Session,
    login: str,
) -> User | None:
    """
    Find a TRACKIT user using username or email.
    """

    return get_user_by_login(
        db,
        login,
    )


# ============================================================================
# Registration
# ============================================================================


def register_user(
    db: Session,
    *,
    username: str,
    first_name: str,
    last_name: str,
    email: str,
    password: str,
) -> User:
    """
    Register a new TRACKIT account.

    The password is hashed by the user service before
    being stored in PostgreSQL.
    """

    username = username.strip().lower()
    email = email.strip().lower()

    if username_exists(db, username):
        raise ValueError(
            "Username is already registered."
        )

    if email_exists(db, email):
        raise ValueError(
            "Email is already registered."
        )

    return create_user_account(
        db,
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=password,
    )


# ============================================================================
# Credential Authentication
# ============================================================================


def authenticate_user(
    db: Session,
    login: str,
    password: str,
) -> User | None:
    """
    Validate a user's credentials.

    Returns:
        User when credentials are valid.
        None when credentials are invalid.

    This function intentionally returns None instead of
    revealing whether the username/email exists.
    """

    login = login.strip().lower()

    user = get_user_by_login(
        db,
        login,
    )

    if user is None:
        return None

    if not verify_password(
        password,
        user.password_hash,
    ):
        return None

    return user


# ============================================================================
# Login Eligibility
# ============================================================================


def is_login_allowed(
    user: User,
) -> bool:
    """
    Determine whether a successfully authenticated
    user is allowed to log into TRACKIT.

    Requirements:
    - Account must be active.
    - Email must be verified.
    """

    if not user.is_active:
        return False

    if not user.is_verified:
        return False

    return True


# ============================================================================
# Login
# ============================================================================


def login_user(
    db: Session,
    login: str,
    password: str,
) -> tuple[str, User] | None:
    """
    Authenticate a user and issue a JWT access token.

    Login requires:
    - valid username/email
    - valid password
    - active account
    - verified email

    JWT claims:
    - sub  -> user ID
    - role -> authorization role
    - token_version -> session invalidation version
    """

    user = authenticate_user(
        db,
        login,
        password,
    )

    if user is None:
        return None

    if not is_login_allowed(user):
        return None

    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "role": user.role,
            "token_version": user.token_version,
        }
    )

    return access_token, user