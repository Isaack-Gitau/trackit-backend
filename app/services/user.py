"""
TRACKIT User Service.

Contains business logic related to user accounts and profiles.

Responsibilities:
- Find users
- Create users
- Update profile information
- Activate/deactivate accounts
- Verify email accounts
- Change passwords
- Invalidate authentication sessions

This module does NOT handle HTTP requests.

Transaction policy:

- User-service operations modify the active SQLAlchemy transaction.
- Multi-step security operations must be able to roll back atomically.
- Request-level database dependencies are responsible for committing
  successful requests and rolling back failed requests.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.models.user import User
from app.repositories.users import (
    create_user,
    get_user_by_email,
    get_user_by_email_excluding_id,
    get_user_by_id,
    get_user_by_login,
    get_user_by_username,
    get_user_by_username_excluding_id,
    update_user_profile,
)


# ============================================================================
# USER LOOKUP
# ============================================================================


def get_user(
    db: Session,
    user_id: int,
) -> User | None:
    """
    Retrieve a user by primary key.
    """

    return get_user_by_id(
        db,
        user_id,
    )


def get_user_by_username_service(
    db: Session,
    username: str,
) -> User | None:
    """
    Retrieve a user by username.
    """

    return get_user_by_username(
        db,
        username,
    )


def get_user_by_email_service(
    db: Session,
    email: str,
) -> User | None:
    """
    Retrieve a user by email.
    """

    return get_user_by_email(
        db,
        email,
    )


def get_user_by_login_service(
    db: Session,
    login: str,
) -> User | None:
    """
    Retrieve a user using either username or email.
    """

    return get_user_by_login(
        db,
        login,
    )


# ============================================================================
# ACCOUNT CREATION
# ============================================================================


def create_user_account(
    db: Session,
    *,
    username: str,
    first_name: str,
    last_name: str,
    email: str,
    password: str,
) -> User:
    """
    Create a new TRACKIT user account.

    Passwords are hashed before persistence.
    """

    username = username.strip().lower()
    email = email.strip().lower()

    if get_user_by_username(
        db,
        username,
    ) is not None:
        raise ValueError(
            "Username is already registered."
        )

    if get_user_by_email(
        db,
        email,
    ) is not None:
        raise ValueError(
            "Email is already registered."
        )

    password_hash = hash_password(
        password
    )

    return create_user(
        db,
        username=username,
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        email=email,
        password_hash=password_hash,
    )


# ============================================================================
# PROFILE MANAGEMENT
# ============================================================================


def update_user_profile_service(
    db: Session,
    user: User,
    *,
    username: str | None = None,
    email: str | None = None,
    first_name: str | None = None,
    last_name: str | None = None,
    profile_picture: str | None = None,
    phone_number: str | None = None,
    bio: str | None = None,
    address: str | None = None,
    social_links: dict[str, object] | None = None,
    preferences: dict[str, object] | None = None,
) -> User:
    """
    Update the authenticated user's profile.

    Business rules:

    - Username must be unique.
    - Email must be unique.
    - Username is normalized to lowercase.
    - Email is normalized to lowercase.
    - Changing the email address removes the existing
      email verification status.
    - The authenticated user's own username/email do not
      trigger uniqueness conflicts.
    - Profile fields are updated without changing the
      user's authentication sessions.
    - Changing  the email address invalidates existing authentication sessions  
    - The transaction is flushed but NOT committed.

    The request-level database dependency controls
    commit and rollback behavior.
    """

    # ========================================================================
    # NORMALIZE USERNAME
    # ========================================================================

    normalized_username = None

    if username is not None:
        normalized_username = (
            username.strip().lower()
        )

    # ========================================================================
    # NORMALIZE EMAIL
    # ========================================================================

    normalized_email = None

    if email is not None:
        normalized_email = (
            email.strip().lower()
        )

    # ========================================================================
    # USERNAME UNIQUENESS
    # ========================================================================

    if normalized_username is not None:
        existing_username_user = (
            get_user_by_username_excluding_id(
                db,
                normalized_username,
                user.id,
            )
        )

        if existing_username_user is not None:
            raise ValueError(
                "Username is already registered."
            )

    # ========================================================================
    # EMAIL UNIQUENESS
    # ========================================================================

    if normalized_email is not None:
        existing_email_user = (
            get_user_by_email_excluding_id(
                db,
                normalized_email,
                user.id,
            )
        )

        if existing_email_user is not None:
            raise ValueError(
                "Email is already registered."
            )

    # ========================================================================
    # DETECT EMAIL CHANGE
    # ========================================================================

    email_changed = (
        normalized_email is not None
        and normalized_email != user.email
    )

    # ========================================================================
    # APPLY PROFILE CHANGES
    # ========================================================================

    update_user_profile(
        db,
        user,
        username=normalized_username,
        email=normalized_email,
        first_name=first_name,
        last_name=last_name,
        profile_picture=profile_picture,
        phone_number=phone_number,
        bio=bio,
        address=address,
        social_links=social_links,
        preferences=preferences,
    )

    # ========================================================================
    # EMAIL VERIFICATION
    #
    # A new email address must be verified.
    # ========================================================================

    if email_changed:
        user.is_verified = False
        user.token_version += 1
 
    # ========================================================================
    # UPDATED TIMESTAMP
    # ========================================================================

    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()
    db.refresh(user)

    return user


# ============================================================================
# ACCOUNT VERIFICATION
# ============================================================================


def verify_user_email(
    db: Session,
    user: User,
) -> User:
    """
    Mark a user's email address as verified.

    The transaction is intentionally not committed here.
    """

    if user.is_verified:
        return user

    user.is_verified = True
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()

    return user


# ============================================================================
# ACCOUNT STATUS
# ============================================================================


def activate_user(
    db: Session,
    user: User,
) -> User:
    """
    Activate a user account.

    The transaction is intentionally not committed here.
    """

    user.is_active = True
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()

    return user


def deactivate_user(
    db: Session,
    user: User,
) -> User:
    """
    Deactivate a user account.

    Incrementing token_version invalidates existing JWT sessions.

    The transaction is intentionally not committed here.
    """

    user.is_active = False
    user.token_version += 1
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()

    return user


# ============================================================================
# PASSWORD MANAGEMENT
# ============================================================================


def verify_user_password(
    user: User,
    password: str,
) -> bool:
    """
    Verify a plaintext password against the stored Argon2 hash.
    """

    return verify_password(
        password,
        user.password_hash,
    )


def change_user_password(
    db: Session,
    user: User,
    new_password: str,
) -> User:
    """
    Change a user's password.

    Security:
    - Password is hashed with the central security service.
    - Existing JWT sessions are invalidated.
    - password_changed_at is updated.

    Transaction behavior:
    - Changes are flushed but NOT committed.
    - The caller controls commit/rollback.

    This is necessary so password-reset operations can atomically
    update the password and consume the reset token together.
    """

    now = datetime.now(
        timezone.utc
    )

    user.password_hash = hash_password(
        new_password
    )

    user.password_changed_at = now

    user.token_version += 1

    user.updated_at = now

    db.add(user)
    db.flush()

    return user


# ============================================================================
# SESSION INVALIDATION
# ============================================================================


def invalidate_user_sessions(
    db: Session,
    user: User,
) -> User:
    """
    Invalidate all existing JWT sessions for a user.

    Incrementing token_version causes previously issued
    JWTs to become invalid.

    The transaction is intentionally not committed here.
    """

    user.token_version += 1
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()

    return user