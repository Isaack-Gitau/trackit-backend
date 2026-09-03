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

from collections.abc import Mapping
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
# PROFILE UPDATE FIELDS
# ============================================================================

PROFILE_UPDATE_FIELDS = {
    "username",
    "email",
    "first_name",
    "last_name",
    "profile_picture",
    "phone_number",
    "bio",
    "address",
    "social_links",
    "preferences",
}

PROFILE_REQUIRED_FIELDS = {
    "username",
    "email",
    "first_name",
    "last_name",
    "social_links",
    "preferences",
}

PROFILE_NULLABLE_FIELDS = {
    "profile_picture",
    "phone_number",
    "bio",
    "address",
}


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
    changes: Mapping[str, object],
) -> User:
    """
    Update the authenticated user's profile.

    PATCH semantics:

    - Only fields present in ``changes`` are modified.
    - A field omitted from ``changes`` remains unchanged.
    - Nullable profile fields may explicitly be set to None.
    - Required profile fields may not be None.
    - Username is normalized to lowercase.
    - Email is normalized to lowercase.
    - Username/email uniqueness is checked against other users.
    - Changing the email address removes email verification.
    - Changing the email address increments token_version and
      therefore invalidates existing authentication sessions.
    - Other profile changes do not invalidate authentication sessions.

    The transaction is flushed but NOT committed.

    The request-level database dependency controls commit
    and rollback behavior.
    """

    # ========================================================================
    # COPY AND VALIDATE SUPPLIED FIELDS
    # ========================================================================

    changes = dict(changes)

    unknown_fields = set(changes) - PROFILE_UPDATE_FIELDS

    if unknown_fields:
        raise ValueError(
            "Unsupported profile fields: "
            + ", ".join(sorted(unknown_fields))
        )

    # ========================================================================
    # VALIDATE NULL VALUES
    # ========================================================================

    for field in PROFILE_REQUIRED_FIELDS:
        if field in changes and changes[field] is None:
            raise ValueError(
                f"{field} cannot be null."
            )

    for field in PROFILE_NULLABLE_FIELDS:
        if field in changes and changes[field] is not None:
            if not isinstance(changes[field], str):
                raise ValueError(
                    f"{field} must be a string or null."
                )

    # ========================================================================
    # NORMALIZE USERNAME
    # ========================================================================

    if "username" in changes:
        username = changes["username"]

        if not isinstance(username, str):
            raise ValueError(
                "Username must be a string."
            )

        normalized_username = (
            username.strip().lower()
        )

        if not normalized_username:
            raise ValueError(
                "Username cannot be empty."
            )

        changes["username"] = normalized_username

    # ========================================================================
    # NORMALIZE EMAIL
    # ========================================================================

    if "email" in changes:
        email = changes["email"]

        if not isinstance(email, str):
            raise ValueError(
                "Email must be a string."
            )

        normalized_email = (
            email.strip().lower()
        )

        if not normalized_email:
            raise ValueError(
                "Email cannot be empty."
            )

        changes["email"] = normalized_email

    # ========================================================================
    # NORMALIZE REQUIRED NAME FIELDS
    # ========================================================================

    if "first_name" in changes:
        first_name = changes["first_name"]

        if not isinstance(first_name, str):
            raise ValueError(
                "First name must be a string."
            )

        first_name = first_name.strip()

        if not first_name:
            raise ValueError(
                "First name cannot be empty."
            )

        changes["first_name"] = first_name

    if "last_name" in changes:
        last_name = changes["last_name"]

        if not isinstance(last_name, str):
            raise ValueError(
                "Last name must be a string."
            )

        last_name = last_name.strip()

        if not last_name:
            raise ValueError(
                "Last name cannot be empty."
            )

        changes["last_name"] = last_name

    # ========================================================================
    # NORMALIZE NULLABLE STRING FIELDS
    #
    # None means "clear this field".
    # A non-None value is stored after trimming whitespace.
    # ========================================================================

    for field in PROFILE_NULLABLE_FIELDS:
        if field not in changes:
            continue

        value = changes[field]

        if value is None:
            continue

        if not isinstance(value, str):
            raise ValueError(
                f"{field} must be a string or null."
            )

        value = value.strip()

        if not value:
            changes[field] = None
        else:
            changes[field] = value

    # ========================================================================
    # VALIDATE JSON PROFILE FIELDS
    # ========================================================================

    for field in (
        "social_links",
        "preferences",
    ):
        if field not in changes:
            continue

        value = changes[field]

        if value is None:
            raise ValueError(
                f"{field} cannot be null."
            )

        if not isinstance(value, dict):
            raise ValueError(
                f"{field} must be an object."
            )

    # ========================================================================
    # USERNAME UNIQUENESS
    # ========================================================================

    if "username" in changes:
        existing_username_user = (
            get_user_by_username_excluding_id(
                db,
                changes["username"],
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

    if "email" in changes:
        existing_email_user = (
            get_user_by_email_excluding_id(
                db,
                changes["email"],
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
        "email" in changes
        and changes["email"] != user.email
    )

    # ========================================================================
    # APPLY PROFILE CHANGES
    # ========================================================================

    update_user_profile(
        db,
        user,
        changes,
    )

    # ========================================================================
    # EMAIL VERIFICATION / SESSION INVALIDATION
    #
    # Only an actual email change invalidates existing sessions.
    # Updating other profile fields leaves token_version unchanged.
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