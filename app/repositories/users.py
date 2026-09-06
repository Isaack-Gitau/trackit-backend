"""
TRACKIT User Repository.

Provides database-access functions for User entities.

Responsibilities:

- Retrieve users by ID.
- Retrieve users by username.
- Retrieve users by email.
- Retrieve users by login identifier.
- Check username/email availability.
- Create users.
- Update authenticated-user profile fields.
- Collect user-owned media storage keys.
- Delete users.

Business rules such as authorization and profile validation
belong in the service layer.

Filesystem operations do NOT belong in this repository.
"""

from collections.abc import Mapping

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.item import Item
from app.models.user import User


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


# ============================================================================
# USER LOOKUP
# ============================================================================


def get_user_by_id(
    db: Session,
    user_id: int,
) -> User | None:
    """
    Retrieve a user by primary key.
    """

    result = db.execute(
        select(User).where(
            User.id == user_id
        )
    )

    return result.scalar_one_or_none()


# -----------------------------------------------------------------------------


def get_user_by_username(
    db: Session,
    username: str,
) -> User | None:
    """
    Retrieve a user by username.

    Username matching is case-insensitive because usernames
    are normalized to lowercase before persistence.
    """

    username = username.strip().lower()

    result = db.execute(
        select(User).where(
            User.username == username
        )
    )

    return result.scalar_one_or_none()


# -----------------------------------------------------------------------------


def get_user_by_email(
    db: Session,
    email: str,
) -> User | None:
    """
    Retrieve a user by email address.

    Email matching is case-insensitive because email addresses
    are normalized to lowercase before persistence.
    """

    email = email.strip().lower()

    result = db.execute(
        select(User).where(
            User.email == email
        )
    )

    return result.scalar_one_or_none()


# -----------------------------------------------------------------------------


def get_user_by_login(
    db: Session,
    login: str,
) -> User | None:
    """
    Retrieve a user using either username or email.
    """

    login = login.strip().lower()

    result = db.execute(
        select(User).where(
            or_(
                User.username == login,
                User.email == login,
            )
        )
    )

    return result.scalar_one_or_none()


# ============================================================================
# EXISTENCE CHECKS
# ============================================================================


def username_exists(
    db: Session,
    username: str,
) -> bool:
    """
    Return True when the username is already registered.
    """

    return (
        get_user_by_username(
            db,
            username,
        )
        is not None
    )


# -----------------------------------------------------------------------------


def email_exists(
    db: Session,
    email: str,
) -> bool:
    """
    Return True when the email address is already registered.
    """

    return (
        get_user_by_email(
            db,
            email,
        )
        is not None
    )


# ============================================================================
# USER CREATION
# ============================================================================


def create_user(
    db: Session,
    *,
    username: str,
    first_name: str,
    last_name: str,
    email: str,
    password_hash: str,
) -> User:
    """
    Create a new TRACKIT user.
    """

    user = User(
        username=username.strip().lower(),
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        email=email.strip().lower(),
        password_hash=password_hash,
        role="user",
        is_active=True,
        is_verified=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


# ============================================================================
# PROFILE AVAILABILITY
# ============================================================================


def get_user_by_username_excluding_id(
    db: Session,
    username: str,
    user_id: int,
) -> User | None:
    """
    Find another user using the supplied username.

    The authenticated user's own record is excluded.

    This is used when changing username so that keeping
    the current username does not trigger a conflict.
    """

    username = username.strip().lower()

    result = db.execute(
        select(User).where(
            User.username == username,
            User.id != user_id,
        )
    )

    return result.scalar_one_or_none()


# -----------------------------------------------------------------------------


def get_user_by_email_excluding_id(
    db: Session,
    email: str,
    user_id: int,
) -> User | None:
    """
    Find another user using the supplied email address.

    The authenticated user's own record is excluded.

    This is used when changing email so that keeping
    the current email does not trigger a conflict.
    """

    email = email.strip().lower()

    result = db.execute(
        select(User).where(
            User.email == email,
            User.id != user_id,
        )
    )

    return result.scalar_one_or_none()


# ============================================================================
# PROFILE UPDATE
# ============================================================================


def update_user_profile(
    db: Session,
    user: User,
    changes: Mapping[str, object],
) -> User:
    """
    Apply explicitly supplied profile changes to a User.

    PATCH semantics:

    - A field present in ``changes`` is updated.
    - A field absent from ``changes`` is left untouched.
    - ``None`` is preserved for nullable fields so that the
      service layer can explicitly clear them.

    Business validation and normalization belong in the service layer.

    This function does not commit the transaction. The request-level
    database dependency controls commit/rollback behavior.
    """

    unknown_fields = set(changes) - PROFILE_UPDATE_FIELDS

    if unknown_fields:
        raise ValueError(
            "Unsupported profile fields: "
            + ", ".join(sorted(unknown_fields))
        )

    for field, value in changes.items():
        setattr(
            user,
            field,
            value,
        )

    db.add(user)
    db.flush()
    db.refresh(user)

    return user


# ============================================================================
# ACCOUNT MEDIA
# ============================================================================


def get_user_media_storage_keys(
    db: Session,
    user: User,
) -> list[str]:
    """
    Collect storage keys for media owned by a user.

    The returned keys are collected before account deletion so that
    the service layer can safely remove the corresponding files after
    the database transaction has successfully committed.

    Includes:

    - The user's profile picture, when present.
    - Images belonging to the user's items, when present.

    This function performs database reads only.

    It does NOT access or modify the filesystem.
    """

    storage_keys: list[str] = []

    if user.profile_picture:
        storage_keys.append(
            user.profile_picture
        )

    result = db.execute(
        select(Item.image).where(
            Item.user_id == user.id,
            Item.image.is_not(None),
        )
    )

    for image_key in result.scalars():
        if image_key:
            storage_keys.append(image_key)

    return storage_keys


# ============================================================================
# USER DELETION
# ============================================================================


def delete_user(
    db: Session,
    user: User,
) -> None:
    """
    Delete a user from the database.

    Database relationships are governed by the existing foreign-key
    constraints and ORM relationship configuration.

    Expected database behavior:

    - User-owned items are deleted through CASCADE.
    - Claims belonging to the user are deleted through CASCADE.
    - Reports belonging to the user are deleted through CASCADE.
    - Comments belonging to the user are deleted through CASCADE.
    - Notifications belonging to the user are deleted through CASCADE.
    - Authentication tokens belonging to the user are deleted through CASCADE.
    - Matches associated with deleted items are deleted through CASCADE.
    - Moderation reviewer references are set to NULL.
    - Audit-log user references are retained with user_id set to NULL.

    The transaction is intentionally NOT committed here.

    The caller controls commit/rollback behavior.
    """

    db.delete(user)
    db.flush()