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

Business rules such as authorization and profile validation
belong in the service layer.
"""

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.user import User


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
    Apply profile changes to a User.

    Only fields explicitly supplied by the service layer
    are modified.

    This function does not commit the transaction. The request-level
    database dependency controls commit/rollback behavior.
    """

    if username is not None:
        user.username = username.strip().lower()

    if email is not None:
        user.email = email.strip().lower()

    if first_name is not None:
        user.first_name = first_name.strip()

    if last_name is not None:
        user.last_name = last_name.strip()

    if profile_picture is not None:
        user.profile_picture = profile_picture.strip()

    if phone_number is not None:
        user.phone_number = phone_number.strip()

    if bio is not None:
        user.bio = bio.strip()

    if address is not None:
        user.address = address.strip()

    if social_links is not None:
        user.social_links = social_links

    if preferences is not None:
        user.preferences = preferences

    db.add(user)
    db.flush()
    db.refresh(user)

    return user