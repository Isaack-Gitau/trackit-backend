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
- List and count users for administrative directory workflows.
- Update authenticated-user profile fields.
- Collect user-owned media storage keys.
- Delete users.
- Apply role changes.

Business rules such as authorization and profile validation
belong in the service layer.

Filesystem operations do NOT belong in this repository.
"""

from collections.abc import Mapping
from datetime import datetime, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.constants import UserRole
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


def get_users_by_ids(
    db: Session,
    user_ids: list[int],
) -> list[User]:
    """
    Retrieve multiple users by primary key.

    Only database access belongs in this repository.
    Validation of requested recipients belongs in the service layer.

    Args:
        db: Active SQLAlchemy session.
        user_ids: User IDs to retrieve.

    Returns:
        Users whose IDs exist in the database.

    Notes:
        The returned list contains only existing users. The service
        layer is responsible for detecting missing requested IDs.
    """

    if not user_ids:
        return []

    result = db.execute(
        select(User).where(
            User.id.in_(user_ids)
        )
    )

    return list(
        result.scalars().all()
    )


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

    New accounts are always created with the regular user role.
    Elevated roles must be assigned through the administrative
    role-management workflow.
    """

    user = User(
        username=username.strip().lower(),
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        email=email.strip().lower(),
        password_hash=password_hash,
        role=UserRole.USER,
        is_active=True,
        is_verified=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


# ============================================================================
# ADMINISTRATIVE USER DIRECTORY
# ============================================================================


def get_users(
    db: Session,
    *,
    search: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    offset: int = 0,
    limit: int = 20,
) -> list[User]:
    """
    Retrieve a filtered page of users for the administrative directory.

    Database access only. Validation of search values, roles, page
    numbers, and limits belongs in the service/API layers.

    Args:
        db:
            Active SQLAlchemy session.

        search:
            Optional case-insensitive search across username,
            first name, last name, and email.

        role:
            Optional exact role filter.

        is_active:
            Optional account-status filter.

        offset:
            Number of matching records to skip.

        limit:
            Maximum number of records to return.

    Returns:
        Users matching the supplied filters, ordered by newest
        account first with user ID as a deterministic tie-breaker.
    """

    query = select(User)

    filters = []

    if search:
        search_pattern = f"%{search}%"

        filters.append(
            or_(
                User.username.ilike(search_pattern),
                User.first_name.ilike(search_pattern),
                User.last_name.ilike(search_pattern),
                User.email.ilike(search_pattern),
            )
        )

    if role is not None:
        filters.append(
            User.role == role
        )

    if is_active is not None:
        filters.append(
            User.is_active.is_(is_active)
        )

    if filters:
        query = query.where(*filters)

    query = (
        query
        .order_by(
            User.created_at.desc(),
            User.id.desc(),
        )
        .offset(offset)
        .limit(limit)
    )

    result = db.execute(query)

    return list(
        result.scalars().all()
    )


# -----------------------------------------------------------------------------


def count_users(
    db: Session,
    *,
    search: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
) -> int:
    """
    Count users matching the administrative directory filters.

    The filtering rules intentionally mirror ``get_users()`` so the
    returned total represents the same population as the paginated
    directory query.
    """

    query = select(
        func.count(User.id)
    )

    filters = []

    if search:
        search_pattern = f"%{search}%"

        filters.append(
            or_(
                User.username.ilike(search_pattern),
                User.first_name.ilike(search_pattern),
                User.last_name.ilike(search_pattern),
                User.email.ilike(search_pattern),
            )
        )

    if role is not None:
        filters.append(
            User.role == role
        )

    if is_active is not None:
        filters.append(
            User.is_active.is_(is_active)
        )

    if filters:
        query = query.where(*filters)

    result = db.execute(query)

    return int(
        result.scalar_one()
    )


# ============================================================================
# ROLE MANAGEMENT
# ============================================================================


def count_users_by_role(
    db: Session,
    role: str,
) -> int:
    """
    Count users currently assigned to a specific role.

    This function performs a database read only.

    Role values should normally come from the centralized
    UserRole constants.
    """

    result = db.execute(
        select(
            func.count(User.id)
        ).where(
            User.role == role
        )
    )

    return int(
        result.scalar_one()
    )


def count_active_users_by_role(
    db: Session,
    role: str,
) -> int:
    """
    Count active users currently assigned to a specific role.

    This function performs a database read only.

    Role values should normally come from the centralized
    UserRole constants.
    """

    result = db.execute(
        select(
            func.count(User.id)
        ).where(
            User.role == role,
            User.is_active.is_(True),
        )
    )

    return int(
        result.scalar_one()
    )


def get_expired_suspended_users(
    db: Session,
    *,
    now: datetime | None = None,
) -> list[User]:
    """
    Retrieve currently suspended users whose scheduled suspension
    has expired.

    The repository performs database access only. Reactivation
    business logic belongs in the service layer.

    Args:
        db: Active SQLAlchemy session.
        now: Optional UTC timestamp used for deterministic tests.
            When omitted, the current UTC time is used.

    Returns:
        A list of suspended users whose deactivation deadline
        has been reached.
    """

    if now is None:
        now = datetime.now(
            timezone.utc
        )

    result = db.execute(
        select(User)
        .where(
            User.is_active.is_(False),
            User.deactivated_until.is_not(None),
            User.deactivated_until <= now,
        )
        .order_by(
            User.deactivated_until.asc(),
            User.id.asc(),
        )
    )

    return list(
        result.scalars().all()
    )


# -----------------------------------------------------------------------------


def promote_user_to_moderator(
    db: Session,
    user: User,
) -> User:
    """
    Promote an existing user account to moderator.

    The operation is intentionally not committed here.
    The caller controls transaction commit/rollback.
    """

    user.role = UserRole.MODERATOR
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()
    db.refresh(user)

    return user


# -----------------------------------------------------------------------------


def promote_moderator_to_admin(
    db: Session,
    user: User,
) -> User:
    """
    Promote an existing moderator account to administrator.

    The operation is intentionally not committed here.
    The caller controls transaction commit/rollback.
    """

    user.role = UserRole.ADMIN
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()
    db.refresh(user)

    return user


# -----------------------------------------------------------------------------

def promote_user_to_admin_bootstrap(
    db: Session,
    user: User,
) -> User:
    """
    Promote the configured bootstrap user directly to administrator.

    This operation exists only for first-administrator bootstrap.
    Security checks belong to the service layer.

    The operation is intentionally not committed here.
    The caller controls transaction commit/rollback.
    """

    user.role = UserRole.ADMIN
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()
    db.refresh(user)

    return user



def demote_admin_to_moderator(
    db: Session,
    user: User,
) -> User:
    """
    Demote an administrator account to moderator.

    The operation is intentionally not committed here.
    The caller controls transaction commit/rollback.
    """

    user.role = UserRole.MODERATOR
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()
    db.refresh(user)

    return user


# -----------------------------------------------------------------------------


def revoke_moderator(
    db: Session,
    user: User,
) -> User:
    """
    Revoke moderator privileges and return the account to
    the regular user role.

    The operation is intentionally not committed here.
    The caller controls transaction commit/rollback.
    """

    user.role = UserRole.USER
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()
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
