"""
TRACKIT User Service.

Contains business logic related to user accounts and profiles.

Responsibilities:
- Find users
- Create users
- Update profile information
- Delete user accounts
- Activate/deactivate accounts
- Temporarily suspend accounts
- Verify email accounts
- Change passwords
- Promote users to moderator
- Promote moderators to administrator
- Demote administrators to moderator
- Revoke moderator privileges
- Invalidate authentication sessions

This module does NOT handle HTTP requests.

Transaction policy:

- User-service operations modify the active SQLAlchemy transaction.
- Multi-step security operations must be able to roll back atomically.
- Request-level database dependencies are responsible for committing
  successful requests and rolling back failed requests.
"""

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from secrets import compare_digest

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.constants import UserRole
from app.core.security import hash_password, verify_password
from app.models.user import User
from app.repositories.users import (
    count_active_users_by_role,
    count_users,
    count_users_by_role,
    create_user,
    delete_user,
    demote_admin_to_moderator,
    get_expired_suspended_users,
    get_user_by_email,
    get_user_by_email_excluding_id,
    get_user_by_id,
    get_user_by_login,
    get_user_by_username,
    get_user_by_username_excluding_id,
    get_user_media_storage_keys,
    get_users,
    promote_moderator_to_admin,
    promote_user_to_admin_bootstrap,
    promote_user_to_moderator,
    revoke_moderator,
    update_user_profile,
)
from app.schemas.profile import PublicProfileResponse
from app.services.tokens import invalidate_all_user_tokens


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
# ACCOUNT SUSPENSION
# ============================================================================


MIN_SUSPENSION_HOURS = 1
MAX_SUSPENSION_HOURS = 24 * 90


# ============================================================================
# SECURITY CONCURRENCY
# ============================================================================


# PostgreSQL transaction-level advisory lock used to serialize operations
# that can reduce the number of administrators while preserving the
# last-administrator invariant.
#
# This is intentionally a single, dedicated application-level lock key.
# pg_advisory_xact_lock() automatically releases the lock when the current
# transaction commits or rolls back.
ADMIN_INVARIANT_LOCK_KEY = 7_314_159


def _acquire_admin_invariant_lock(
    db: Session,
) -> None:
    """
    Acquire the transaction-level PostgreSQL lock protecting
    administrator-count invariants.

    The lock is held until the surrounding database transaction
    commits or rolls back.

    This prevents concurrent administrator demotions and administrator
    suspensions from both observing the same administrator count and
    subsequently leaving the system without a protected administrator.

    The application uses PostgreSQL as its production database, so this
    PostgreSQL-specific coordination primitive is intentional.
    """

    db.execute(
        text(
            "SELECT pg_advisory_xact_lock(:lock_key)"
        ),
        {
            "lock_key": ADMIN_INVARIANT_LOCK_KEY,
        },
    )


def _invalidate_role_change_authentication(
    db: Session,
    user: User,
) -> None:
    """
    Invalidate authentication state after a role change.

    Role changes are security-sensitive because an existing JWT may
    contain the user's previous role. Incrementing token_version makes
    previously issued JWTs fail the normal current-user authentication
    check.

    Stored authentication tokens are also invalidated.

    The operation is intentionally not committed here. The caller's
    transaction controls commit/rollback.
    """

    user.token_version += 1
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)

    invalidate_all_user_tokens(
        db,
        user_id=user.id,
    )

    db.flush()


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

def list_users_for_admin(
    db: Session,
    *,
    search: str | None = None,
    role: str | None = None,
    status: str | None = None,
    page: int = 1,
    limit: int = 20,
) -> tuple[list[User], int]:
    """
    Retrieve a paginated administrative user directory.

    Business rules:

    - Page numbers start at 1.
    - Limits must be between 1 and 100.
    - Search is case-insensitive and covers username, first name,
      last name, and email.
    - Role may be user, moderator, or admin.
    - Status may be active or inactive.
    - Blank search values are treated as no search filter.
    - The returned total represents the complete filtered population,
      not just the current page.

    The operation performs database reads only and does not modify
    the transaction.

    Returns:
        A tuple containing:
        - the users for the requested page;
        - the total number of users matching the filters.
    """

    if not isinstance(page, int) or isinstance(page, bool):
        raise ValueError(
            "Page must be a whole number."
        )

    if page < 1:
        raise ValueError(
            "Page must be at least 1."
        )

    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ValueError(
            "Limit must be a whole number."
        )

    if limit < 1:
        raise ValueError(
            "Limit must be at least 1."
        )

    if limit > 100:
        raise ValueError(
            "Limit cannot exceed 100."
        )

    normalized_search = (
        search.strip()
        if search is not None
        else None
    )

    if normalized_search == "":
        normalized_search = None

    valid_roles = {
        UserRole.USER,
        UserRole.MODERATOR,
        UserRole.ADMIN,
    }

    if role is not None:
        role = role.strip().lower()

        if role not in valid_roles:
            raise ValueError(
                "Invalid user role."
            )

    if status is not None:
        status = status.strip().lower()

        if status not in {
            "active",
            "inactive",
        }:
            raise ValueError(
                "Invalid account status."
            )

    is_active: bool | None = None

    if status == "active":
        is_active = True
    elif status == "inactive":
        is_active = False

    offset = (page - 1) * limit

    users = get_users(
        db,
        search=normalized_search,
        role=role,
        is_active=is_active,
        offset=offset,
        limit=limit,
    )

    total = count_users(
        db,
        search=normalized_search,
        role=role,
        is_active=is_active,
    )

    return users, total



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

    New accounts are always created with the regular user role.
    Elevated roles must only be assigned through the protected
    administrator-management workflow.

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
# ACCOUNT DELETION
# ============================================================================


def delete_user_account_service(
    db: Session,
    user: User,
) -> list[str]:
    """
    Delete the authenticated user's account.

    Before deleting the database record, collect all media storage keys
    belonging to the account so the corresponding physical files can be
    removed after the database transaction has successfully committed.

    Database behavior:

    - The user record is deleted.
    - User-owned items are deleted through the existing CASCADE relationship.
    - Claims, reports, notifications, comments, matches, and auth tokens
      associated with the deleted user are removed through their existing
      relationships/foreign keys.
    - Reviewer references using SET NULL remain in the database.
    - Audit-log user references using SET NULL remain in the database.

    Filesystem behavior:

    - No files are deleted here.
    - The returned storage keys are intended for post-commit cleanup.

    Transaction behavior:

    - The operation is flushed but NOT committed.
    - The caller controls commit/rollback behavior.

    Returns:
        A list of storage keys belonging to the user's profile picture
        and item images.
    """

    media_storage_keys = get_user_media_storage_keys(
        db,
        user,
    )

    delete_user(
        db,
        user,
    )

    return media_storage_keys


# ============================================================================
# ADMIN ACCOUNT DELETION
# ============================================================================


def delete_user_account_by_admin_service(
    db: Session,
    *,
    target_user: User,
    acting_admin: User,
) -> list[str]:
    """
    Permanently delete a user account on behalf of an administrator.

    Security rules:

    - Only callers already authorized as administrators may invoke
      this service through the API layer.
    - An administrator cannot delete their own account.
    - The final active administrator cannot be deleted.
    - The administrator-count check is serialized using the existing
      PostgreSQL transaction-level advisory lock.
    - All existing user-account deletion cascades are reused.
    - Audit-log rows referencing the deleted user survive through
      their existing ON DELETE SET NULL foreign key.
    - The transaction is flushed but not committed.
    - The caller controls transaction commit/rollback.

    Filesystem behavior:

    - Profile-picture and item-image storage keys are collected before
      deletion.
    - Physical files are not deleted here.
    - The returned storage keys are intended for post-commit cleanup.

    Returns:
        A list of storage keys belonging to the deleted user's profile
        picture and item images.

    Raises:
        ValueError:
            If the administrator attempts to delete themselves or if
            the target is the final administrator.
    """

    if target_user.id == acting_admin.id:
        raise ValueError(
            "An administrator cannot delete their own account."
        )

    target_role = (
        target_user.role or ""
    ).strip().lower()

    if (
        target_role == UserRole.ADMIN
        and target_user.is_active
    ):
        _acquire_admin_invariant_lock(db)

        active_administrator_count = count_active_users_by_role(
            db,
            UserRole.ADMIN,
        )

        if active_administrator_count <= 1:
            raise ValueError(
                "The last active administrator cannot be deleted."
            )

    return delete_user_account_service(
        db,
        target_user,
    )


# ============================================================================
# PROFILE MANAGEMENT
# ============================================================================


def delete_user_profile_picture_service(
    db: Session,
    user: User,
) -> str | None:
    """
    Remove the authenticated user's profile-picture reference.

    The database change is flushed but NOT committed.

    Returns:
        The previous profile-picture storage key, or None when
        the user did not have a profile picture.

    The caller is responsible for committing the transaction before
    deleting the returned physical file from storage.
    """

    previous_image = user.profile_picture

    if not previous_image:
        return None

    user.profile_picture = None
    user.updated_at = datetime.now(timezone.utc)

    db.add(user)
    db.flush()
    db.refresh(user)

    return previous_image



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
    - The role field is never accepted as a profile update.

    The transaction is flushed but NOT committed.

    The request-level database dependency controls commit
    and rollback behavior.
    """

    changes = dict(changes)

    unknown_fields = set(changes) - PROFILE_UPDATE_FIELDS

    if unknown_fields:
        raise ValueError(
            "Unsupported profile fields: "
            + ", ".join(sorted(unknown_fields))
        )

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

    normalized_username: str | None = None

    if "username" in changes:
        username = changes["username"]

        if not isinstance(username, str):
            raise ValueError(
                "Username must be a string."
            )

        normalized_username = username.strip().lower()

        if not normalized_username:
            raise ValueError(
                "Username cannot be empty."
            )

        changes["username"] = normalized_username

    normalized_email: str | None = None

    if "email" in changes:
        email = changes["email"]

        if not isinstance(email, str):
            raise ValueError(
                "Email must be a string."
            )

        normalized_email = email.strip().lower()

        if not normalized_email:
            raise ValueError(
                "Email cannot be empty."
            )

        changes["email"] = normalized_email

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

    email_changed = (
        normalized_email is not None
        and normalized_email != user.email
    )

    update_user_profile(
        db,
        user,
        changes,
    )

    if email_changed:
        user.is_verified = False
        user.token_version += 1

    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.flush()
    db.refresh(user)

    return user


def update_user_privacy_service(
    db: Session,
    user: User,
    changes: Mapping[str, bool | None],
) -> dict[str, bool]:
    """
    Update the authenticated user's public-profile privacy settings.

    Privacy settings are stored inside the existing ``preferences`` JSON
    object under the ``privacy`` key.

    PATCH semantics:

    - Omitted fields remain unchanged.
    - True makes the corresponding profile field public.
    - False keeps the corresponding profile field private.
    - Existing unrelated preference keys are preserved.

    The transaction is flushed but NOT committed.

    The request-level database dependency controls commit
    and rollback behavior.
    """

    allowed_fields = {
        "profile_picture",
        "bio",
        "first_name",
        "last_name",
        "email",
        "phone_number",
        "social_links",
    }

    changes = dict(changes)

    unknown_fields = set(changes) - allowed_fields

    if unknown_fields:
        raise ValueError(
            "Unsupported privacy fields: "
            + ", ".join(sorted(unknown_fields))
        )

    for field, value in changes.items():
        if value is not None and not isinstance(value, bool):
            raise ValueError(
                f"{field} privacy setting must be true or false."
            )

    existing_preferences = user.preferences

    if not isinstance(existing_preferences, dict):
        existing_preferences = {}

    preferences = dict(existing_preferences)

    existing_privacy = preferences.get("privacy")

    if not isinstance(existing_privacy, dict):
        existing_privacy = {}

    privacy = dict(existing_privacy)

    default_privacy = {
        "profile_picture": True,
        "bio": True,
        "first_name": False,
        "last_name": False,
        "email": False,
        "phone_number": False,
        "social_links": False,
    }

    for field, default in default_privacy.items():
        value = privacy.get(field)

        if not isinstance(value, bool):
            privacy[field] = default

    for field, value in changes.items():
        if value is not None:
            privacy[field] = value

    preferences["privacy"] = privacy

    user.preferences = preferences
    user.updated_at = datetime.now(timezone.utc)

    db.add(user)
    db.flush()
    db.refresh(user)

    return {
        field: bool(privacy[field])
        for field in default_privacy
    }


def get_public_user_profile_service(
    db: Session,
    user_id: int,
) -> PublicProfileResponse | None:
    """
    Retrieve the public profile of an active user.

    Inactive users are treated the same as nonexistent users and
    therefore return None.

    Only explicitly permitted public-profile fields are returned.
    Sensitive account, security, administrative, address, and
    preference data is never exposed.
    """

    user = get_user_by_id(
        db,
        user_id,
    )

    if user is None or not user.is_active:
        return None

    default_privacy = {
        "profile_picture": True,
        "bio": True,
        "first_name": False,
        "last_name": False,
        "email": False,
        "phone_number": False,
        "social_links": False,
    }

    preferences = user.preferences

    if not isinstance(preferences, dict):
        preferences = {}

    stored_privacy = preferences.get("privacy")

    if not isinstance(stored_privacy, dict):
        stored_privacy = {}

    privacy = dict(default_privacy)

    for field in default_privacy:
        value = stored_privacy.get(field)

        if isinstance(value, bool):
            privacy[field] = value

    return PublicProfileResponse(
        id=user.id,
        username=user.username,
        profile_picture=(
            user.profile_picture
            if privacy["profile_picture"]
            else None
        ),
        bio=(
            user.bio
            if privacy["bio"]
            else None
        ),
        first_name=(
            user.first_name
            if privacy["first_name"]
            else None
        ),
        last_name=(
            user.last_name
            if privacy["last_name"]
            else None
        ),
        email=(
            user.email
            if privacy["email"]
            else None
        ),
        phone_number=(
            user.phone_number
            if privacy["phone_number"]
            else None
        ),
        social_links=(
            dict(user.social_links)
            if privacy["social_links"]
            else {}
        ),
    )


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

    This operation also clears any scheduled suspension metadata.

    Activation invalidates existing authentication sessions by
    incrementing token_version.

    The transaction is intentionally not committed here.
    """

    now = datetime.now(
        timezone.utc
    )

    user.is_active = True
    user.deactivated_at = None
    user.deactivated_until = None
    user.deactivation_reason = None

    user.token_version += 1
    user.updated_at = now

    db.add(user)

    invalidate_all_user_tokens(
        db,
        user_id=user.id,
    )

    db.flush()

    return user


def deactivate_user(
    db: Session,
    user: User,
) -> User:
    """
    Deactivate a user account.

    This is the generic account-deactivation operation.

    Incrementing token_version invalidates existing JWT sessions.
    Stored authentication tokens are also invalidated.

    The transaction is intentionally not committed here.
    """

    now = datetime.now(
        timezone.utc
    )

    user.is_active = False
    user.deactivated_at = None
    user.deactivated_until = None
    user.deactivation_reason = None

    user.token_version += 1
    user.updated_at = now

    db.add(user)

    invalidate_all_user_tokens(
        db,
        user_id=user.id,
    )

    db.flush()

    return user


def suspend_user(
    db: Session,
    *,
    target_user: User,
    acting_admin: User,
    duration_hours: int,
    reason: str | None = None,
) -> User:
    """
    Temporarily suspend a user account.

    Security rules:

    - Only administrators may perform this operation through the
      protected API workflow.
    - Administrators cannot suspend themselves.
    - An already inactive account cannot be suspended again.
    - The final active administrator cannot be suspended.
    - Duration must be a whole number of hours.
    - Minimum duration is 1 hour.
    - Maximum duration is 90 days / 2160 hours.
    - Reason is optional and limited to 500 characters.
    - The user's existing role is preserved.
    - Existing JWT sessions are invalidated through token_version.
    - Stored authentication tokens are invalidated.
    - Suspension metadata is persisted on the user record.
    - The operation is flushed but not committed.

    ``deactivated_at`` records the suspension start time.

    ``deactivated_until`` records the automatic reactivation time.

    ``deactivation_reason`` stores the optional administrative reason.

    Raises:
        ValueError:
            If the operation violates any suspension rule.
    """

    if target_user.id == acting_admin.id:
        raise ValueError(
            "An administrator cannot suspend themselves."
        )

    if not isinstance(duration_hours, int) or isinstance(
        duration_hours,
        bool,
    ):
        raise ValueError(
            "Suspension duration must be a whole number of hours."
        )

    if duration_hours < MIN_SUSPENSION_HOURS:
        raise ValueError(
            "Suspension duration must be at least 1 hour."
        )

    if duration_hours > MAX_SUSPENSION_HOURS:
        raise ValueError(
            "Suspension duration cannot exceed 90 days."
        )

    if not target_user.is_active:
        raise ValueError(
            "User account is already inactive."
        )

    target_role = (
        (target_user.role or "")
        .strip()
        .lower()
    )

    if target_role == UserRole.ADMIN:
        # The lock must be acquired before counting active administrators.
        # Otherwise two concurrent suspension requests could both observe
        # the same count and both suspend an administrator.
        _acquire_admin_invariant_lock(db)

        active_admin_count = count_active_users_by_role(
            db,
            UserRole.ADMIN,
        )

        if active_admin_count <= 1:
            raise ValueError(
                "The last active administrator cannot be suspended."
            )

    if reason is not None:
        if not isinstance(reason, str):
            raise ValueError(
                "Suspension reason must be a string or null."
            )

        reason = reason.strip()

        if not reason:
            reason = None

        if reason is not None and len(reason) > 500:
            raise ValueError(
                "Suspension reason cannot exceed 500 characters."
            )

    now = datetime.now(
        timezone.utc
    )

    deactivated_until = (
        now
        + timedelta(
            hours=duration_hours
        )
    )

    target_user.is_active = False
    target_user.deactivated_at = now
    target_user.deactivated_until = deactivated_until
    target_user.deactivation_reason = reason

    target_user.token_version += 1
    target_user.updated_at = now

    db.add(target_user)

    invalidate_all_user_tokens(
        db,
        user_id=target_user.id,
    )

    db.flush()

    return target_user


def activate_suspended_user(
    db: Session,
    user: User,
) -> User:
    """
    Reactivate a temporarily suspended account.

    This function is intended for both:

    - manual administrator activation;
    - automatic scheduled reactivation.

    The target must currently represent a valid temporary suspension:

    - is_active must be False;
    - deactivated_at must be present;
    - deactivated_until must be present.

    This prevents unrelated inactive accounts from being incorrectly
    treated as suspended accounts.

    The user's existing role is preserved.

    Suspension metadata is cleared.

    Authentication sessions are invalidated again to ensure that
    no stale authentication state survives the suspension lifecycle.

    The transaction is intentionally not committed here.
    """

    if user.is_active:
        raise ValueError(
            "User account is already active."
        )

    if (
        user.deactivated_at is None
        or user.deactivated_until is None
    ):
        raise ValueError(
            "User account is not currently suspended."
        )

    now = datetime.now(
        timezone.utc
    )

    user.is_active = True
    user.deactivated_at = None
    user.deactivated_until = None
    user.deactivation_reason = None

    user.token_version += 1
    user.updated_at = now

    db.add(user)

    invalidate_all_user_tokens(
        db,
        user_id=user.id,
    )

    db.flush()

    return user


# ============================================================================
# ADMINISTRATION
# ============================================================================


def promote_user_to_moderator_service(
    db: Session,
    *,
    target_user: User,
    acting_admin: User,
) -> User:
    """
    Promote a regular user account to moderator.

    Security rules:

    - Only callers already authorized as administrators may invoke
      this service through the API layer.
    - An administrator cannot promote themselves.
    - A user who is already a moderator cannot be promoted again.
    - An administrator cannot be promoted to moderator.
    - Only a regular user account may enter the moderator role.
    - Existing authentication sessions are invalidated after the role
      change.
    - Stored authentication tokens are invalidated after the role change.
    - The operation is flushed but not committed.
    - The caller controls transaction commit/rollback.

    Raises:
        ValueError:
            If the acting administrator attempts to promote themselves,
            if the target already has an elevated role, or if the target
            has an unexpected role.
    """

    if target_user.id == acting_admin.id:
        raise ValueError(
            "An administrator cannot promote themselves."
        )

    target_role = (
        (target_user.role or "")
        .strip()
        .lower()
    )

    if target_role == UserRole.MODERATOR:
        raise ValueError(
            "User is already a moderator."
        )

    if target_role == UserRole.ADMIN:
        raise ValueError(
            "User is already an administrator."
        )

    if target_role != UserRole.USER:
        raise ValueError(
            "Only regular users can be promoted to moderator."
        )

    promoted_user = promote_user_to_moderator(
        db,
        target_user,
    )

    _invalidate_role_change_authentication(
        db,
        promoted_user,
    )

    return promoted_user


# -----------------------------------------------------------------------------
# FIRST ADMINISTRATOR BOOTSTRAP
# -----------------------------------------------------------------------------


def bootstrap_first_admin_service(
    db: Session,
    *,
    target_user: User,
    bootstrap_username: str,
    provided_secret: str,
    configured_secret: str,
) -> User:
    """
    Promote the configured first administrator account directly
    from regular user to administrator.

    This is a one-time initialization path and is intentionally
    separate from the normal:

        user → moderator → administrator

    role lifecycle.

    Security requirements:

    - The bootstrap secret must be configured.
    - The provided secret must match the configured secret.
    - The target username must match the configured bootstrap username.
    - The target account must be active.
    - The target account must be verified.
    - The target account must currently be a regular user.
    - No active administrator may already exist.
    - Administrator-count checks are serialized using the existing
      PostgreSQL transaction-level advisory lock.
    - Existing authentication sessions are invalidated after
      the role change.
    - The operation is flushed but not committed.
    - The caller controls transaction commit/rollback.

    Raises:
        ValueError:
            If any bootstrap requirement is not satisfied.
    """

    normalized_bootstrap_username = (
        bootstrap_username or ""
    ).strip().lower()

    normalized_target_username = (
        target_user.username or ""
    ).strip().lower()

    if not configured_secret:
        raise ValueError(
            "Administrator bootstrap is not configured."
        )

    if not normalized_bootstrap_username:
        raise ValueError(
            "Administrator bootstrap username is not configured."
        )

    if not provided_secret or not compare_digest(
        provided_secret,
        configured_secret,
    ):
        raise ValueError(
            "Invalid administrator bootstrap credentials."
        )

    if (
        normalized_target_username
        != normalized_bootstrap_username
    ):
        raise ValueError(
            "This account is not authorized for administrator bootstrap."
        )

    if not target_user.is_active:
        raise ValueError(
            "The bootstrap account must be active."
        )

    if not target_user.is_verified:
        raise ValueError(
            "Email verification is required before administrator bootstrap."
        )

    target_role = (
        (target_user.role or "")
        .strip()
        .lower()
    )

    if target_role != UserRole.USER:
        raise ValueError(
            "Only a regular user account can be used for administrator bootstrap."
        )

    # Serialize the first-administrator check against other operations
    # that can change the administrator count.
    _acquire_admin_invariant_lock(db)

    active_admin_count = count_active_users_by_role(
        db,
        UserRole.ADMIN,
    )

    if active_admin_count > 0:
        raise ValueError(
            "Administrator bootstrap is no longer available."
        )

    promoted_user = promote_user_to_admin_bootstrap(
        db,
        target_user,
    )

    _invalidate_role_change_authentication(
        db,
        promoted_user,
    )

    return promoted_user


# -----------------------------------------------------------------------------
# NORMAL MODERATOR → ADMINISTRATOR PROMOTION
# ----------------------------------------------------------------------------


def promote_moderator_to_admin_service(
    db: Session,
    *,
    target_user: User,
    acting_admin: User,
) -> User:
    """
    Promote an existing moderator account to administrator.

    Security rules:

    - Only callers already authorized as administrators may invoke
      this service through the API layer.
    - An administrator cannot promote themselves.
    - An account that is already an administrator cannot be promoted again.
    - Only an existing moderator may be promoted to administrator.
    - Existing authentication sessions are invalidated after the role
      change.
    - Stored authentication tokens are invalidated after the role change.
    - The operation is flushed but not committed.
    - The caller controls transaction commit/rollback.

    Raises:
        ValueError:
            If the acting administrator attempts to promote themselves,
            if the target is already an administrator, or if the target
            is not currently a moderator.
    """

    if target_user.id == acting_admin.id:
        raise ValueError(
            "An administrator cannot promote themselves."
        )

    target_role = (
        (target_user.role or "")
        .strip()
        .lower()
    )

    if target_role == UserRole.ADMIN:
        raise ValueError(
            "User is already an administrator."
        )

    if target_role != UserRole.MODERATOR:
        raise ValueError(
            "Only moderators can be promoted to administrator."
        )

    promoted_user = promote_moderator_to_admin(
        db,
        target_user,
    )

    _invalidate_role_change_authentication(
        db,
        promoted_user,
    )

    return promoted_user


# -----------------------------------------------------------------------------


def demote_admin_to_moderator_service(
    db: Session,
    *,
    target_user: User,
    acting_admin: User,
) -> User:
    """
    Demote an administrator account to moderator.

    Security rules:

    - Only callers already authorized as administrators may invoke
      this service through the API layer.
    - An administrator cannot demote themselves.
    - The final remaining administrator cannot be demoted.
    - Only an existing administrator may be demoted through this workflow.
    - The administrator-count check is serialized using a PostgreSQL
      transaction-level advisory lock.
    - Existing authentication sessions are invalidated after the role
      change.
    - Stored authentication tokens are invalidated after the role change.
    - The operation is flushed but not committed.
    - The caller controls transaction commit/rollback.

    Raises:
        ValueError:
            If the acting administrator attempts to demote themselves,
            if the target is not an administrator, or if the target is
            the last remaining administrator.
    """

    if target_user.id == acting_admin.id:
        raise ValueError(
            "An administrator cannot demote themselves."
        )

    target_role = (
        (target_user.role or "")
        .strip()
        .lower()
    )

    if target_role != UserRole.ADMIN:
        raise ValueError(
            "User is not an administrator."
        )

    # Acquire the lock before counting administrators so concurrent
    # demotions cannot both observe the same administrator count.
    _acquire_admin_invariant_lock(db)

    admin_count = count_users_by_role(
        db,
        UserRole.ADMIN,
    )

    if admin_count <= 1:
        raise ValueError(
            "The last administrator cannot be demoted."
        )

    demoted_user = demote_admin_to_moderator(
        db,
        target_user,
    )

    _invalidate_role_change_authentication(
        db,
        demoted_user,
    )

    return demoted_user


# -----------------------------------------------------------------------------


def revoke_moderator_service(
    db: Session,
    *,
    target_user: User,
    acting_admin: User,
) -> User:
    """
    Revoke moderator privileges from an existing moderator.

    The moderator is returned to the regular user role.

    Security rules:

    - Only callers already authorized as administrators may invoke
      this service through the API layer.
    - An administrator cannot demote themselves.
    - Administrators cannot be directly revoked to regular users.
    - Only an existing moderator may be revoked through this workflow.
    - Existing authentication sessions are invalidated after the role
      change.
    - Stored authentication tokens are invalidated after the role change.
    - The operation is flushed but not committed.
    - The caller controls transaction commit/rollback.

    Raises:
        ValueError:
            If the acting administrator targets themselves,
            if the target is an administrator, or if the target
            is not currently a moderator.
    """

    if target_user.id == acting_admin.id:
        raise ValueError(
            "An administrator cannot demote themselves."
        )

    target_role = (
        (target_user.role or "")
        .strip()
        .lower()
    )

    if target_role == UserRole.ADMIN:
        raise ValueError(
            "Administrators cannot be revoked to regular users."
        )

    if target_role != UserRole.MODERATOR:
        raise ValueError(
            "User is not a moderator."
        )

    revoked_user = revoke_moderator(
        db,
        target_user,
    )

    _invalidate_role_change_authentication(
        db,
        revoked_user,
    )

    return revoked_user


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
    - Existing stored authentication tokens are invalidated.
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

    invalidate_all_user_tokens(
        db,
        user_id=user.id,
    )

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
    Invalidate all existing authentication sessions for a user.

    Security behavior:

    - Increment token_version to invalidate previously issued JWTs.
    - Invalidate all unused stored authentication tokens.

    The transaction is intentionally not committed here.
    """

    user.token_version += 1
    user.updated_at = datetime.now(
        timezone.utc
    )

    db.add(user)

    invalidate_all_user_tokens(
        db,
        user_id=user.id,
    )

    db.flush()

    return user


# ============================================================================
# AUTOMATIC SUSPENSION EXPIRATION
# ============================================================================


def reactivate_expired_suspended_users(
    db: Session,
    *,
    now: datetime | None = None,
) -> list[User]:
    """
    Reactivate users whose temporary suspensions have expired.

    This function is intended for scheduled/background execution.

    Workflow:

    1. Retrieve suspended users whose deactivation deadline has
       been reached.
    2. Reactivate each account using the central suspension
       activation workflow.
    3. Preserve each user's existing role.
    4. Clear suspension metadata.
    5. Invalidate authentication sessions again.
    6. Flush all changes without committing.

    Args:
        db:
            Active SQLAlchemy session.

        now:
            Optional UTC timestamp used for deterministic tests.
            When omitted, the repository determines the current
            UTC time.

    Returns:
        A list of users successfully reactivated during this
        execution.

    Transaction behavior:

        Changes are flushed but NOT committed. The caller controls
        transaction commit or rollback.
    """

    expired_users = get_expired_suspended_users(
        db,
        now=now,
    )

    reactivated_users: list[User] = []

    for user in expired_users:
        activate_suspended_user(
            db,
            user,
        )
        reactivated_users.append(user)

    return reactivated_users