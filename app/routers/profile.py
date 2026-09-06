"""
TRACKIT Profile Router.

Provides authenticated-user profile endpoints,
account management, and authorized administrative
user inspection.

Endpoints:

    GET    /api/profile
    PATCH  /api/profile
    DELETE /api/profile/account

    GET    /api/profile/admin/{user_id}

Users may:
- View their own profile.
- Update their username.
- Update their email.
- Update their first name.
- Update their last name.
- Update their profile picture.
- Update their phone number.
- Update their bio.
- Update their address.
- Update their social links.
- Update their preferences.
- Permanently delete their own account.

Administrators may:
- View any user's detailed account/profile information.

Administrative responses deliberately exclude
authentication and security secrets.

Account deletion requires the user's current
password and permanently removes the account
and its user-owned data.
"""

import logging

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import (
    get_current_admin,
    get_current_user,
)
from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.profile import (
    AdminUserDetailResponse,
    ProfileResponse,
    ProfileUpdate,
)
from app.services.user import (
    delete_user_account_service,
    get_user,
    update_user_profile_service,
    verify_user_password,
)
from app.utils.images import delete_stored_image


# ============================================================================
# LOGGING
# ============================================================================

logger = logging.getLogger(__name__)


# ============================================================================
# ROUTER
# ============================================================================

router = APIRouter(
    prefix="/profile",
    tags=["Profile"],
)


# ============================================================================
# GET CURRENT USER PROFILE
# ============================================================================


@router.get(
    "",
    response_model=ProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile",
)
def get_profile(
    current_user: User = Depends(get_current_user),
) -> ProfileResponse:
    """
    Return the profile belonging to the authenticated user.

    The user is identified from the JWT.

    A user cannot request another user's profile through
    this endpoint.
    """

    return ProfileResponse.model_validate(
        current_user
    )


# ============================================================================
# UPDATE CURRENT USER PROFILE
# ============================================================================


@router.patch(
    "",
    response_model=ProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Update current user profile",
)
def update_profile(
    profile_data: ProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProfileResponse:
    """
    Update the authenticated user's profile.

    Supported fields include:

    - username
    - email
    - first_name
    - last_name
    - profile_picture
    - phone_number
    - bio
    - address
    - social_links
    - preferences

    PATCH semantics are preserved:

    - Omitted fields are left unchanged.
    - Nullable fields supplied as null are cleared.
    - Nullable string fields supplied as an empty string are
      normalized by the schema to null and therefore cleared.
    - Required fields cannot be null or empty.
    - social_links and preferences cannot be null.

    Email changes also invalidate existing authentication
    sessions through the user service.
    """

    # -------------------------------------------------------------------------
    # Determine exactly which fields were supplied.
    #
    # exclude_unset=True is essential for PATCH semantics.
    #
    # Example:
    #
    #     {}
    #
    # means "change nothing".
    #
    # Whereas:
    #
    #     {"bio": None}
    #
    # means "explicitly clear the bio".
    #
    # We must preserve that distinction when passing the changes
    # to the service layer.
    # -------------------------------------------------------------------------

    changes = profile_data.model_dump(
        exclude_unset=True
    )

    # -------------------------------------------------------------------------
    # Empty PATCH body
    # -------------------------------------------------------------------------

    if not changes:
        return ProfileResponse.model_validate(
            current_user
        )

    # -------------------------------------------------------------------------
    # Update profile
    #
    # Pass the complete changes mapping to the service rather than
    # expanding it into keyword arguments.
    #
    # This allows the service/repository to distinguish:
    #
    #     field omitted
    #
    # from:
    #
    #     field explicitly supplied as None
    # -------------------------------------------------------------------------

    try:
        updated_user = update_user_profile_service(
            db,
            current_user,
            changes,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    # -------------------------------------------------------------------------
    # Protect against database-level uniqueness races.
    #
    # The service performs the normal uniqueness check, but the
    # database unique indexes remain the final protection.
    # -------------------------------------------------------------------------

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered.",
        ) from None

    # -------------------------------------------------------------------------
    # Return the updated profile.
    # -------------------------------------------------------------------------

    return ProfileResponse.model_validate(
        updated_user
    )


# ============================================================================
# DELETE CURRENT USER ACCOUNT
# ============================================================================


@router.delete(
    "/account",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Permanently delete current user account",
)
def delete_account(
    password: str = Body(
        ...,
        embed=True,
        min_length=1,
        description="Current account password required to permanently delete the account.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """
    Permanently delete the authenticated user's account.

    Security:

    - The request must contain a valid authenticated session.
    - The user's current password must be supplied.
    - The password is verified against the stored password hash.
    - No password is stored or logged.

    Database behavior:

    - The user's account is deleted.
    - Existing database CASCADE relationships remove
      user-owned items, claims, reports, notifications,
      comments, matches, and authentication tokens.
    - Reviewer references using SET NULL are retained.
    - Audit-log references using SET NULL are retained.

    Media behavior:

    - The user's profile picture and item images are collected
      before deletion.
    - The database deletion is committed first.
    - Physical media files are removed only after the database
      transaction succeeds.

    If physical media cleanup fails after a successful account
    deletion, the account remains deleted. The cleanup failure
    is logged for later operational handling.

    Returns:
        None. HTTP 204 No Content is returned on success.
    """

    # -------------------------------------------------------------------------
    # Verify current password.
    #
    # We deliberately use the same password verification service
    # used elsewhere in the application so password verification
    # remains centralized.
    # -------------------------------------------------------------------------

    if not verify_user_password(
        current_user,
        password,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    # -------------------------------------------------------------------------
    # Collect media and delete the account inside the current
    # database transaction.
    #
    # The service flushes the deletion but does NOT commit.
    # -------------------------------------------------------------------------

    try:
        media_storage_keys = delete_user_account_service(
            db,
            current_user,
        )

        # ---------------------------------------------------------------------
        # Explicitly commit this transaction.
        #
        # This endpoint needs deterministic knowledge that the database
        # deletion succeeded before physical media files are removed.
        #
        # A second commit from get_db() after the endpoint returns is
        # harmless because the transaction is already complete.
        # ---------------------------------------------------------------------

        db.commit()

    except Exception:
        db.rollback()
        raise

    # -------------------------------------------------------------------------
    # Remove physical media only after the database deletion has
    # successfully committed.
    #
    # Filesystem cleanup failure must NOT resurrect the deleted account.
    # -------------------------------------------------------------------------

    for storage_key in media_storage_keys:
        try:
            delete_stored_image(
                storage_key
            )

        except Exception:
            logger.exception(
                "Failed to delete account media after user deletion."
            )

    # -------------------------------------------------------------------------
    # HTTP 204 response.
    # -------------------------------------------------------------------------

    return None


# ============================================================================
# ADMIN: GET USER DETAIL
# ============================================================================


@router.get(
    "/admin/{user_id}",
    response_model=AdminUserDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get detailed user profile as administrator",
)
def get_admin_user_profile(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> AdminUserDetailResponse:
    """
    Return detailed profile and account information for any user.

    Access is restricted to administrators.

    The authenticated administrator is identified by the JWT.

    The target user ID is used only to identify which user
    the administrator wants to inspect.

    Security-sensitive authentication fields are deliberately
    excluded by AdminUserDetailResponse.
    """

    # -------------------------------------------------------------------------
    # Retrieve target user.
    # -------------------------------------------------------------------------

    user = get_user(
        db,
        user_id,
    )

    # -------------------------------------------------------------------------
    # Target user does not exist.
    # -------------------------------------------------------------------------

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    # -------------------------------------------------------------------------
    # Return the safe administrative representation.
    # -------------------------------------------------------------------------

    return AdminUserDetailResponse.model_validate(
        user
    )