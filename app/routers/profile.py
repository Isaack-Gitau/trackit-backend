"""
TRACKIT Profile Router.

Provides authenticated-user profile endpoints and
authorized administrative user inspection.

Endpoints:

    GET   /api/profile
    PATCH /api/profile

    GET   /api/profile/admin/{user_id}

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

Administrators may:
- View any user's detailed account/profile information.

Administrative responses deliberately exclude
authentication and security secrets.
"""

from fastapi import APIRouter, Depends, HTTPException, status
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
    get_user,
    update_user_profile_service,
)


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

    All fields are optional.

    Only fields explicitly supplied by the client are changed.
    """

    # -------------------------------------------------------------------------
    # Determine which fields were actually supplied.
    #
    # This is important because PATCH semantics distinguish:
    #
    #     field omitted
    #
    # from:
    #
    #     field supplied as null
    #
    # The schema/service combination handles the supported values,
    # while model_dump(exclude_unset=True) ensures we don't
    # accidentally overwrite unrelated profile fields.
    # -------------------------------------------------------------------------

    changes = profile_data.model_dump(
        exclude_unset=True
    )

    if not changes:
        return ProfileResponse.model_validate(
            current_user
        )

    # -------------------------------------------------------------------------
    # Update profile
    # -------------------------------------------------------------------------

    try:
        updated_user = update_user_profile_service(
            db,
            current_user,
            **changes,
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

    return ProfileResponse.model_validate(
        updated_user
    )


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

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    # -------------------------------------------------------------------------
    # Serialize through the dedicated administrative schema.
    #
    # Never return the SQLAlchemy User model directly.
    # This prevents accidental exposure of password hashes,
    # token versions, authentication tokens, or other secrets.
    # -------------------------------------------------------------------------

    return AdminUserDetailResponse.model_validate(
        user
    )