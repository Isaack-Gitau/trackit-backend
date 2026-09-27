"""
TRACKIT Profile Router.

Provides authenticated-user profile endpoints,
public user profiles, privacy settings, account management,
user administration, administrative role management,
account suspension management, and administrator-authored
email communication.

Endpoints:

    GET    /api/profile
    PATCH  /api/profile
    PATCH  /api/profile/privacy
    GET    /api/profile/users/{user_id}
    DELETE /api/profile/account

    POST   /api/profile/admin/email

    GET    /api/profile/admin/{user_id}
    POST   /api/profile/admin/{user_id}/promote
    POST   /api/profile/admin/{user_id}/promote-admin
    PATCH  /api/profile/admin/{user_id}/demote-admin
    PATCH  /api/profile/admin/{user_id}/revoke-moderator
    PATCH  /api/profile/admin/{user_id}/deactivate
    PATCH  /api/profile/admin/{user_id}/activate

Users may:
- View their own profile.
- View active users' public profiles.
- Control which optional profile fields are publicly visible.
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

Moderators may:
- View detailed profiles of users for moderation/operations.

Administrators may:
- View any user's detailed account/profile information.
- Promote regular users to moderators.
- Promote moderators to administrators.
- Demote administrators to moderators.
- Revoke moderator privileges.
- Temporarily suspend active user accounts.
- Manually reactivate suspended user accounts.
- Send custom administrative emails to selected users.

Administrative responses deliberately exclude
authentication and security secrets.

Account deletion requires the user's current
password and permanently removes the account
and its user-owned data.
"""

import logging

from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import (
    get_current_admin,
    get_current_moderator,
    get_current_user,
)
from app.db.dependencies import get_db
from app.core.constants import UserRole
from app.models.user import User
from app.schemas.profile import (
    AdminEmailDeliveryResult,
    AdminEmailRequest,
    AdminEmailResponse,
    AdminUserDetailResponse,
    ModerationUserDetailResponse,
    ProfilePrivacyResponse,
    ProfilePrivacyUpdate,
    ProfileResponse,
    ProfileUpdate,
    PublicProfileResponse,
    UserSuspensionRequest,
)
from app.services.admin_email import send_admin_email_to_users
from app.services.audit_log import (
    AUDIT_ADMIN_ACTION,
    create_audit_log,
)
from app.services.user import (
    activate_suspended_user,
    delete_user_account_service,
    delete_user_profile_picture_service,
    demote_admin_to_moderator_service,
    get_public_user_profile_service,
    get_user,
    promote_moderator_to_admin_service,
    promote_user_to_moderator_service,
    revoke_moderator_service,
    suspend_user,
    update_user_privacy_service,
    update_user_profile_service,
    verify_user_password,
)
from app.utils.images import (
    ImageUploadError,
    delete_stored_image,
    sanitize_and_store_profile_image,
)


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

    Role changes are not accepted.
    """

    changes = profile_data.model_dump(
        exclude_unset=True
    )

    if not changes:
        return ProfileResponse.model_validate(
            current_user
        )

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
# UPDATE CURRENT USER PROFILE PICTURE
# ============================================================================


@router.post(
    "/picture",
    response_model=ProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload a new profile picture",
)
async def upload_profile_picture(
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProfileResponse:
    """
    Replace the authenticated user's profile picture.

    The uploaded image is validated and sanitized by the shared
    TRACKIT image-security pipeline.

    The client-provided filename and MIME type are never trusted.

    The new image is stored beneath:

        MEDIA_ROOT/profiles/

    The database stores only the resulting relative storage key.

    Transaction behavior:

    - The new image is stored first.
    - The user record is flushed.
    - The database transaction is explicitly committed.
    - Only after a successful commit is the previous image removed.
    - If the database operation fails, the new image is removed and
      the previous profile picture remains untouched.
    """

    stored_image: str | None = None
    previous_image = current_user.profile_picture

    try:
        stored_image = sanitize_and_store_profile_image(
            image.file
        )

        current_user.profile_picture = stored_image

        db.flush()
        db.commit()

    except ImageUploadError as exc:
        db.rollback()

        if stored_image:
            try:
                delete_stored_image(stored_image)
            except Exception:
                # Cleanup must never hide the original upload error.
                pass

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception:
        db.rollback()

        if stored_image:
            try:
                delete_stored_image(stored_image)
            except Exception:
                # Cleanup must never hide the original database error.
                pass

        raise

    finally:
        await image.close()

    # The database now definitely references the new image.
    #
    # Deleting the old image is best-effort because a filesystem cleanup
    # failure must not turn an already successful profile update into a
    # failed API response.
    if previous_image and previous_image != stored_image:
        try:
            delete_stored_image(previous_image)
        except Exception:
            logger.warning(
                "Failed to delete previous profile picture %s",
                previous_image,
                exc_info=True,
            )

    return ProfileResponse.model_validate(
        current_user
    )


# ============================================================================
# DELETE CURRENT USER PROFILE PICTURE
# ============================================================================


@router.delete(
    "/picture",
    response_model=ProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Delete the current user's profile picture",
)
def delete_profile_picture(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProfileResponse:
    """
    Remove the authenticated user's profile picture.

    The database reference is cleared and committed before the
    physical image file is removed.

    A filesystem cleanup failure is logged but does not turn an
    already-successful database operation into a failed response.
    """

    previous_image = (
        delete_user_profile_picture_service(
            db,
            current_user,
        )
    )

    db.commit()

    if previous_image:
        try:
            delete_stored_image(previous_image)
        except Exception:
            logger.warning(
                "Failed to delete profile picture %s",
                previous_image,
                exc_info=True,
            )

    return ProfileResponse.model_validate(
        current_user
    )




# ============================================================================
# UPDATE CURRENT USER PRIVACY SETTINGS
# ============================================================================


@router.patch(
    "/privacy",
    response_model=ProfilePrivacyResponse,
    status_code=status.HTTP_200_OK,
    summary="Update public profile privacy settings",
)
def update_profile_privacy(
    privacy_data: ProfilePrivacyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProfilePrivacyResponse:
    """
    Update the authenticated user's public-profile privacy settings.

    PATCH semantics are used:

    - Omitted fields remain unchanged.
    - True makes the corresponding profile field public.
    - False keeps the corresponding profile field private.

    Privacy settings are stored inside the existing user
    preferences JSON object under the ``privacy`` key.

    Existing unrelated preference keys are preserved.
    """

    changes = privacy_data.model_dump(
        exclude_unset=True
    )

    try:
        privacy = update_user_privacy_service(
            db,
            current_user,
            changes,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return ProfilePrivacyResponse(
        **privacy
    )


# ============================================================================
# GET PUBLIC USER PROFILE
# ============================================================================


@router.get(
    "/users/{user_id}",
    response_model=PublicProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a user's public profile",
)
def get_public_user_profile(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PublicProfileResponse:
    """
    Return the public profile of an active TRACKIT user.

    Only authenticated users may access public profiles.

    The target user's privacy settings determine which optional
    profile fields are returned.

    Username is always public.

    Inactive or nonexistent users are intentionally treated
    identically and return HTTP 404.

    Sensitive account, administrative, security, address,
    status, verification, and preference information is never
    exposed through this endpoint.
    """

    # The dependency intentionally authenticates the requester.
    # The requester itself does not otherwise affect visibility.
    _ = current_user

    public_profile = get_public_user_profile_service(
        db,
        user_id,
    )

    if public_profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    return public_profile


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
        description=(
            "Current account password required to permanently "
            "delete the account."
        ),
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

    if not verify_user_password(
        current_user,
        password,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    try:
        media_storage_keys = delete_user_account_service(
            db,
            current_user,
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    for storage_key in media_storage_keys:
        try:
            delete_stored_image(
                storage_key
            )

        except Exception:
            logger.exception(
                "Failed to delete account media after user deletion."
            )

    return None


# ============================================================================
# ADMIN ONLY: SEND CUSTOM EMAIL
# ============================================================================


@router.post(
    "/admin/email",
    response_model=AdminEmailResponse,
    status_code=status.HTTP_200_OK,
    summary="Send a custom administrative email",
)
async def send_admin_email(
    email_data: AdminEmailRequest,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> AdminEmailResponse:
    """
    Send a custom administrative email to selected TRACKIT users.

    Only authenticated administrators may perform this action.

    Recipients are identified by TRACKIT user IDs. Their registered
    email addresses are resolved by the service layer.

    Security and delivery rules:

    - Arbitrary email addresses are not accepted.
    - Every requested user must exist before any email is sent.
    - Users without registered email addresses are rejected before
      delivery begins.
    - Inactive or suspended users may receive administrative email.
    - The administrator may include their own account.
    - Each recipient receives an individual email.
    - Recipients cannot see the email addresses of other recipients.
    - SMTP failure for one recipient does not stop delivery to
      remaining recipients.
    - Email message content is never stored in audit logs.
    - SMTP exception details are not exposed through the API.

    Delivery failures are returned as per-recipient results rather
    than causing successful deliveries to be rolled back. SMTP is an
    external system and therefore cannot participate in the database
    transaction.

    Raises:
        HTTPException:
            400 when recipient validation fails.
    """

    try:
        delivery_results = await send_admin_email_to_users(
            db,
            user_ids=email_data.user_ids,
            subject=email_data.subject,
            message=email_data.message,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    response_results: list[AdminEmailDeliveryResult] = []

    for result in delivery_results:
        response_result = AdminEmailDeliveryResult(
            user_id=result.user_id,
            success=result.success,
            error=result.error,
        )

        response_results.append(
            response_result
        )

        if result.success:
            create_audit_log(
                db,
                event_type=AUDIT_ADMIN_ACTION,
                success=True,
                description=(
                    f"Administrator {current_admin.id} "
                    f"sent a custom administrative email "
                    f"to user {result.user_id}."
                ),
                user_id=current_admin.id,
                resource_type="user",
                resource_id=result.user_id,
            )

        else:
            create_audit_log(
                db,
                event_type=AUDIT_ADMIN_ACTION,
                success=False,
                description=(
                    f"Administrator {current_admin.id} "
                    f"attempted to send a custom administrative "
                    f"email to user {result.user_id}, but delivery failed."
                ),
                user_id=current_admin.id,
                resource_type="user",
                resource_id=result.user_id,
            )

    sent_count = sum(
        1
        for result in delivery_results
        if result.success
    )

    failed_count = len(delivery_results) - sent_count

    return AdminEmailResponse(
        total=len(delivery_results),
        sent=sent_count,
        failed=failed_count,
        results=response_results,
    )


# ============================================================================
# MODERATOR + ADMIN: GET USER DETAIL
# ============================================================================


@router.get(
    "/admin/{user_id}",
    response_model=AdminUserDetailResponse | ModerationUserDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get user details for moderation",
)
def get_admin_user_profile(
    user_id: int,
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
) -> AdminUserDetailResponse | ModerationUserDetailResponse:
    """
    Return user details for moderation or administration.

    Access is restricted to moderators and administrators.

    Administrators inherit moderator-level privileges and receive
    the broader administrative user-detail response.

    Moderators receive only the moderation-relevant account
    identity and status fields.

    The authenticated moderator/administrator is identified
    by the JWT, while the database-backed user role determines
    which response representation is returned.
    """

    user = get_user(
        db,
        user_id,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if current_moderator.role == UserRole.ADMIN:
        return AdminUserDetailResponse.model_validate(
            user
        )

    return ModerationUserDetailResponse.model_validate(
        user
    )


# ============================================================================
# ADMIN ONLY: PROMOTE USER → MODERATOR
# ============================================================================


@router.post(
    "/admin/{user_id}/promote",
    response_model=AdminUserDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Promote a user to moderator",
)
def promote_user_to_moderator(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> AdminUserDetailResponse:
    """
    Promote a regular user account to moderator.

    Only authenticated administrators may perform this action.

    This endpoint deliberately promotes only:

        user → moderator

    Promotion from moderator → admin uses the separate
    administrator promotion endpoint.
    """

    target_user = get_user(
        db,
        user_id,
    )

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    try:
        promoted_user = promote_user_to_moderator_service(
            db,
            target_user=target_user,
            acting_admin=current_admin,
        )

        create_audit_log(
            db,
            event_type=AUDIT_ADMIN_ACTION,
            success=True,
            description=(
                f"Administrator {current_admin.id} "
                f"promoted user {target_user.id} "
                "from user to moderator."
            ),
            user_id=current_admin.id,
        )

        return AdminUserDetailResponse.model_validate(
            promoted_user
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


# ============================================================================
# ADMIN ONLY: PROMOTE MODERATOR → ADMIN
# ============================================================================


@router.post(
    "/admin/{user_id}/promote-admin",
    response_model=AdminUserDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Promote a moderator to administrator",
)
def promote_moderator_to_admin(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> AdminUserDetailResponse:
    """
    Promote an existing moderator account to administrator.

    Only authenticated administrators may perform this action.

    This endpoint deliberately promotes only:

        moderator → admin

    Regular users must first be promoted to moderator.
    """

    target_user = get_user(
        db,
        user_id,
    )

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    try:
        promoted_user = promote_moderator_to_admin_service(
            db,
            target_user=target_user,
            acting_admin=current_admin,
        )

        create_audit_log(
            db,
            event_type=AUDIT_ADMIN_ACTION,
            success=True,
            description=(
                f"Administrator {current_admin.id} "
                f"promoted moderator {target_user.id} "
                "from moderator to administrator."
            ),
            user_id=current_admin.id,
        )

        return AdminUserDetailResponse.model_validate(
            promoted_user
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


# ============================================================================
# ADMIN ONLY: DEMOTE ADMIN → MODERATOR
# ============================================================================


@router.patch(
    "/admin/{user_id}/demote-admin",
    response_model=AdminUserDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Demote an administrator to moderator",
)
def demote_admin_to_moderator(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> AdminUserDetailResponse:
    """
    Demote an administrator account to moderator.

    Only authenticated administrators may perform this action.

    Security rules:

    - Administrators cannot demote themselves.
    - The last remaining administrator cannot be demoted.
    - Only an administrator can be targeted by this endpoint.

    Successful demotions are recorded in the audit log.
    """

    target_user = get_user(
        db,
        user_id,
    )

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    try:
        demoted_user = demote_admin_to_moderator_service(
            db,
            target_user=target_user,
            acting_admin=current_admin,
        )

        create_audit_log(
            db,
            event_type=AUDIT_ADMIN_ACTION,
            success=True,
            description=(
                f"Administrator {current_admin.id} "
                f"demoted administrator {target_user.id} "
                "from administrator to moderator."
            ),
            user_id=current_admin.id,
        )

        return AdminUserDetailResponse.model_validate(
            demoted_user
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


# ============================================================================
# ADMIN ONLY: REVOKE MODERATOR → USER
# ============================================================================


@router.patch(
    "/admin/{user_id}/revoke-moderator",
    response_model=AdminUserDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke moderator privileges",
)
def revoke_moderator(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> AdminUserDetailResponse:
    """
    Revoke moderator privileges from a moderator account.

    The target account is returned to the regular user role.

    Only authenticated administrators may perform this action.

    Administrators cannot be directly revoked through this endpoint.

    Successful revocations are recorded in the audit log.
    """

    target_user = get_user(
        db,
        user_id,
    )

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    try:
        revoked_user = revoke_moderator_service(
            db,
            target_user=target_user,
            acting_admin=current_admin,
        )

        create_audit_log(
            db,
            event_type=AUDIT_ADMIN_ACTION,
            success=True,
            description=(
                f"Administrator {current_admin.id} "
                f"revoked moderator {target_user.id} "
                "from moderator to user."
            ),
            user_id=current_admin.id,
        )

        return AdminUserDetailResponse.model_validate(
            revoked_user
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


# ============================================================================
# ADMIN ONLY: TEMPORARY ACCOUNT SUSPENSION
# ============================================================================


@router.patch(
    "/admin/{user_id}/deactivate",
    response_model=AdminUserDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Temporarily suspend a user account",
)
def deactivate_user(
    user_id: int,
    suspension_data: UserSuspensionRequest,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> AdminUserDetailResponse:
    """
    Temporarily suspend an active user account.

    Only authenticated administrators may perform this action.

    Suspension rules are enforced by the user service:

    - Administrators cannot suspend themselves.
    - The target must currently be active.
    - The last active administrator cannot be suspended.
    - Duration must be between 1 hour and 90 days.
    - The optional reason may contain at most 500 characters.

    Suspension invalidates existing authentication sessions.

    The suspension metadata is stored on the user account so
    an independent expiration worker can automatically reactivate
    the account when the suspension period ends.

    Successful suspensions are recorded in the audit log.
    """

    target_user = get_user(
        db,
        user_id,
    )

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    try:
        suspended_user = suspend_user(
            db,
            target_user=target_user,
            acting_admin=current_admin,
            duration_hours=suspension_data.duration_hours,
            reason=suspension_data.reason,
        )

        create_audit_log(
            db,
            event_type=AUDIT_ADMIN_ACTION,
            success=True,
            description=(
                f"Administrator {current_admin.id} "
                f"suspended user {target_user.id} "
                f"for {suspension_data.duration_hours} hours."
            ),
            user_id=current_admin.id,
        )

        return AdminUserDetailResponse.model_validate(
            suspended_user
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


# ============================================================================
# ADMIN ONLY: MANUAL ACCOUNT ACTIVATION
# ============================================================================


@router.patch(
    "/admin/{user_id}/activate",
    response_model=AdminUserDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Reactivate a suspended user account",
)
def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> AdminUserDetailResponse:
    """
    Manually reactivate a suspended user account.

    Only authenticated administrators may perform this action.

    Manual activation clears all suspension metadata and
    invalidates existing authentication sessions.

    The user's role is preserved.

    Successful activations are recorded in the audit log.
    """

    target_user = get_user(
        db,
        user_id,
    )

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    try:
        activated_user = activate_suspended_user(
            db,
            target_user,
        )

        create_audit_log(
            db,
            event_type=AUDIT_ADMIN_ACTION,
            success=True,
            description=(
                f"Administrator {current_admin.id} "
                f"reactivated user {target_user.id}."
            ),
            user_id=current_admin.id,
        )

        return AdminUserDetailResponse.model_validate(
            activated_user
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc