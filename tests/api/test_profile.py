"""
TRACKIT Profile API Tests.

Tests authenticated-user profile operations.

Coverage:

- Get current user's profile.
- Authentication requirements.
- Update username.
- Update email.
- Update first name and last name.
- Update profile fields.
- Update social links.
- Update preferences.
- PATCH semantics.
- Email verification reset after email change.
- Duplicate username protection.
- Duplicate email protection.
- Protection against modifying another user's profile.
- Account deletion.
- Password confirmation for account deletion.
- User-owned data cleanup.
- User-owned media cleanup.
- Reviewer SET NULL behavior.
- Audit-log SET NULL behavior.
- Old JWT invalidation after account deletion.
- Account deletion transaction behavior.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.models.audit_log import AuditLog
from app.models.auth_token import AuthToken
from app.models.claim import Claim
from app.models.comment import Comment
from app.models.item import Item
from app.models.match import Match
from app.models.notification import Notification
from app.models.report import Report
from app.models.user import User


# ============================================================================
# TEST HELPERS
# ============================================================================


def create_test_user(
    db: Session,
    *,
    user_id: int,
    username: str,
    email: str,
    first_name: str = "Test",
    last_name: str = "User",
    is_verified: bool = True,
    password: str | None = None,
) -> User:
    """
    Create a test user directly in the test database.
    """

    password_hash = (
        hash_password(password)
        if password is not None
        else "test-password-hash"
    )

    user = User(
        id=user_id,
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password_hash=password_hash,
        role="user",
        is_active=True,
        is_verified=is_verified,
    )

    db.add(user)
    db.flush()

    return user


def authenticated_headers(
    user: User,
) -> dict[str, str]:
    """
    Create Authorization headers for a test user.

    The JWT payload follows the same structure expected by
    app.api.deps.get_current_user().
    """

    token = create_access_token(
        data={
            "sub": str(user.id),
            "token_version": user.token_version,
        },
    )

    return {
        "Authorization": f"Bearer {token}",
    }


# ============================================================================
# GET PROFILE
# ============================================================================


def test_get_profile_returns_authenticated_user(
    client: TestClient,
    db: Session,
):
    """
    Authenticated users can retrieve their own profile.
    """

    user = create_test_user(
        db,
        user_id=1001,
        username="profileuser",
        email="profileuser@example.com",
        first_name="Profile",
        last_name="User",
    )

    response = client.get(
        "/api/profile",
        headers=authenticated_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == user.id
    assert data["username"] == "profileuser"
    assert data["first_name"] == "Profile"
    assert data["last_name"] == "User"
    assert data["email"] == "profileuser@example.com"
    assert data["is_verified"] is True


# ============================================================================
# AUTHENTICATION REQUIREMENTS
# ============================================================================


def test_get_profile_requires_authentication(
    client: TestClient,
):
    """
    Profile retrieval requires authentication.
    """

    response = client.get(
        "/api/profile",
    )

    assert response.status_code == 401


def test_update_profile_requires_authentication(
    client: TestClient,
):
    """
    Profile updates require authentication.
    """

    response = client.patch(
        "/api/profile",
        json={
            "first_name": "Unauthorized",
        },
    )

    assert response.status_code == 401


# ============================================================================
# USERNAME UPDATE
# ============================================================================


def test_update_profile_username(
    client: TestClient,
    db: Session,
):
    """
    Authenticated users can change their username.
    """

    user = create_test_user(
        db,
        user_id=1002,
        username="oldusername",
        email="usernamechange@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "username": "NewUsername",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["username"] == "newusername"

    db.refresh(user)

    assert user.username == "newusername"


# ============================================================================
# EMAIL UPDATE
# ============================================================================


def test_update_profile_email(
    client: TestClient,
    db: Session,
):
    """
    Authenticated users can change their email address.
    """

    user = create_test_user(
        db,
        user_id=1003,
        username="emailchangeuser",
        email="oldemail@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "email": "NewEmail@Example.COM",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["email"] == "newemail@example.com"

    db.refresh(user)

    assert user.email == "newemail@example.com"


def test_update_email_resets_verification(
    client: TestClient,
    db: Session,
):
    """
    Changing the email address requires the new email
    address to be verified again.
    """

    user = create_test_user(
        db,
        user_id=1004,
        username="verificationuser",
        email="verified@example.com",
        is_verified=True,
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "email": "newverification@example.com",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["email"] == "newverification@example.com"
    assert data["is_verified"] is False

    db.refresh(user)

    assert user.email == "newverification@example.com"
    assert user.is_verified is False


def test_update_email_invalidates_existing_access_token(
    client: TestClient,
    db: Session,
):
    """
    Changing the email address invalidates previously issued
    access tokens by incrementing the user's token version.
    """

    user = create_test_user(
        db,
        user_id=1008,
        username="tokenuser",
        email="oldtoken@example.com",
        is_verified=True,
    )

    old_headers = authenticated_headers(user)

    response = client.get(
        "/api/profile",
        headers=old_headers,
    )

    assert response.status_code == 200

    response = client.patch(
        "/api/profile",
        headers=old_headers,
        json={
            "email": "newtoken@example.com",
        },
    )

    assert response.status_code == 200

    db.refresh(user)

    assert user.email == "newtoken@example.com"
    assert user.is_verified is False
    assert user.token_version == 1

    response = client.get(
        "/api/profile",
        headers=old_headers,
    )

    assert response.status_code == 401


# ============================================================================
# NAME UPDATE
# ============================================================================


def test_update_profile_names(
    client: TestClient,
    db: Session,
):
    """
    Authenticated users can change their first and last name.
    """

    user = create_test_user(
        db,
        user_id=1005,
        username="nameuser",
        email="profileuser@example.com",
        first_name="Old",
        last_name="Name",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "first_name": "New",
            "last_name": "Person",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["first_name"] == "New"
    assert data["last_name"] == "Person"

    db.refresh(user)

    assert user.first_name == "New"
    assert user.last_name == "Person"


# ============================================================================
# ADDITIONAL PROFILE FIELDS
# ============================================================================


def test_update_profile_fields(
    client: TestClient,
    db: Session,
):
    """
    Authenticated users can update their additional profile fields.
    """

    user = create_test_user(
        db,
        user_id=1006,
        username="profilefields",
        email="profilefields@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "profile_picture": "https://example.com/profile.jpg",
            "phone_number": "+254700000001",
            "bio": "TRACKIT user profile.",
            "address": "Nairobi, Kenya",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["profile_picture"] == (
        "https://example.com/profile.jpg"
    )
    assert data["phone_number"] == "+254700000001"
    assert data["bio"] == "TRACKIT user profile."
    assert data["address"] == "Nairobi, Kenya"

    db.refresh(user)

    assert user.profile_picture == (
        "https://example.com/profile.jpg"
    )
    assert user.phone_number == "+254700000001"
    assert user.bio == "TRACKIT user profile."
    assert user.address == "Nairobi, Kenya"


# ============================================================================
# SOCIAL LINKS
# ============================================================================


def test_update_social_links(
    client: TestClient,
    db: Session,
):
    """
    Authenticated users can update social links.
    """

    user = create_test_user(
        db,
        user_id=1007,
        username="socialuser",
        email="socialuser@example.com",
    )

    social_links = {
        "github": "https://github.com/example",
        "linkedin": "https://linkedin.com/in/example",
    }

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "social_links": social_links,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["social_links"] == social_links

    db.refresh(user)

    assert user.social_links == social_links


# ============================================================================
# PREFERENCES
# ============================================================================


def test_update_preferences(
    client: TestClient,
    db: Session,
):
    """
    Authenticated users can update profile preferences.
    """

    user = create_test_user(
        db,
        user_id=1008,
        username="preferencesuser",
        email="preferences@example.com",
    )

    preferences = {
        "email_notifications": True,
        "push_notifications": False,
        "theme": "dark",
    }

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "preferences": preferences,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["preferences"] == preferences

    db.refresh(user)

    assert user.preferences == preferences


# ============================================================================
# PATCH SEMANTICS
# ============================================================================


def test_update_profile_only_changes_supplied_fields(
    client: TestClient,
    db: Session,
):
    """
    PATCH updates only the fields supplied by the client.

    Unspecified fields must remain unchanged.
    """

    user = create_test_user(
        db,
        user_id=1009,
        username="patchuser",
        email="patchuser@example.com",
        first_name="Original",
        last_name="Person",
    )

    user.phone_number = "+254711111111"
    user.bio = "Original bio"

    db.flush()

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "first_name": "Changed",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["first_name"] == "Changed"
    assert data["last_name"] == "Person"
    assert data["phone_number"] == "+254711111111"
    assert data["bio"] == "Original bio"

    db.refresh(user)

    assert user.first_name == "Changed"
    assert user.last_name == "Person"
    assert user.phone_number == "+254711111111"
    assert user.bio == "Original bio"


def test_update_profile_with_empty_body_returns_current_profile(
    client: TestClient,
    db: Session,
):
    """
    An empty PATCH body does not modify the profile.
    """

    user = create_test_user(
        db,
        user_id=1010,
        username="emptyupdate",
        email="emptyupdate@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == user.id
    assert data["username"] == "emptyupdate"
    assert data["email"] == "emptyupdate@example.com"


# ============================================================================
# DUPLICATE USERNAME
# ============================================================================


def test_update_profile_rejects_duplicate_username(
    client: TestClient,
    db: Session,
):
    """
    A user cannot change their username to one already
    belonging to another user.
    """

    user = create_test_user(
        db,
        user_id=1011,
        username="firstprofileuser",
        email="firstprofile@example.com",
    )

    create_test_user(
        db,
        user_id=1012,
        username="takenusername",
        email="secondprofile@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "username": "TakenUsername",
        },
    )

    assert response.status_code == 409


# ============================================================================
# DUPLICATE EMAIL
# ============================================================================


def test_update_profile_rejects_duplicate_email(
    client: TestClient,
    db: Session,
):
    """
    A user cannot change their email to one already
    belonging to another user.
    """

    user = create_test_user(
        db,
        user_id=1013,
        username="firstemailuser",
        email="firstemail@example.com",
    )

    create_test_user(
        db,
        user_id=1014,
        username="secondemailuser",
        email="takenemail@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "email": "TakenEmail@Example.COM",
        },
    )

    assert response.status_code == 409


# ============================================================================
# EXISTING USERNAME
# ============================================================================


def test_update_profile_allows_existing_username(
    client: TestClient,
    db: Session,
):
    """
    Supplying the user's existing username should not
    trigger a duplicate conflict.
    """

    user = create_test_user(
        db,
        user_id=1015,
        username="sameusername",
        email="sameusername@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "username": "SameUsername",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["username"] == "sameusername"


# ============================================================================
# EXISTING EMAIL
# ============================================================================


def test_update_profile_allows_existing_email(
    client: TestClient,
    db: Session,
):
    """
    Supplying the user's existing email should not
    trigger a duplicate conflict or reset verification.
    """

    user = create_test_user(
        db,
        user_id=1016,
        username="sameemailuser",
        email="sameemail@example.com",
        is_verified=True,
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "email": "SameEmail@Example.COM",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["email"] == "sameemail@example.com"
    assert data["is_verified"] is True


# ============================================================================
# AUTHENTICATED USER OWNERSHIP
# ============================================================================


def test_profile_endpoint_only_updates_authenticated_user(
    client: TestClient,
    db: Session,
):
    """
    The profile endpoint updates the user represented by
    the JWT and does not accept a user ID from the client.
    """

    authenticated_user = create_test_user(
        db,
        user_id=1017,
        username="authenticateduser",
        email="authenticated@example.com",
    )

    other_user = create_test_user(
        db,
        user_id=1018,
        username="otheruser",
        email="other@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(authenticated_user),
        json={
            "username": "changedauthenticated",
        },
    )

    assert response.status_code == 200

    db.refresh(authenticated_user)
    db.refresh(other_user)

    assert authenticated_user.username == (
        "changedauthenticated"
    )
    assert other_user.username == "otheruser"


# ============================================================================
# ADMIN USER PROFILE
# ============================================================================


def admin_authenticated_headers(
    user: User,
) -> dict[str, str]:
    """
    Create Authorization headers for an administrative test user.
    """

    token = create_access_token(
        data={
            "sub": str(user.id),
            "token_version": user.token_version,
        },
    )

    return {
        "Authorization": f"Bearer {token}",
    }


def test_admin_can_view_another_users_profile(
    client: TestClient,
    db: Session,
):
    """
    Administrators can view another user's detailed
    profile and account information.
    """

    admin = create_test_user(
        db,
        user_id=1019,
        username="adminuser",
        email="admin@example.com",
    )

    admin.role = "admin"
    db.flush()

    target_user = create_test_user(
        db,
        user_id=1020,
        username="targetuser",
        email="target@example.com",
        first_name="Target",
        last_name="Person",
    )

    target_user.profile_picture = (
        "https://example.com/avatar.jpg"
    )
    target_user.phone_number = "+254700000002"
    target_user.bio = "Target profile."
    target_user.address = "Nairobi, Kenya"
    target_user.social_links = {
        "github": "https://github.com/target",
    }
    target_user.preferences = {
        "theme": "dark",
    }

    db.flush()

    response = client.get(
        f"/api/profile/admin/{target_user.id}",
        headers=admin_authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_user.id
    assert data["username"] == "targetuser"
    assert data["first_name"] == "Target"
    assert data["last_name"] == "Person"
    assert data["email"] == "target@example.com"

    assert data["role"] == "user"
    assert data["is_active"] is True
    assert data["is_verified"] is True

    assert data["profile_picture"] == (
        "https://example.com/avatar.jpg"
    )
    assert data["phone_number"] == "+254700000002"
    assert data["bio"] == "Target profile."
    assert data["address"] == "Nairobi, Kenya"

    assert data["social_links"] == {
        "github": "https://github.com/target",
    }

    assert data["preferences"] == {
        "theme": "dark",
    }


def test_admin_can_view_private_user_profile(
    client: TestClient,
    db: Session,
):
    """
    Administrative access is not restricted by public/private
    profile visibility.

    The current User model may not yet contain an explicit
    profile visibility field, so this test establishes that
    administrative access is independent of public-profile rules.
    """

    admin = create_test_user(
        db,
        user_id=1021,
        username="profileadmin",
        email="profileadmin@example.com",
    )

    admin.role = "admin"
    db.flush()

    target_user = create_test_user(
        db,
        user_id=1022,
        username="privateuser",
        email="privateuser@example.com",
    )

    response = client.get(
        f"/api/profile/admin/{target_user.id}",
        headers=admin_authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_user.id
    assert data["username"] == "privateuser"


def test_normal_user_cannot_view_admin_user_profile(
    client: TestClient,
    db: Session,
):
    """
    Normal users cannot access the administrative
    user-detail endpoint.
    """

    normal_user = create_test_user(
        db,
        user_id=1023,
        username="normalviewer",
        email="normalviewer@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=1024,
        username="targetadminview",
        email="targetadminview@example.com",
    )

    response = client.get(
        f"/api/profile/admin/{target_user.id}",
        headers=authenticated_headers(normal_user),
    )

    assert response.status_code == 403


def test_admin_user_profile_requires_authentication(
    client: TestClient,
    db: Session,
):
    """
    The administrative user-detail endpoint requires authentication.
    """

    target_user = create_test_user(
        db,
        user_id=1025,
        username="authenticationtarget",
        email="authenticationtarget@example.com",
    )

    response = client.get(
        f"/api/profile/admin/{target_user.id}",
    )

    assert response.status_code == 401


def test_admin_user_profile_returns_404_for_nonexistent_user(
    client: TestClient,
    db: Session,
):
    """
    Administrators receive 404 when the requested user does not exist.
    """

    admin = create_test_user(
        db,
        user_id=1026,
        username="missinguseradmin",
        email="missinguseradmin@example.com",
    )

    admin.role = "admin"
    db.flush()

    response = client.get(
        "/api/profile/admin/999999",
        headers=admin_authenticated_headers(admin),
    )

    assert response.status_code == 404


def test_admin_user_profile_does_not_expose_security_fields(
    client: TestClient,
    db: Session,
):
    """
    Administrative profile responses must never expose
    authentication or credential fields.
    """

    admin = create_test_user(
        db,
        user_id=1027,
        username="securityadmin",
        email="securityadmin@example.com",
    )

    admin.role = "admin"
    db.flush()

    target_user = create_test_user(
        db,
        user_id=1028,
        username="securitytarget",
        email="securitytarget@example.com",
    )

    response = client.get(
        f"/api/profile/admin/{target_user.id}",
        headers=admin_authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert "password_hash" not in data
    assert "token_version" not in data
    assert "auth_tokens" not in data
    assert "tokens" not in data
    assert "password_reset_token" not in data
    assert "verification_token" not in data
    assert "access_token" not in data
    assert "refresh_token" not in data


def test_admin_can_view_inactive_user(
    client: TestClient,
    db: Session,
):
    """
    Administrators can inspect inactive users.
    """

    admin = create_test_user(
        db,
        user_id=1029,
        username="inactiveviewer",
        email="inactiveviewer@example.com",
    )

    admin.role = "admin"
    db.flush()

    target_user = create_test_user(
        db,
        user_id=1030,
        username="inactiveuser",
        email="inactiveuser@example.com",
    )

    target_user.is_active = False
    db.flush()

    response = client.get(
        f"/api/profile/admin/{target_user.id}",
        headers=admin_authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_user.id
    assert data["is_active"] is False


# ============================================================================
# PATCH NULL / CLEAR SEMANTICS
# ============================================================================


def test_update_profile_can_clear_bio(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=101,
        username="clearbio",
        email="clearbio@example.com",
    )

    user.bio = "This should be cleared."
    db.flush()

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "bio": None,
        },
    )

    assert response.status_code == 200
    assert response.json()["bio"] is None

    db.refresh(user)

    assert user.bio is None


def test_update_profile_can_clear_phone_number(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=102,
        username="clearphone",
        email="clearphone@example.com",
    )

    user.phone_number = "+254711111111"
    db.flush()

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "phone_number": None,
        },
    )

    assert response.status_code == 200
    assert response.json()["phone_number"] is None

    db.refresh(user)

    assert user.phone_number is None


def test_update_profile_can_clear_profile_picture(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=103,
        username="clearpicture",
        email="clearpicture@example.com",
    )

    user.profile_picture = "https://example.com/profile.jpg"
    db.flush()

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "profile_picture": None,
        },
    )

    assert response.status_code == 200
    assert response.json()["profile_picture"] is None

    db.refresh(user)

    assert user.profile_picture is None


def test_update_profile_can_clear_address(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=104,
        username="clearaddress",
        email="clearaddress@example.com",
    )

    user.address = "Nairobi"
    db.flush()

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "address": None,
        },
    )

    assert response.status_code == 200
    assert response.json()["address"] is None

    db.refresh(user)

    assert user.address is None


# ============================================================================
# REQUIRED FIELD NULL VALIDATION
# ============================================================================


def test_update_profile_rejects_null_username(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=105,
        username="nullusername",
        email="nullusername@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "username": None,
        },
    )

    assert response.status_code == 422


def test_update_profile_rejects_null_email(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=106,
        username="nullemail",
        email="nullemail@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "email": None,
        },
    )

    assert response.status_code == 422


def test_update_profile_rejects_null_first_name(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=107,
        username="nullfirstname",
        email="nullfirstname@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "first_name": None,
        },
    )

    assert response.status_code == 422


def test_update_profile_rejects_null_last_name(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=108,
        username="nulllastname",
        email="nulllastname@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "last_name": None,
        },
    )

    assert response.status_code == 422


# ============================================================================
# REQUIRED FIELD EMPTY STRING VALIDATION
# ============================================================================


def test_update_profile_rejects_empty_username(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=109,
        username="emptyusername",
        email="emptyusername@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "username": "",
        },
    )

    assert response.status_code == 422


def test_update_profile_rejects_empty_email(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=110,
        username="emptyemail",
        email="emptyemail@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "email": "",
        },
    )

    assert response.status_code == 422


def test_update_profile_rejects_empty_first_name(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=111,
        username="emptyfirstname",
        email="emptyfirstname@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "first_name": "",
        },
    )

    assert response.status_code == 422


def test_update_profile_rejects_empty_last_name(
    client: TestClient,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=112,
        username="emptylastname",
        email="emptylastname@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "last_name": "",
        },
    )

    assert response.status_code == 422


# ============================================================================
# NON-NULL JSON FIELD VALIDATION
# ============================================================================


def test_update_profile_rejects_null_social_links(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=113,
        username="nullsocial",
        email="nullsocial@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "social_links": None,
        },
    )

    assert response.status_code == 422


def test_update_profile_rejects_null_preferences(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=114,
        username="nullpreferences",
        email="nullpreferences@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "preferences": None,
        },
    )

    assert response.status_code == 422


# ============================================================================
# EMPTY STRING CLEARING FOR NULLABLE FIELDS
# ============================================================================


def test_update_profile_empty_nullable_strings_clear_values(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=115,
        username="emptynullable",
        email="emptynullable@example.com",
    )

    user.profile_picture = "profile.jpg"
    user.phone_number = "+254711111111"
    user.bio = "Biography"
    user.address = "Nairobi"

    db.flush()

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "profile_picture": "",
            "phone_number": "",
            "bio": "",
            "address": "",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["profile_picture"] is None
    assert data["phone_number"] is None
    assert data["bio"] is None
    assert data["address"] is None

    db.refresh(user)

    assert user.profile_picture is None
    assert user.phone_number is None
    assert user.bio is None
    assert user.address is None


# ============================================================================
# PATCH OMISSION SEMANTICS
# ============================================================================


def test_update_profile_omitted_nullable_field_remains_unchanged(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        user_id=116,
        username="omittednullable",
        email="omittednullable@example.com",
    )

    user.bio = "Keep this biography."
    user.phone_number = "+254722222222"

    db.flush()

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "first_name": "Changed",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["first_name"] == "Changed"
    assert data["bio"] == "Keep this biography."
    assert data["phone_number"] == "+254722222222"

    db.refresh(user)

    assert user.bio == "Keep this biography."
    assert user.phone_number == "+254722222222"


# ============================================================================
# ACCOUNT DELETION
# ============================================================================


ACCOUNT_DELETE_PASSWORD = "Trackit@123"


def test_delete_account_requires_authentication(
    client: TestClient,
):
    """
    Account deletion requires an authenticated user.
    """

    response = client.request(
        "DELETE",
        "/api/profile/account",
        json={
            "password": ACCOUNT_DELETE_PASSWORD,
        },
    )

    assert response.status_code == 401


def test_delete_account_rejects_incorrect_password(
    client: TestClient,
    db: Session,
):
    """
    Account deletion must require the user's current password.
    """

    user = create_test_user(
        db,
        user_id=2001,
        username="wrongpassworduser",
        email="wrongpassword@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user_id = user.id

    response = client.request(
        "DELETE",
        "/api/profile/account",
        headers=authenticated_headers(user),
        json={
            "password": "WrongPassword@123",
        },
    )

    assert response.status_code == 400

    assert response.json()["detail"] == (
        "Current password is incorrect."
    )

    persisted_user = db.get(User, user_id)

    assert persisted_user is not None
    assert persisted_user.id == 2001
    assert persisted_user.username == "wrongpassworduser"


def test_delete_account_requires_password(
    client: TestClient,
    db: Session,
):
    """
    Account deletion requires a non-empty password.
    """

    user = create_test_user(
        db,
        user_id=2002,
        username="missingpassworduser",
        email="missingpassword@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user_id = user.id

    response = client.request(
        "DELETE",
        "/api/profile/account",
        headers=authenticated_headers(user),
        json={},
    )

    assert response.status_code == 422

    persisted_user = db.get(User, user_id)

    assert persisted_user is not None


def test_delete_account_with_correct_password_returns_204(
    client: TestClient,
    db: Session,
):
    """
    A user can delete their account using the correct password.
    """

    user = create_test_user(
        db,
        user_id=2003,
        username="deleteuser",
        email="deleteuser@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user_id = user.id

    response = client.request(
        "DELETE",
        "/api/profile/account",
        headers=authenticated_headers(user),
        json={
            "password": ACCOUNT_DELETE_PASSWORD,
        },
    )

    assert response.status_code == 204
    assert response.content == b""

    db.expire_all()

    assert db.get(User, user_id) is None


def test_delete_account_invalidates_existing_access_token(
    client: TestClient,
    db: Session,
):
    """
    A JWT issued before account deletion cannot be used after
    the user record has been removed.
    """

    user = create_test_user(
        db,
        user_id=2004,
        username="deletedtokenuser",
        email="deletedtoken@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    old_headers = authenticated_headers(user)

    response = client.get(
        "/api/profile",
        headers=old_headers,
    )

    assert response.status_code == 200

    response = client.request(
        "DELETE",
        "/api/profile/account",
        headers=old_headers,
        json={
            "password": ACCOUNT_DELETE_PASSWORD,
        },
    )

    assert response.status_code == 204

    response = client.get(
        "/api/profile",
        headers=old_headers,
    )

    assert response.status_code == 401


# ============================================================================
# ACCOUNT DATA CLEANUP
# ============================================================================


def test_delete_account_removes_user_owned_data(
    client: TestClient,
    db: Session,
):
    """
    Deleting an account removes the user's directly owned records
    and records connected through CASCADE relationships.
    """

    user = create_test_user(
        db,
        user_id=2010,
        username="cleanupuser",
        email="cleanupuser@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    item = Item(
        user_id=user.id,
        title="Lost phone",
        description="Test phone",
        type="lost",
        category="Electronics",
        location="Nairobi",
        status="approved",
    )

    db.add(item)
    db.flush()

    claim = Claim(
        item_id=item.id,
        claimant_id=user.id,
        reason="I believe this item belongs to me.",
    )

    report = Report(
        item_id=item.id,
        reporter_id=user.id,
        reason=(
            "This report is being created for account "
            "deletion testing."
        ),
        description=(
            "Test report created to verify account "
            "deletion cleanup."
        ),
    )

    notification = Notification(
        user_id=user.id,
        type="account",
        category="system",
        priority="normal",
        title="Test notification",
        message="Test notification message",
    )

    comment = Comment(
        item_id=item.id,
        user_id=user.id,
        content="This is a test comment.",
    )

    auth_token = AuthToken(
        user_id=user.id,
        token_hash="a" * 64,
        token_type="password_reset",
        expires_at=(
            datetime.now(timezone.utc)
            + timedelta(minutes=15)
        ),
    )

    db.add_all(
        [
            claim,
            report,
            notification,
            comment,
            auth_token,
        ]
    )

    db.flush()

    match = Match(
        lost_item_id=item.id,
        found_item_id=item.id,
        score=100,
        match_level="high",
        category_score=100,
        title_score=100,
        description_score=100,
        location_score=100,
        time_score=100,
        reason=(
            "Test match created to verify account "
            "deletion cleanup."
        ),
    )

    db.add(match)
    db.flush()

    item_id = item.id
    claim_id = claim.id
    report_id = report.id
    notification_id = notification.id
    comment_id = comment.id
    token_id = auth_token.id
    match_id = match.id
    user_id = user.id

    response = client.request(
        "DELETE",
        "/api/profile/account",
        headers=authenticated_headers(user),
        json={
            "password": ACCOUNT_DELETE_PASSWORD,
        },
    )

    assert response.status_code == 204

    db.expire_all()

    assert db.get(User, user_id) is None
    assert db.get(Item, item_id) is None
    assert db.get(Claim, claim_id) is None
    assert db.get(Report, report_id) is None
    assert db.get(Notification, notification_id) is None
    assert db.get(Comment, comment_id) is None
    assert db.get(AuthToken, token_id) is None
    assert db.get(Match, match_id) is None


def test_delete_account_removes_profile_picture_file(
    client: TestClient,
    db: Session,
):
    """
    Account deletion removes the user's stored profile picture.
    """

    storage_key = "items/account-delete-profile.webp"

    media_root = Path(settings.MEDIA_ROOT)

    image_path = (
        media_root
        / "items"
        / "account-delete-profile.webp"
    )

    image_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    image_path.write_bytes(
        b"test-profile-image"
    )

    user = create_test_user(
        db,
        user_id=2011,
        username="profileimageuser",
        email="profileimage@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user_id = user.id

    user.profile_picture = storage_key

    db.flush()

    assert image_path.exists()

    response = client.request(
        "DELETE",
        "/api/profile/account",
        headers=authenticated_headers(user),
        json={
            "password": ACCOUNT_DELETE_PASSWORD,
        },
    )

    assert response.status_code == 204
    assert not image_path.exists()

    db.expire_all()

    assert db.get(User, user_id) is None


def test_delete_account_removes_item_image_files(
    client: TestClient,
    db: Session,
):
    """
    Account deletion removes stored images belonging to the
    user's items.
    """

    storage_key_one = (
        "items/account-delete-item-one.webp"
    )

    storage_key_two = (
        "items/account-delete-item-two.webp"
    )

    media_root = Path(settings.MEDIA_ROOT)

    image_path_one = (
        media_root
        / "items"
        / "account-delete-item-one.webp"
    )

    image_path_two = (
        media_root
        / "items"
        / "account-delete-item-two.webp"
    )

    image_path_one.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    image_path_one.write_bytes(
        b"test-item-image-one"
    )

    image_path_two.write_bytes(
        b"test-item-image-two"
    )

    user = create_test_user(
        db,
        user_id=2012,
        username="itemimageuser",
        email="itemimage@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user_id = user.id

    item_one = Item(
        user_id=user.id,
        title="Item one",
        description="Test item one",
        type="lost",
        category="Other",
        location="Nairobi",
        image=storage_key_one,
        status="approved",
    )

    item_two = Item(
        user_id=user.id,
        title="Item two",
        description="Test item two",
        type="found",
        category="Other",
        location="Nairobi",
        image=storage_key_two,
        status="approved",
    )

    db.add_all(
        [
            item_one,
            item_two,
        ]
    )

    db.flush()

    assert image_path_one.exists()
    assert image_path_two.exists()

    response = client.request(
        "DELETE",
        "/api/profile/account",
        headers=authenticated_headers(user),
        json={
            "password": ACCOUNT_DELETE_PASSWORD,
        },
    )

    assert response.status_code == 204

    assert not image_path_one.exists()
    assert not image_path_two.exists()

    db.expire_all()

    assert db.get(User, user_id) is None


# ============================================================================
# REVIEWER SET NULL / AUDIT LOG RETENTION
# ============================================================================


def test_delete_account_preserves_review_records_with_null_reviewer(
    client: TestClient,
    db: Session,
):
    """
    Records reviewed by the deleted user remain in the database,
    but their reviewer references become NULL.
    """

    user = create_test_user(
        db,
        user_id=2020,
        username="reviewerdeleteuser",
        email="reviewerdelete@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    owner = create_test_user(
        db,
        user_id=2021,
        username="reviewedowner",
        email="reviewedowner@example.com",
    )

    item = Item(
        user_id=owner.id,
        title="Reviewed item",
        description="Test reviewed item",
        type="lost",
        category="Other",
        location="Nairobi",
        status="approved",
        reviewed_by=user.id,
    )

    db.add(item)
    db.flush()

    report = Report(
        item_id=item.id,
        reporter_id=owner.id,
        reason=(
            "This report is being created for account "
            "deletion testing"
        ),
        description=(
            "Test reviewed report created to verify "
            "reviewer cleanup."
        ),
        reviewed_by=user.id,
    )

    claim = Claim(
        item_id=item.id,
        claimant_id=owner.id,
        reason="I believe this item belongs to me.",
        reviewed_by=user.id,
    )

    db.add_all(
        [
            report,
            claim,
        ]
    )

    db.flush()

    item_id = item.id
    report_id = report.id
    claim_id = claim.id

    response = client.request(
        "DELETE",
        "/api/profile/account",
        headers=authenticated_headers(user),
        json={
            "password": ACCOUNT_DELETE_PASSWORD,
        },
    )

    assert response.status_code == 204

    db.expire_all()

    persisted_item = db.get(
        Item,
        item_id,
    )

    persisted_report = db.get(
        Report,
        report_id,
    )

    persisted_claim = db.get(
        Claim,
        claim_id,
    )

    assert persisted_item is not None
    assert persisted_report is not None
    assert persisted_claim is not None

    assert persisted_item.reviewed_by is None
    assert persisted_report.reviewed_by is None
    assert persisted_claim.reviewed_by is None


def test_delete_account_preserves_audit_logs_with_null_user(
    client: TestClient,
    db: Session,
):
    """
    Audit logs remain after account deletion, but the deleted user's
    foreign-key reference is cleared.
    """

    user = create_test_user(
        db,
        user_id=2022,
        username="auditdeleteuser",
        email="auditdelete@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    audit_log = AuditLog(
        user_id=user.id,
        action="test_event",
        details="Account deletion test.",
    )

    db.add(audit_log)
    db.flush()

    audit_log_id = audit_log.id

    response = client.request(
        "DELETE",
        "/api/profile/account",
        headers=authenticated_headers(user),
        json={
            "password": ACCOUNT_DELETE_PASSWORD,
        },
    )

    assert response.status_code == 204

    db.expire_all()

    persisted_log = db.get(
        AuditLog,
        audit_log_id,
    )

    assert persisted_log is not None
    assert persisted_log.user_id is None


# ============================================================================
# TRANSACTION BEHAVIOR
# ============================================================================


def test_delete_user_account_service_can_be_rolled_back(
    db: Session,
):
    """
    The account-deletion service performs a database flush but does not
    commit. The caller can therefore roll the operation back.
    """

    from app.services.user import (
        delete_user_account_service,
    )

    user = create_test_user(
        db,
        user_id=2030,
        username="rollbackuser",
        email="rollback@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user_id = user.id

    nested = db.begin_nested()

    storage_keys = delete_user_account_service(
        db,
        user,
    )

    assert storage_keys == []

    assert db.get(User, user_id) is None

    nested.rollback()

    db.expire_all()

    restored_user = db.get(
        User,
        user_id,
    )

    assert restored_user is not None
    assert restored_user.id == user_id
    assert restored_user.username == "rollbackuser"
    assert restored_user.email == "rollback@example.com"


def test_delete_account_service_failure_does_not_delete_user(
    client: TestClient,
    db: Session,
):
    """
    If the account deletion service fails before commit, the route
    rolls the database transaction back and the account remains.
    """

    user = create_test_user(
        db,
        user_id=2031,
        username="servicefailureuser",
        email="servicefailure@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user_id = user.id

    with patch(
        "app.routers.profile.delete_user_account_service",
        side_effect=RuntimeError(
            "simulated database failure"
        ),
    ):
        with pytest.raises(
            RuntimeError,
            match="simulated database failure",
        ):
            client.request(
                "DELETE",
                "/api/profile/account",
                headers=authenticated_headers(user),
                json={
                    "password": ACCOUNT_DELETE_PASSWORD,
                },
            )

    db.expire_all()

    remaining_user = db.get(
        User,
        user_id,
    )

    assert remaining_user is not None
    assert remaining_user.id == user_id


# ============================================================================
# POST-COMMIT MEDIA CLEANUP FAILURE
# ============================================================================


def test_delete_account_media_cleanup_failure_does_not_restore_account(
    client: TestClient,
    db: Session,
):
    """
    Once the database deletion has committed, a physical media cleanup
    failure must not restore the deleted account or turn the successful
    account deletion into a failed transaction.
    """

    user = create_test_user(
        db,
        user_id=2040,
        username="mediafailureuser",
        email="mediafailure@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user_id = user.id

    user.profile_picture = (
        "items/media-cleanup-failure.webp"
    )

    db.flush()

    with patch(
        "app.routers.profile.delete_stored_image",
        side_effect=RuntimeError(
            "simulated media cleanup failure"
        ),
    ):
        response = client.request(
            "DELETE",
            "/api/profile/account",
            headers=authenticated_headers(user),
            json={
                "password": ACCOUNT_DELETE_PASSWORD,
            },
        )

    assert response.status_code == 204

    db.expire_all()

    assert db.get(User, user_id) is None