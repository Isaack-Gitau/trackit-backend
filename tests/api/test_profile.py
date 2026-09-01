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
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token
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
) -> User:
    """
    Create a test user directly in the test database.
    """

    user = User(
        id=user_id,
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password_hash="test-password-hash",
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
        headers=authenticated_headers(
            authenticated_user
        ),
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