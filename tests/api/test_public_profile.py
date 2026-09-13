"""
TRACKIT Public Profile and Privacy API Tests.

Coverage:

- Public profile authentication requirements.
- Public profile default visibility.
- Public profile privacy settings.
- Privacy PATCH semantics.
- Preservation of unrelated preferences.
- Exposure of optional public fields.
- Hiding of private fields.
- Safe handling of malformed stored privacy settings.
- Nonexistent-user handling.
- Inactive/suspended-user handling.
- Sensitive account information is never exposed.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.constants import UserRole
from app.core.security import create_access_token, hash_password
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
    role: str = UserRole.USER,
    is_active: bool = True,
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
        password_hash=hash_password("TestPassword123!"),
        role=role,
        is_active=is_active,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    return user


def authenticated_headers(
    user: User,
) -> dict[str, str]:
    """
    Create Authorization headers for a test user.
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
# PUBLIC PROFILE
# ============================================================================


def test_public_profile_requires_authentication(
    client: TestClient,
    db: Session,
):
    """
    Public profiles are available only to authenticated users.
    """

    user = create_test_user(
        db,
        user_id=7001,
        username="publicauth",
        email="publicauth@example.com",
    )

    response = client.get(
        f"/api/profile/users/{user.id}",
    )

    assert response.status_code == 401


def test_public_profile_returns_default_public_fields(
    client: TestClient,
    db: Session,
):
    """
    Username, profile picture, and bio are public by default.

    First name, last name, email, phone number, and social links
    are private by default.
    """

    viewer = create_test_user(
        db,
        user_id=7002,
        username="viewer",
        email="viewer@example.com",
    )

    target = create_test_user(
        db,
        user_id=7003,
        username="targetuser",
        email="target@example.com",
        first_name="Target",
        last_name="Person",
    )

    target.profile_picture = "https://example.com/avatar.jpg"
    target.bio = "Target public bio."
    target.phone_number = "+254700000003"
    target.social_links = {
        "github": "https://github.com/target",
        "linkedin": "https://linkedin.com/in/target",
    }

    db.flush()

    response = client.get(
        f"/api/profile/users/{target.id}",
        headers=authenticated_headers(viewer),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target.id
    assert data["username"] == "targetuser"
    assert data["profile_picture"] == (
        "https://example.com/avatar.jpg"
    )
    assert data["bio"] == "Target public bio."

    assert data["first_name"] is None
    assert data["last_name"] is None
    assert data["email"] is None
    assert data["phone_number"] is None
    assert data["social_links"] == {}


def test_public_profile_never_exposes_sensitive_account_fields(
    client: TestClient,
    db: Session,
):
    """
    Sensitive account, administrative, security, address, status,
    verification, and preference fields are never exposed.
    """

    viewer = create_test_user(
        db,
        user_id=7004,
        username="sensitiveviewer",
        email="sensitiveviewer@example.com",
    )

    target = create_test_user(
        db,
        user_id=7005,
        username="sensitivetarget",
        email="sensitive@example.com",
        role=UserRole.ADMIN,
    )

    target.address = "Nairobi, Kenya"
    target.preferences = {
        "theme": "dark",
        "privacy": {
            "email": True,
        },
    }
    target.deactivation_reason = "Administrative reason"
    target.token_version = 42

    db.flush()

    response = client.get(
        f"/api/profile/users/{target.id}",
        headers=authenticated_headers(viewer),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target.id
    assert data["username"] == "sensitivetarget"

    assert "password_hash" not in data
    assert "role" not in data
    assert "is_active" not in data
    assert "is_verified" not in data
    assert "address" not in data
    assert "preferences" not in data
    assert "token_version" not in data
    assert "deactivation_reason" not in data


def test_update_privacy_requires_authentication(
    client: TestClient,
):
    """
    Privacy settings require authentication.
    """

    response = client.patch(
        "/api/profile/privacy",
        json={
            "email": True,
        },
    )

    assert response.status_code == 401


def test_update_privacy_returns_default_settings(
    client: TestClient,
    db: Session,
):
    """
    A privacy update returns the complete effective privacy state.
    """

    user = create_test_user(
        db,
        user_id=7006,
        username="privacydefaults",
        email="privacydefaults@example.com",
    )

    response = client.patch(
        "/api/profile/privacy",
        headers=authenticated_headers(user),
        json={
            "email": True,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data == {
        "profile_picture": True,
        "bio": True,
        "first_name": False,
        "last_name": False,
        "email": True,
        "phone_number": False,
        "social_links": False,
    }


def test_update_privacy_can_make_optional_fields_public(
    client: TestClient,
    db: Session,
):
    """
    Users can make supported optional profile fields public.
    """

    user = create_test_user(
        db,
        user_id=7007,
        username="privacypublic",
        email="privacypublic@example.com",
        first_name="Public",
        last_name="Person",
    )

    user.profile_picture = "https://example.com/public.jpg"
    user.bio = "Public profile."
    user.phone_number = "+254711111111"
    user.social_links = {
        "github": "https://github.com/public",
    }

    db.flush()

    privacy_response = client.patch(
        "/api/profile/privacy",
        headers=authenticated_headers(user),
        json={
            "first_name": True,
            "last_name": True,
            "email": True,
            "phone_number": True,
            "social_links": True,
        },
    )

    assert privacy_response.status_code == 200

    profile_response = client.get(
        f"/api/profile/users/{user.id}",
        headers=authenticated_headers(user),
    )

    assert profile_response.status_code == 200

    data = profile_response.json()

    assert data["username"] == "privacypublic"
    assert data["profile_picture"] == (
        "https://example.com/public.jpg"
    )
    assert data["bio"] == "Public profile."
    assert data["first_name"] == "Public"
    assert data["last_name"] == "Person"
    assert data["email"] == "privacypublic@example.com"
    assert data["phone_number"] == "+254711111111"
    assert data["social_links"] == {
        "github": "https://github.com/public",
    }


def test_update_privacy_patch_preserves_existing_settings(
    client: TestClient,
    db: Session,
):
    """
    Omitting privacy fields preserves their existing settings.
    """

    user = create_test_user(
        db,
        user_id=7008,
        username="privacypatch",
        email="privacypatch@example.com",
    )

    first_response = client.patch(
        "/api/profile/privacy",
        headers=authenticated_headers(user),
        json={
            "email": True,
            "phone_number": True,
        },
    )

    assert first_response.status_code == 200

    second_response = client.patch(
        "/api/profile/privacy",
        headers=authenticated_headers(user),
        json={
            "bio": False,
        },
    )

    assert second_response.status_code == 200

    data = second_response.json()

    assert data["profile_picture"] is True
    assert data["bio"] is False
    assert data["first_name"] is False
    assert data["last_name"] is False
    assert data["email"] is True
    assert data["phone_number"] is True
    assert data["social_links"] is False


def test_update_privacy_preserves_unrelated_preferences(
    client: TestClient,
    db: Session,
):
    """
    Privacy updates merge into preferences without replacing
    unrelated preference keys.
    """

    user = create_test_user(
        db,
        user_id=7009,
        username="preferencepreserve",
        email="preferencepreserve@example.com",
    )

    user.preferences = {
        "email_notifications": True,
        "push_notifications": False,
        "theme": "dark",
    }

    db.flush()

    response = client.patch(
        "/api/profile/privacy",
        headers=authenticated_headers(user),
        json={
            "email": True,
        },
    )

    assert response.status_code == 200

    db.refresh(user)

    assert user.preferences["email_notifications"] is True
    assert user.preferences["push_notifications"] is False
    assert user.preferences["theme"] == "dark"
    assert user.preferences["privacy"]["email"] is True


def test_public_profile_respects_privacy_settings(
    client: TestClient,
    db: Session,
):
    """
    Public profiles expose fields according to stored privacy settings.
    """

    viewer = create_test_user(
        db,
        user_id=7010,
        username="privacyviewer",
        email="privacyviewer@example.com",
    )

    target = create_test_user(
        db,
        user_id=7011,
        username="privacytarget",
        email="privacytarget@example.com",
        first_name="Visible",
        last_name="Name",
    )

    target.phone_number = "+254722222222"
    target.social_links = {
        "github": "https://github.com/privacytarget",
    }
    target.preferences = {
        "privacy": {
            "profile_picture": False,
            "bio": False,
            "first_name": True,
            "last_name": True,
            "email": True,
            "phone_number": True,
            "social_links": True,
        }
    }

    db.flush()

    response = client.get(
        f"/api/profile/users/{target.id}",
        headers=authenticated_headers(viewer),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["username"] == "privacytarget"
    assert data["profile_picture"] is None
    assert data["bio"] is None
    assert data["first_name"] == "Visible"
    assert data["last_name"] == "Name"
    assert data["email"] == "privacytarget@example.com"
    assert data["phone_number"] == "+254722222222"
    assert data["social_links"] == {
        "github": "https://github.com/privacytarget",
    }


def test_public_profile_malformed_privacy_settings_use_safe_defaults(
    client: TestClient,
    db: Session,
):
    """
    Malformed stored privacy values safely fall back to defaults.

    Sensitive fields remain private unless explicitly set to boolean True.
    """

    viewer = create_test_user(
        db,
        user_id=7012,
        username="malformedviewer",
        email="malformedviewer@example.com",
    )

    target = create_test_user(
        db,
        user_id=7013,
        username="malformedtarget",
        email="malformedtarget@example.com",
        first_name="Should",
        last_name="Hide",
    )

    target.profile_picture = "https://example.com/malformed.jpg"
    target.bio = "Should remain public."
    target.phone_number = "+254733333333"
    target.social_links = {
        "github": "https://github.com/malformed",
    }

    target.preferences = {
        "theme": "dark",
        "privacy": {
            "profile_picture": "yes",
            "bio": False,
            "first_name": "yes",
            "last_name": 123,
            "email": "true",
            "phone_number": [],
            "social_links": {},
        },
    }

    db.flush()

    response = client.get(
        f"/api/profile/users/{target.id}",
        headers=authenticated_headers(viewer),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["username"] == "malformedtarget"
    assert data["profile_picture"] == (
        "https://example.com/malformed.jpg"
    )
    assert data["bio"] is None
    assert data["first_name"] is None
    assert data["last_name"] is None
    assert data["email"] is None
    assert data["phone_number"] is None
    assert data["social_links"] == {}


def test_public_profile_nonexistent_user_returns_404(
    client: TestClient,
    db: Session,
):
    """
    A nonexistent public-profile target returns HTTP 404.
    """

    viewer = create_test_user(
        db,
        user_id=7014,
        username="missingviewer",
        email="missingviewer@example.com",
    )

    response = client.get(
        "/api/profile/users/999999",
        headers=authenticated_headers(viewer),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."


def test_public_profile_inactive_user_returns_404(
    client: TestClient,
    db: Session,
):
    """
    Inactive or suspended users are intentionally indistinguishable
    from nonexistent users through the public-profile endpoint.
    """

    viewer = create_test_user(
        db,
        user_id=7015,
        username="inactiveviewer",
        email="inactiveviewer@example.com",
    )

    target = create_test_user(
        db,
        user_id=7016,
        username="inactiveuser",
        email="inactiveuser@example.com",
        is_active=False,
    )

    response = client.get(
        f"/api/profile/users/{target.id}",
        headers=authenticated_headers(viewer),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."


def test_public_profile_returns_null_for_public_fields_with_no_value(
    client: TestClient,
    db: Session,
):
    """
    A public field may legitimately return null when the user has
    chosen to make it public but has not supplied a value.
    """

    viewer = create_test_user(
        db,
        user_id=7017,
        username="nullviewer",
        email="nullviewer@example.com",
    )

    target = create_test_user(
        db,
        user_id=7018,
        username="nulltarget",
        email="nulltarget@example.com",
    )

    response = client.patch(
        "/api/profile/privacy",
        headers=authenticated_headers(target),
        json={
            "first_name": True,
            "email": True,
            "phone_number": True,
            "social_links": True,
        },
    )

    assert response.status_code == 200

    profile_response = client.get(
        f"/api/profile/users/{target.id}",
        headers=authenticated_headers(viewer),
    )

    assert profile_response.status_code == 200

    data = profile_response.json()

    assert data["username"] == "nulltarget"
    assert data["first_name"] == "Test"
    assert data["email"] == "nulltarget@example.com"
    assert data["phone_number"] is None
    assert data["social_links"] == {}
