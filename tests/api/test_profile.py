"""
TRACKIT Profile API Tests.

Tests authenticated-user profile operations and administrator
role-management workflows.

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
- Email change token invalidation.
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
- Post-commit media cleanup behavior.
- Moderator profile access.
- Administrator profile access.
- User -> moderator promotion.
- Moderator -> administrator promotion.
- Administrator -> moderator demotion.
- Moderator -> user privilege revocation.
- Promotion authorization.
- Demotion authorization.
- Promotion role validation.
- Demotion role validation.
- Self-promotion protection.
- Self-demotion protection.
- Last-administrator protection.
- Nonexistent-user role-management handling.
- Audit-log creation for role changes.
- Profile role escalation protection.
- Role-management transaction behavior.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import UserRole
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
from app.services.user import (
    demote_admin_to_moderator_service,
    promote_moderator_to_admin_service,
    promote_user_to_moderator_service,
    revoke_moderator_service,
)


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
        role=UserRole.USER,
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

    The JWT intentionally does not contain a trusted role value.
    The database remains authoritative for authorization.
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


def set_role(
    db: Session,
    user: User,
    role: str,
) -> User:
    """
    Assign a role directly in test setup.
    """

    user.role = role
    db.flush()

    return user


def create_admin(
    db: Session,
    *,
    user_id: int,
    username: str,
    email: str,
) -> User:
    """
    Create an administrator test user.
    """

    user = create_test_user(
        db,
        user_id=user_id,
        username=username,
        email=email,
    )

    return set_role(
        db,
        user,
        UserRole.ADMIN,
    )


def create_moderator(
    db: Session,
    *,
    user_id: int,
    username: str,
    email: str,
) -> User:
    """
    Create a moderator test user.
    """

    user = create_test_user(
        db,
        user_id=user_id,
        username=username,
        email=email,
    )

    return set_role(
        db,
        user,
        UserRole.MODERATOR,
    )


def count_audit_logs(
    db: Session,
    *,
    user_id: int,
    action: str = "admin_action",
) -> int:
    """
    Count audit logs created by a specific acting user.
    """

    return (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == user_id,
            AuditLog.action == action,
        )
        .count()
    )


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


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("get", "/api/profile", None),
        (
            "patch",
            "/api/profile",
            {"first_name": "Unauthorized"},
        ),
    ],
)
def test_profile_operations_require_authentication(
    client: TestClient,
    method: str,
    path: str,
    payload: dict | None,
):
    """
    Profile operations require authentication.
    """

    if method == "get":
        response = client.get(path)
    else:
        response = client.patch(
            path,
            json=payload,
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
    assert response.json()["username"] == "newusername"

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
    assert response.json()["email"] == "newemail@example.com"

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
    assert response.json()["social_links"] == social_links

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
        user_id=1010,
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
    assert response.json()["preferences"] == preferences

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
    """

    user = create_test_user(
        db,
        user_id=1011,
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
        user_id=1012,
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
# DUPLICATE USERNAME / EMAIL
# ============================================================================


def test_update_profile_rejects_duplicate_username(
    client: TestClient,
    db: Session,
):
    """
    A user cannot change their username to another user's username.
    """

    user = create_test_user(
        db,
        user_id=1013,
        username="firstprofileuser",
        email="firstprofile@example.com",
    )

    create_test_user(
        db,
        user_id=1014,
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


def test_update_profile_rejects_duplicate_email(
    client: TestClient,
    db: Session,
):
    """
    A user cannot change their email to another user's email.
    """

    user = create_test_user(
        db,
        user_id=1015,
        username="firstemailuser",
        email="firstemail@example.com",
    )

    create_test_user(
        db,
        user_id=1016,
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


def test_update_profile_allows_existing_username(
    client: TestClient,
    db: Session,
):
    """
    Supplying the user's existing username does not create a conflict.
    """

    user = create_test_user(
        db,
        user_id=1017,
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
    assert response.json()["username"] == "sameusername"


def test_update_profile_allows_existing_email(
    client: TestClient,
    db: Session,
):
    """
    Supplying the user's existing email does not create a conflict
    or reset verification.
    """

    user = create_test_user(
        db,
        user_id=1018,
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
    assert response.json()["email"] == "sameemail@example.com"
    assert response.json()["is_verified"] is True


# ============================================================================
# PATCH CLEAR / VALIDATION SEMANTICS
# ============================================================================


@pytest.mark.parametrize(
    ("user_id", "username", "email", "field"),
    [
        (1020, "clearbio", "clearbio@example.com", "bio"),
        (1021, "clearphone", "clearphone@example.com", "phone_number"),
        (
            1022,
            "clearpicture",
            "clearpicture@example.com",
            "profile_picture",
        ),
        (1023, "clearaddress", "clearaddress@example.com", "address"),
    ],
)
def test_update_profile_can_clear_nullable_field(
    client: TestClient,
    db: Session,
    user_id: int,
    username: str,
    email: str,
    field: str,
):
    """
    Nullable profile fields can be explicitly cleared with null.
    """

    user = create_test_user(
        db,
        user_id=user_id,
        username=username,
        email=email,
    )

    setattr(user, field, "existing value")
    db.flush()

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            field: None,
        },
    )

    assert response.status_code == 200
    assert response.json()[field] is None

    db.refresh(user)

    assert getattr(user, field) is None


@pytest.mark.parametrize(
    "field",
    [
        "username",
        "email",
        "first_name",
        "last_name",
    ],
)
def test_update_profile_rejects_null_required_field(
    client: TestClient,
    db: Session,
    field: str,
):
    """
    Required profile fields cannot be set to null.
    """

    user = create_test_user(
        db,
        user_id=1030 + len(field),
        username=f"null{field}",
        email=f"null{field}@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            field: None,
        },
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "field",
    [
        "username",
        "email",
        "first_name",
        "last_name",
    ],
)
def test_update_profile_rejects_empty_required_field(
    client: TestClient,
    db: Session,
    field: str,
):
    """
    Required profile fields cannot be empty strings.
    """

    user = create_test_user(
        db,
        user_id=1040 + len(field),
        username=f"empty{field}",
        email=f"empty{field}@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            field: "",
        },
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "field",
    [
        "social_links",
        "preferences",
    ],
)
def test_update_profile_rejects_null_json_field(
    client: TestClient,
    db: Session,
    field: str,
):
    """
    JSON profile fields that are not nullable reject null.
    """

    user = create_test_user(
        db,
        user_id=1050 + len(field),
        username=f"null{field}",
        email=f"null{field}@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            field: None,
        },
    )

    assert response.status_code == 422


def test_update_profile_empty_nullable_strings_clear_values(
    client: TestClient,
    db: Session,
):
    """
    Empty strings clear nullable string profile fields.
    """

    user = create_test_user(
        db,
        user_id=1060,
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


# ============================================================================
# ACCOUNT DELETION
# ============================================================================


ACCOUNT_DELETE_PASSWORD = "Trackit@123"


def test_delete_account_requires_authentication(
    client: TestClient,
):
    """
    Account deletion requires authentication.
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
    Account deletion requires the user's current password.
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

    assert db.get(User, user_id) is not None


def test_delete_account_requires_password(
    client: TestClient,
    db: Session,
):
    """
    Account deletion requires a password.
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
    assert db.get(User, user_id) is not None


def test_delete_account_with_correct_password_returns_204(
    client: TestClient,
    db: Session,
):
    """
    A user can delete their account with the correct password.
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
    A JWT issued before deletion cannot authenticate after deletion.
    """

    user = create_test_user(
        db,
        user_id=2004,
        username="deletedtokenuser",
        email="deletedtoken@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    old_headers = authenticated_headers(user)

    assert (
        client.get(
            "/api/profile",
            headers=old_headers,
        ).status_code
        == 200
    )

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
    Deleting an account removes directly owned and cascading data.
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
        reason="Account deletion test.",
        description="Test report created for cleanup.",
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
        reason="Account deletion cleanup test.",
    )

    db.add(match)
    db.flush()

    ids = {
        "user": user.id,
        "item": item.id,
        "claim": claim.id,
        "report": report.id,
        "notification": notification.id,
        "comment": comment.id,
        "auth_token": auth_token.id,
        "match": match.id,
    }

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

    assert db.get(User, ids["user"]) is None
    assert db.get(Item, ids["item"]) is None
    assert db.get(Claim, ids["claim"]) is None
    assert db.get(Report, ids["report"]) is None
    assert db.get(Notification, ids["notification"]) is None
    assert db.get(Comment, ids["comment"]) is None
    assert db.get(AuthToken, ids["auth_token"]) is None
    assert db.get(Match, ids["match"]) is None


def test_delete_account_removes_profile_picture_file(
    client: TestClient,
    db: Session,
):
    """
    Account deletion removes the user's stored profile picture.
    """

    storage_key = "items/account-delete-profile.webp"
    image_path = (
        Path(settings.MEDIA_ROOT)
        / "items"
        / "account-delete-profile.webp"
    )

    image_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    image_path.write_bytes(b"test-profile-image")

    user = create_test_user(
        db,
        user_id=2011,
        username="profileimageuser",
        email="profileimage@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user.profile_picture = storage_key
    db.flush()

    assert image_path.exists()

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
    assert not image_path.exists()

    db.expire_all()

    assert db.get(User, user_id) is None


def test_delete_account_removes_item_image_files(
    client: TestClient,
    db: Session,
):
    """
    Account deletion removes stored item images.
    """

    storage_key_one = "items/account-delete-item-one.webp"
    storage_key_two = "items/account-delete-item-two.webp"

    media_root = Path(settings.MEDIA_ROOT)

    image_path_one = media_root / storage_key_one
    image_path_two = media_root / storage_key_two

    image_path_one.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    image_path_one.write_bytes(b"test-item-image-one")
    image_path_two.write_bytes(b"test-item-image-two")

    user = create_test_user(
        db,
        user_id=2012,
        username="itemimageuser",
        email="itemimage@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

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

    db.add_all([item_one, item_two])
    db.flush()

    assert image_path_one.exists()
    assert image_path_two.exists()

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
    Records reviewed by a deleted user remain, with reviewer references
    set to NULL.
    """

    reviewer = create_test_user(
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
        reviewed_by=reviewer.id,
    )

    db.add(item)
    db.flush()

    report = Report(
        item_id=item.id,
        reporter_id=owner.id,
        reason="Reviewer cleanup test.",
        description="Reviewed report.",
        reviewed_by=reviewer.id,
    )

    claim = Claim(
        item_id=item.id,
        claimant_id=owner.id,
        reason="I believe this item belongs to me.",
        reviewed_by=reviewer.id,
    )

    db.add_all([report, claim])
    db.flush()

    ids = {
        "item": item.id,
        "report": report.id,
        "claim": claim.id,
    }

    response = client.request(
        "DELETE",
        "/api/profile/account",
        headers=authenticated_headers(reviewer),
        json={
            "password": ACCOUNT_DELETE_PASSWORD,
        },
    )

    assert response.status_code == 204

    db.expire_all()

    persisted_item = db.get(Item, ids["item"])
    persisted_report = db.get(Report, ids["report"])
    persisted_claim = db.get(Claim, ids["claim"])

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
    Audit logs remain after account deletion, but user_id becomes NULL.
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
# ACCOUNT-DELETION TRANSACTION BEHAVIOR
# ============================================================================


def test_delete_user_account_service_can_be_rolled_back(
    db: Session,
):
    """
    Account deletion can be rolled back before the outer transaction commits.
    """

    user = create_test_user(
        db,
        user_id=2030,
        username="rollbackuser",
        email="rollback@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user_id = user.id

    nested = db.begin_nested()

    storage_keys = (
        __import__(
            "app.services.user",
            fromlist=["delete_user_account_service"],
        )
        .delete_user_account_service(
            db,
            user,
        )
    )

    assert storage_keys == []
    assert db.get(User, user.id) is None

    nested.rollback()

    db.expire_all()

    restored_user = db.get(User, user_id)

    assert restored_user is not None
    assert restored_user.username == "rollbackuser"
    assert restored_user.email == "rollback@example.com"


def test_delete_account_service_failure_does_not_delete_user(
    client: TestClient,
    db: Session,
):
    """
    A failure before commit rolls the account deletion back.
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
            "simulated database failure",
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

    assert db.get(User, user_id) is not None


def test_delete_account_media_cleanup_failure_does_not_restore_account(
    client: TestClient,
    db: Session,
):
    """
    A post-commit media cleanup failure does not restore the account.
    """

    user = create_test_user(
        db,
        user_id=2040,
        username="mediafailureuser",
        email="mediafailure@example.com",
        password=ACCOUNT_DELETE_PASSWORD,
    )

    user.profile_picture = (
        "items/media-cleanup-failure.webp"
    )

    db.flush()

    user_id = user.id

    with patch(
        "app.routers.profile.delete_stored_image",
        side_effect=RuntimeError(
            "simulated media cleanup failure",
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


# ============================================================================
# ADMIN/MODERATOR USER PROFILE ACCESS
# ============================================================================


def test_admin_can_view_another_users_profile(
    client: TestClient,
    db: Session,
):
    """
    Administrators can view another user's detailed profile.
    """

    admin = create_admin(
        db,
        user_id=3001,
        username="adminuser",
        email="admin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3002,
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
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_user.id
    assert data["username"] == "targetuser"
    assert data["first_name"] == "Target"
    assert data["last_name"] == "Person"
    assert data["email"] == "target@example.com"
    assert data["role"] == UserRole.USER
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


def test_moderator_can_view_another_users_profile(
    client: TestClient,
    db: Session,
):
    """
    Moderators have moderator-level access to user details.
    """

    moderator = create_moderator(
        db,
        user_id=3003,
        username="moderatorviewer",
        email="moderatorviewer@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3004,
        username="moderatorprofiletarget",
        email="moderatorprofiletarget@example.com",
    )

    response = client.get(
        f"/api/profile/admin/{target_user.id}",
        headers=authenticated_headers(moderator),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_user.id
    assert data["role"] == UserRole.USER


def test_normal_user_cannot_view_admin_user_profile(
    client: TestClient,
    db: Session,
):
    """
    Normal users cannot access the moderator-level user-detail endpoint.
    """

    normal_user = create_test_user(
        db,
        user_id=3005,
        username="normalviewer",
        email="normalviewer@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3006,
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
    Administrative user-detail access requires authentication.
    """

    target_user = create_test_user(
        db,
        user_id=3007,
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
    Authorized users receive 404 for nonexistent target users.
    """

    admin = create_admin(
        db,
        user_id=3008,
        username="missinguseradmin",
        email="missinguseradmin@example.com",
    )

    response = client.get(
        "/api/profile/admin/999999",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 404


def test_admin_user_profile_does_not_expose_security_fields(
    client: TestClient,
    db: Session,
):
    """
    Administrative profile responses do not expose credentials or
    authentication internals.
    """

    admin = create_admin(
        db,
        user_id=3009,
        username="securityadmin",
        email="securityadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3010,
        username="securitytarget",
        email="securitytarget@example.com",
    )

    response = client.get(
        f"/api/profile/admin/{target_user.id}",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    forbidden_fields = {
        "password_hash",
        "token_version",
        "auth_tokens",
        "tokens",
        "password_reset_token",
        "verification_token",
        "access_token",
        "refresh_token",
    }

    assert forbidden_fields.isdisjoint(data.keys())


def test_admin_can_view_inactive_user(
    client: TestClient,
    db: Session,
):
    """
    Administrators can inspect inactive users.
    """

    admin = create_admin(
        db,
        user_id=3011,
        username="inactiveviewer",
        email="inactiveviewer@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3012,
        username="inactiveuser",
        email="inactiveuser@example.com",
    )

    target_user.is_active = False
    db.flush()

    response = client.get(
        f"/api/profile/admin/{target_user.id}",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is False


# ============================================================================
# USER -> MODERATOR PROMOTION
# ============================================================================


def test_promote_user_to_moderator_requires_authentication(
    client: TestClient,
    db: Session,
):
    """
    User -> moderator promotion requires authentication.
    """

    target_user = create_test_user(
        db,
        user_id=3101,
        username="promotiontarget",
        email="promotiontarget@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{target_user.id}/promote",
    )

    assert response.status_code == 401


def test_normal_user_cannot_promote_user_to_moderator(
    client: TestClient,
    db: Session,
):
    """
    Normal users cannot perform role promotion.
    """

    normal_user = create_test_user(
        db,
        user_id=3102,
        username="normalpromoter",
        email="normalpromoter@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3103,
        username="promotiontarget2",
        email="promotiontarget2@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{target_user.id}/promote",
        headers=authenticated_headers(normal_user),
    )

    assert response.status_code == 403

    db.refresh(target_user)

    assert target_user.role == UserRole.USER


def test_moderator_cannot_promote_user_to_moderator(
    client: TestClient,
    db: Session,
):
    """
    Moderators cannot manage administrator privileges.
    """

    moderator = create_moderator(
        db,
        user_id=3104,
        username="moderatorpromoter",
        email="moderatorpromoter@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3105,
        username="moderatorpromotiontarget",
        email="moderatorpromotiontarget@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{target_user.id}/promote",
        headers=authenticated_headers(moderator),
    )

    assert response.status_code == 403

    db.refresh(target_user)

    assert target_user.role == UserRole.USER


def test_admin_can_promote_user_to_moderator(
    client: TestClient,
    db: Session,
):
    """
    Administrators can promote a regular user to moderator.
    """

    admin = create_admin(
        db,
        user_id=3106,
        username="promotingadmin",
        email="promotingadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3107,
        username="newmoderator",
        email="newmoderator@example.com",
    )

    before_audit_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    response = client.post(
        f"/api/profile/admin/{target_user.id}/promote",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_user.id
    assert data["role"] == UserRole.MODERATOR

    db.refresh(target_user)

    assert target_user.role == UserRole.MODERATOR

    after_audit_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    assert after_audit_count == before_audit_count + 1


@pytest.mark.parametrize(
    "target_role",
    [
        UserRole.MODERATOR,
        UserRole.ADMIN,
    ],
)
def test_admin_cannot_promote_already_elevated_user_to_moderator(
    client: TestClient,
    db: Session,
    target_role: str,
):
    """
    The user -> moderator endpoint cannot be used to alter an
    already elevated account.
    """

    admin = create_admin(
        db,
        user_id=3108 + len(target_role),
        username=f"promoter{target_role}",
        email=f"promoter{target_role}@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3110 + len(target_role),
        username=f"already{target_role}",
        email=f"already{target_role}@example.com",
    )

    set_role(
        db,
        target_user,
        target_role,
    )

    response = client.post(
        f"/api/profile/admin/{target_user.id}/promote",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409

    db.refresh(target_user)

    assert target_user.role == target_role


def test_admin_promote_user_to_moderator_nonexistent_user_returns_404(
    client: TestClient,
    db: Session,
):
    """
    Promoting a nonexistent user returns 404.
    """

    admin = create_admin(
        db,
        user_id=3112,
        username="missingpromotionadmin",
        email="missingpromotionadmin@example.com",
    )

    response = client.post(
        "/api/profile/admin/999999/promote",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 404


def test_admin_cannot_promote_themselves_to_moderator(
    client: TestClient,
    db: Session,
):
    """
    Administrators cannot promote themselves.
    """

    admin = create_admin(
        db,
        user_id=3113,
        username="selfpromotionadmin",
        email="selfpromotionadmin@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{admin.id}/promote",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN


# ============================================================================
# MODERATOR -> ADMIN PROMOTION
# ============================================================================


def test_promote_moderator_to_admin_requires_authentication(
    client: TestClient,
    db: Session,
):
    """
    Moderator -> administrator promotion requires authentication.
    """

    moderator = create_moderator(
        db,
        user_id=3201,
        username="promotemoderatortarget",
        email="promotemoderatortarget@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{moderator.id}/promote-admin",
    )

    assert response.status_code == 401


def test_normal_user_cannot_promote_moderator_to_admin(
    client: TestClient,
    db: Session,
):
    """
    Normal users cannot promote moderators to administrators.
    """

    normal_user = create_test_user(
        db,
        user_id=3202,
        username="normaladminpromoter",
        email="normaladminpromoter@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=3203,
        username="moderatoradminpromotiontarget",
        email="moderatoradminpromotiontarget@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{target_moderator.id}/promote-admin",
        headers=authenticated_headers(normal_user),
    )

    assert response.status_code == 403

    db.refresh(target_moderator)

    assert target_moderator.role == UserRole.MODERATOR


def test_moderator_cannot_promote_moderator_to_admin(
    client: TestClient,
    db: Session,
):
    """
    Moderators cannot promote other moderators to administrators.
    """

    acting_moderator = create_moderator(
        db,
        user_id=3204,
        username="actingmoderator",
        email="actingmoderator@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=3205,
        username="targetmoderator",
        email="targetmoderator@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{target_moderator.id}/promote-admin",
        headers=authenticated_headers(acting_moderator),
    )

    assert response.status_code == 403

    db.refresh(target_moderator)

    assert target_moderator.role == UserRole.MODERATOR


def test_admin_can_promote_moderator_to_admin(
    client: TestClient,
    db: Session,
):
    """
    Administrators can promote moderators to administrators.
    """

    admin = create_admin(
        db,
        user_id=3206,
        username="adminpromotermoderator",
        email="adminpromotermoderator@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=3207,
        username="moderatorbecomingadmin",
        email="moderatorbecomingadmin@example.com",
    )

    before_audit_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    response = client.post(
        f"/api/profile/admin/{target_moderator.id}/promote-admin",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_moderator.id
    assert data["role"] == UserRole.ADMIN

    db.refresh(target_moderator)

    assert target_moderator.role == UserRole.ADMIN

    after_audit_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    assert after_audit_count == before_audit_count + 1


def test_admin_cannot_promote_existing_admin_to_admin(
    client: TestClient,
    db: Session,
):
    """
    An administrator cannot promote an existing administrator.
    """

    admin = create_admin(
        db,
        user_id=3208,
        username="existingadminpromoter",
        email="existingadminpromoter@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=3209,
        username="alreadyadminagain",
        email="alreadyadminagain@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{target_admin.id}/promote-admin",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409

    db.refresh(target_admin)

    assert target_admin.role == UserRole.ADMIN


def test_admin_cannot_promote_regular_user_directly_to_admin(
    client: TestClient,
    db: Session,
):
    """
    Regular users must become moderators before administrators.
    """

    admin = create_admin(
        db,
        user_id=3210,
        username="hierarchyadmin",
        email="hierarchyadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3211,
        username="regularpromotiontarget",
        email="regularpromotiontarget@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{target_user.id}/promote-admin",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409

    db.refresh(target_user)

    assert target_user.role == UserRole.USER


def test_admin_promote_moderator_to_admin_nonexistent_user_returns_404(
    client: TestClient,
    db: Session,
):
    """
    Promoting a nonexistent moderator returns 404.
    """

    admin = create_admin(
        db,
        user_id=3212,
        username="missingadminpromotion",
        email="missingadminpromotion@example.com",
    )

    response = client.post(
        "/api/profile/admin/999999/promote-admin",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 404


def test_admin_cannot_promote_themselves_to_admin(
    client: TestClient,
    db: Session,
):
    """
    Administrators cannot promote themselves.
    """

    admin = create_admin(
        db,
        user_id=3213,
        username="selfadminpromotion",
        email="selfadminpromotion@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{admin.id}/promote-admin",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN


# ============================================================================
# ADMIN -> MODERATOR DEMOTION
# ============================================================================


def test_demote_admin_to_moderator_requires_authentication(
    client: TestClient,
    db: Session,
):
    """
    Administrator demotion requires authentication.
    """

    target_admin = create_admin(
        db,
        user_id=3301,
        username="demotetarget",
        email="demotetarget@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_admin.id}/demote-admin",
    )

    assert response.status_code == 401


def test_normal_user_cannot_demote_admin(
    client: TestClient,
    db: Session,
):
    """
    Normal users cannot demote administrators.
    """

    normal_user = create_test_user(
        db,
        user_id=3302,
        username="normaldemoter",
        email="normaldemoter@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=3303,
        username="targetadmindemote",
        email="targetadmindemote@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_admin.id}/demote-admin",
        headers=authenticated_headers(normal_user),
    )

    assert response.status_code == 403

    db.refresh(target_admin)

    assert target_admin.role == UserRole.ADMIN


def test_moderator_cannot_demote_admin(
    client: TestClient,
    db: Session,
):
    """
    Moderators cannot demote administrators.
    """

    moderator = create_moderator(
        db,
        user_id=3304,
        username="moderatorcannotdemote",
        email="moderatorcannotdemote@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=3305,
        username="adminmoderatorcannotdemote",
        email="adminmoderatorcannotdemote@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_admin.id}/demote-admin",
        headers=authenticated_headers(moderator),
    )

    assert response.status_code == 403

    db.refresh(target_admin)

    assert target_admin.role == UserRole.ADMIN


def test_admin_can_demote_another_admin_to_moderator(
    client: TestClient,
    db: Session,
):
    """
    An administrator can demote another administrator to moderator.
    """

    acting_admin = create_admin(
        db,
        user_id=3306,
        username="actingadmindemoter",
        email="actingadmindemoter@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=3307,
        username="targetadmindemote",
        email="targetadmindemote@example.com",
    )

    before_audit_count = count_audit_logs(
        db,
        user_id=acting_admin.id,
    )

    response = client.patch(
        f"/api/profile/admin/{target_admin.id}/demote-admin",
        headers=authenticated_headers(acting_admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_admin.id
    assert data["role"] == UserRole.MODERATOR

    db.refresh(target_admin)

    assert target_admin.role == UserRole.MODERATOR

    after_audit_count = count_audit_logs(
        db,
        user_id=acting_admin.id,
    )

    assert after_audit_count == before_audit_count + 1


def test_admin_cannot_demote_themselves(
    client: TestClient,
    db: Session,
):
    """
    An administrator cannot demote themselves.
    """

    admin = create_admin(
        db,
        user_id=3308,
        username="selfdemotingadmin",
        email="selfdemotingadmin@example.com",
    )

    other_admin = create_admin(
        db,
        user_id=3309,
        username="otheradmin",
        email="otheradmin@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{admin.id}/demote-admin",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409

    db.refresh(admin)
    db.refresh(other_admin)

    assert admin.role == UserRole.ADMIN
    assert other_admin.role == UserRole.ADMIN


def test_admin_cannot_demote_last_admin(
    client: TestClient,
    db: Session,
):
    """
    The final administrator cannot be demoted.
    """

    admin = create_admin(
        db,
        user_id=3310,
        username="lastadmin",
        email="lastadmin@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{admin.id}/demote-admin",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN


def test_admin_demote_non_admin_returns_409(
    client: TestClient,
    db: Session,
):
    """
    A moderator cannot be demoted through the admin -> moderator endpoint.
    """

    admin = create_admin(
        db,
        user_id=3311,
        username="demotevalidationadmin",
        email="demotevalidationadmin@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=3312,
        username="alreadyamoderator",
        email="alreadyamoderator@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_moderator.id}/demote-admin",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409

    db.refresh(target_moderator)

    assert target_moderator.role == UserRole.MODERATOR


def test_admin_demote_nonexistent_user_returns_404(
    client: TestClient,
    db: Session,
):
    """
    Demoting a nonexistent user returns 404.
    """

    admin = create_admin(
        db,
        user_id=3313,
        username="missingdemoteadmin",
        email="missingdemoteadmin@example.com",
    )

    response = client.patch(
        "/api/profile/admin/999999/demote-admin",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 404


# ============================================================================
# MODERATOR -> USER REVOCATION
# ============================================================================


def test_revoke_moderator_requires_authentication(
    client: TestClient,
    db: Session,
):
    """
    Moderator revocation requires authentication.
    """

    moderator = create_moderator(
        db,
        user_id=3401,
        username="revoketarget",
        email="revoketarget@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{moderator.id}/revoke-moderator",
    )

    assert response.status_code == 401


def test_normal_user_cannot_revoke_moderator(
    client: TestClient,
    db: Session,
):
    """
    Normal users cannot revoke moderator privileges.
    """

    normal_user = create_test_user(
        db,
        user_id=3402,
        username="normalrevoker",
        email="normalrevoker@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=3403,
        username="moderatorrevoketarget",
        email="moderatorrevoketarget@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_moderator.id}/revoke-moderator",
        headers=authenticated_headers(normal_user),
    )

    assert response.status_code == 403

    db.refresh(target_moderator)

    assert target_moderator.role == UserRole.MODERATOR


def test_moderator_cannot_revoke_moderator(
    client: TestClient,
    db: Session,
):
    """
    Moderators cannot revoke other moderators.
    """

    acting_moderator = create_moderator(
        db,
        user_id=3404,
        username="actingmoderatorrevoker",
        email="actingmoderatorrevoker@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=3405,
        username="targetmoderatorrevoker",
        email="targetmoderatorrevoker@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_moderator.id}/revoke-moderator",
        headers=authenticated_headers(acting_moderator),
    )

    assert response.status_code == 403

    db.refresh(target_moderator)

    assert target_moderator.role == UserRole.MODERATOR


def test_admin_can_revoke_moderator_to_user(
    client: TestClient,
    db: Session,
):
    """
    Administrators can revoke moderator privileges.
    """

    admin = create_admin(
        db,
        user_id=3406,
        username="adminrevoker",
        email="adminrevoker@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=3407,
        username="moderatorbecominguser",
        email="moderatorbecominguser@example.com",
    )

    before_audit_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    response = client.patch(
        f"/api/profile/admin/{target_moderator.id}/revoke-moderator",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_moderator.id
    assert data["role"] == UserRole.USER

    db.refresh(target_moderator)

    assert target_moderator.role == UserRole.USER

    after_audit_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    assert after_audit_count == before_audit_count + 1


def test_admin_cannot_revoke_admin_to_user(
    client: TestClient,
    db: Session,
):
    """
    Administrators must use the admin -> moderator workflow for admins.
    """

    acting_admin = create_admin(
        db,
        user_id=3408,
        username="actingadminrevoke",
        email="actingadminrevoke@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=3409,
        username="targetadminrevoke",
        email="targetadminrevoke@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_admin.id}/revoke-moderator",
        headers=authenticated_headers(acting_admin),
    )

    assert response.status_code == 409

    db.refresh(target_admin)

    assert target_admin.role == UserRole.ADMIN


def test_admin_cannot_revoke_regular_user(
    client: TestClient,
    db: Session,
):
    """
    Regular users are not valid targets for moderator revocation.
    """

    admin = create_admin(
        db,
        user_id=3410,
        username="regularrevocationadmin",
        email="regularrevocationadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3411,
        username="regularrevocationtarget",
        email="regularrevocationtarget@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/revoke-moderator",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409

    db.refresh(target_user)

    assert target_user.role == UserRole.USER


def test_admin_cannot_revoke_themselves(
    client: TestClient,
    db: Session,
):
    """
    An administrator cannot target themselves with moderator revocation.
    """

    admin = create_admin(
        db,
        user_id=3412,
        username="selfrevokingadmin",
        email="selfrevokingadmin@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{admin.id}/revoke-moderator",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN


def test_admin_revoke_nonexistent_user_returns_404(
    client: TestClient,
    db: Session,
):
    """
    Revoking a nonexistent user returns 404.
    """

    admin = create_admin(
        db,
        user_id=3413,
        username="missingrevokeadmin",
        email="missingrevokeadmin@example.com",
    )

    response = client.patch(
        "/api/profile/admin/999999/revoke-moderator",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 404


# ============================================================================
# DIRECT SERVICE ROLE-MANAGEMENT SECURITY
# ============================================================================


def test_promote_user_to_moderator_service_rejects_self_promotion(
    db: Session,
):
    """
    The service itself protects against self-promotion even if the router
    authorization layer is bypassed.
    """

    admin = create_admin(
        db,
        user_id=3501,
        username="serviceadmin",
        email="serviceadmin@example.com",
    )

    with pytest.raises(
        ValueError,
        match="cannot promote themselves",
    ):
        promote_user_to_moderator_service(
            db,
            target_user=admin,
            acting_admin=admin,
        )

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN


def test_promote_moderator_to_admin_service_rejects_self_promotion(
    db: Session,
):
    """
    The administrator-promotion service protects against self-promotion.
    """

    admin = create_admin(
        db,
        user_id=3502,
        username="serviceadmin2",
        email="serviceadmin2@example.com",
    )

    with pytest.raises(
        ValueError,
        match="cannot promote themselves",
    ):
        promote_moderator_to_admin_service(
            db,
            target_user=admin,
            acting_admin=admin,
        )

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN


def test_demote_admin_service_rejects_self_demotion(
    db: Session,
):
    """
    The admin-demotion service protects against self-demotion.
    """

    admin = create_admin(
        db,
        user_id=3503,
        username="selfdemoteservice",
        email="selfdemoteservice@example.com",
    )

    with pytest.raises(
        ValueError,
        match="cannot demote themselves",
    ):
        demote_admin_to_moderator_service(
            db,
            target_user=admin,
            acting_admin=admin,
        )

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN


def test_revoke_moderator_service_rejects_admin_target(
    db: Session,
):
    """
    The moderator-revocation service cannot downgrade administrators.
    """

    acting_admin = create_admin(
        db,
        user_id=3504,
        username="revokeactingadmin",
        email="revokeactingadmin@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=3505,
        username="revokeadmin",
        email="revokeadmin@example.com",
    )

    with pytest.raises(
        ValueError,
        match="cannot be revoked",
    ):
        revoke_moderator_service(
            db,
            target_user=target_admin,
            acting_admin=acting_admin,
        )

    db.refresh(target_admin)

    assert target_admin.role == UserRole.ADMIN


# ============================================================================
# ROLE PERSISTENCE / HIERARCHY
# ============================================================================


def test_user_to_moderator_to_admin_role_lifecycle(
    client: TestClient,
    db: Session,
):
    """
    Verify the complete intended promotion hierarchy:

        user -> moderator -> admin
    """

    admin = create_admin(
        db,
        user_id=3601,
        username="lifecycleadmin",
        email="lifecycleadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3602,
        username="rolelifecycle",
        email="rolelifecycle@example.com",
    )

    response = client.post(
        f"/api/profile/admin/{target_user.id}/promote",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    db.refresh(target_user)

    assert target_user.role == UserRole.MODERATOR

    response = client.post(
        f"/api/profile/admin/{target_user.id}/promote-admin",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    db.refresh(target_user)

    assert target_user.role == UserRole.ADMIN


def test_admin_to_moderator_to_user_role_lifecycle(
    client: TestClient,
    db: Session,
):
    """
    Verify the complete intended demotion hierarchy:

        admin -> moderator -> user
    """

    acting_admin = create_admin(
        db,
        user_id=3603,
        username="demotionlifecycleadmin",
        email="demotionlifecycleadmin@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=3604,
        username="demotionlifecycle",
        email="demotionlifecycle@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_admin.id}/demote-admin",
        headers=authenticated_headers(acting_admin),
    )

    assert response.status_code == 200

    db.refresh(target_admin)

    assert target_admin.role == UserRole.MODERATOR

    response = client.patch(
        f"/api/profile/admin/{target_admin.id}/revoke-moderator",
        headers=authenticated_headers(acting_admin),
    )

    assert response.status_code == 200

    db.refresh(target_admin)

    assert target_admin.role == UserRole.USER


# ============================================================================
# PROFILE ROLE ESCALATION PROTECTION
# ============================================================================


@pytest.mark.parametrize(
    ("initial_role", "requested_role"),
    [
        (UserRole.USER, UserRole.ADMIN),
        (UserRole.USER, UserRole.MODERATOR),
        (UserRole.MODERATOR, UserRole.ADMIN),
        (UserRole.MODERATOR, UserRole.USER),
        (UserRole.ADMIN, UserRole.USER),
        (UserRole.ADMIN, UserRole.MODERATOR),
    ],
)
def test_profile_update_cannot_change_user_role(
    client: TestClient,
    db: Session,
    initial_role: str,
    requested_role: str,
):
    """
    Normal profile updates cannot modify the authenticated user's role.

    Role management must happen through dedicated administrator-only
    endpoints.
    """

    user = create_test_user(
        db,
        user_id=3700 + len(initial_role) + len(requested_role),
        username=(
            f"profile{initial_role}{requested_role}"
        ),
        email=(
            f"profile{initial_role}{requested_role}"
            "@example.com"
        ),
    )

    set_role(
        db,
        user,
        initial_role,
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(user),
        json={
            "role": requested_role,
        },
    )

    assert response.status_code == 200

    db.refresh(user)

    assert user.role == initial_role


def test_profile_update_cannot_change_role_even_with_multiple_fields(
    client: TestClient,
    db: Session,
):
    """
    Role cannot be changed even when it is supplied alongside valid
    profile changes.
    """

    moderator = create_moderator(
        db,
        user_id=3710,
        username="multiupdateadmin",
        email="multiupdateadmin@example.com",
    )

    response = client.patch(
        "/api/profile",
        headers=authenticated_headers(moderator),
        json={
            "first_name": "Changed",
            "bio": "Updated profile.",
            "role": UserRole.ADMIN,
        },
    )

    assert response.status_code == 200

    db.refresh(moderator)

    assert moderator.first_name == "Changed"
    assert moderator.bio == "Updated profile."
    assert moderator.role == UserRole.MODERATOR


# ============================================================================
# JWT ROLE CLAIM MUST NOT OVERRIDE DATABASE ROLE
# ============================================================================


def test_database_role_is_authoritative_for_authorization(
    client: TestClient,
    db: Session,
):
    """
    Authorization must use the current database role rather than trusting
    a role value supplied inside the JWT.
    """

    user = create_test_user(
        db,
        user_id=3801,
        username="jwtroleuser",
        email="jwtroleuser@example.com",
    )

    token = create_access_token(
        data={
            "sub": str(user.id),
            "token_version": user.token_version,
            "role": UserRole.ADMIN,
        },
    )

    response = client.post(
        "/api/profile/admin/3802/promote",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 403


def test_revoked_moderator_token_cannot_gain_privileges_from_old_role(
    client: TestClient,
    db: Session,
):
    """
    Changing the database role downward immediately removes the user's
    ability to use moderator/admin endpoints according to the new role.
    """

    acting_admin = create_admin(
        db,
        user_id=3803,
        username="roleauthorityadmin",
        email="roleauthorityadmin@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=3804,
        username="roleauthoritytarget",
        email="roleauthoritytarget@example.com",
    )

    target_headers = authenticated_headers(target_admin)

    response = client.patch(
        f"/api/profile/admin/{target_admin.id}/demote-admin",
        headers=authenticated_headers(acting_admin),
    )

    assert response.status_code == 200

    db.refresh(target_admin)

    assert target_admin.role == UserRole.MODERATOR

    response = client.post(
        "/api/profile/admin/3805/promote",
        headers=target_headers,
    )

    assert response.status_code == 403


# ============================================================================
# ROLE MANAGEMENT TRANSACTION BEHAVIOR
# ============================================================================


def test_promote_user_to_moderator_service_can_be_rolled_back(
    db: Session,
):
    """
    User -> moderator promotion is flush-only and can be rolled back.
    """

    admin = create_admin(
        db,
        user_id=3901,
        username="rollbackpromotionadmin",
        email="rollbackpromotionadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3902,
        username="rollbackpromotiontarget",
        email="rollbackpromotiontarget@example.com",
    )

    target_user_id =target_user.id

    nested = db.begin_nested()

    promoted = promote_user_to_moderator_service(
        db,
        target_user=target_user,
        acting_admin=admin,
    )

    assert promoted.role == UserRole.MODERATOR

    db.refresh(target_user)

    assert target_user.role == UserRole.MODERATOR

    nested.rollback()

    db.expire_all()

    restored_user = db.get(
        User,
        target_user_id,
    )

    assert restored_user is not None
    assert restored_user.role == UserRole.USER


def test_promote_moderator_to_admin_service_can_be_rolled_back(
    db: Session,
):
    """
    Moderator -> administrator promotion is flush-only and can be rolled back.
    """

    admin = create_admin(
        db,
        user_id=3903,
        username="rollbackadminpromotion",
        email="rollbackadminpromotion@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=3904,
        username="rollbackmoderatorpromotion",
        email="rollbackmoderatorpromotion@example.com",
    )

    target_moderator_id = target_moderator.id

    nested = db.begin_nested()

    promoted = promote_moderator_to_admin_service(
        db,
        target_user=target_moderator,
        acting_admin=admin,
    )

    assert promoted.role == UserRole.ADMIN

    nested.rollback()

    db.expire_all()

    restored_user = db.get(
        User,
        target_moderator_id,
    )

    assert restored_user is not None
    assert restored_user.role == UserRole.MODERATOR


def test_demote_admin_to_moderator_service_can_be_rolled_back(
    db: Session,
):
    """
    Administrator -> moderator demotion is flush-only and can be rolled back.
    """

    acting_admin = create_admin(
        db,
        user_id=3905,
        username="rollbackdemotionacting",
        email="rollbackdemotionacting@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=3906,
        username="rollbackdemotiontarget",
        email="rollbackdemotiontarget@example.com",
    )

    target_admin_id = target_admin.id

    nested = db.begin_nested()

    demoted = demote_admin_to_moderator_service(
        db,
        target_user=target_admin,
        acting_admin=acting_admin,
    )

    assert demoted.role == UserRole.MODERATOR

    nested.rollback()

    db.expire_all()

    restored_user = db.get(
        User,
        target_admin_id,
    )

    assert restored_user is not None
    assert restored_user.role == UserRole.ADMIN


def test_revoke_moderator_service_can_be_rolled_back(
    db: Session,
):
    """
    Moderator -> user revocation is flush-only and can be rolled back.
    """

    admin = create_admin(
        db,
        user_id=3907,
        username="rollbackrevocationadmin",
        email="rollbackrevocationadmin@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=3908,
        username="rollbackrevocationtarget",
        email="rollbackrevocationtarget@example.com",
    )

    nested = db.begin_nested()

    revoked = revoke_moderator_service(
        db,
        target_user=target_moderator,
        acting_admin=admin,
    )

    assert revoked.role == UserRole.USER

    nested.rollback()

    db.expire_all()

    restored_user = db.get(
        User,
        target_moderator.id,
    )

    assert restored_user is not None
    assert restored_user.role == UserRole.MODERATOR


# ============================================================================
# ADMIN INVARIANT
# ============================================================================


def test_last_admin_invariant_is_enforced_by_service(
    db: Session,
):
    """
    The service layer independently protects the last administrator.
    """

    admin = create_admin(
        db,
        user_id=4001,
        username="onlyadminservice",
        email="onlyadminservice@example.com",
    )

    with pytest.raises(
        ValueError,
        match="last administrator",
    ):
        demote_admin_to_moderator_service(
            db,
            target_user=admin,
            acting_admin=(
                User(
                    id=4002,
                    username="differentadmin",
                    first_name="Different",
                    last_name="Admin",
                    email="differentadmin@example.com",
                    password_hash="test-password-hash",
                    role=UserRole.ADMIN,
                    is_active=True,
                    is_verified=True,
                )
            ),
        )

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN