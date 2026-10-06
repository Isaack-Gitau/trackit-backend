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
from threading import Barrier, Thread
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.rate_limit import clear_rate_limit_store
from tests.conftest import TEST_DATABASE_URL
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
    activate_suspended_user,
    bootstrap_first_admin_service,
    demote_admin_to_moderator_service,
    promote_moderator_to_admin_service,
    promote_user_to_moderator_service,
    revoke_moderator_service,
    suspend_user,

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
    Moderators may view moderation-relevant account details,
    but private profile and contact information is excluded.
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

    target_user.first_name = "Private"
    target_user.last_name = "Person"
    target_user.profile_picture = (
        "https://example.com/private-avatar.jpg"
    )
    target_user.phone_number = "+254700000004"
    target_user.bio = "Private moderation target profile."
    target_user.address = "Private address, Nairobi"
    target_user.social_links = {
        "github": "https://github.com/private-target",
    }
    target_user.preferences = {
        "theme": "dark",
        "notifications": True,
    }

    db.commit()

    response = client.get(
        f"/api/profile/admin/{target_user.id}",
        headers=authenticated_headers(moderator),
    )

    assert response.status_code == 200

    data = response.json()

    # Moderation-safe identity and account status are visible.
    assert data["id"] == target_user.id
    assert data["username"] == "moderatorprofiletarget"
    assert data["role"] == UserRole.USER
    assert data["is_active"] is True
    assert data["is_verified"] is True
    assert data["deactivated_at"] is None
    assert data["deactivated_until"] is None
    assert data["deactivation_reason"] is None

    # Private profile/contact information is not exposed.
    forbidden_fields = {
        "first_name",
        "last_name",
        "email",
        "profile_picture",
        "phone_number",
        "bio",
        "address",
        "social_links",
        "preferences",
        "password_changed_at",
    }

    assert forbidden_fields.isdisjoint(data)


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


def test_admin_can_list_users(
    client: TestClient,
    db: Session,
):
    """
    Administrators can retrieve the paginated user directory.
    """

    admin = create_admin(
        db,
        user_id=3010,
        username="directoryadmin",
        email="directoryadmin@example.com",
    )

    user_one = create_test_user(
        db,
        user_id=3011,
        username="directoryuserone",
        email="directoryone@example.com",
        first_name="Directory",
        last_name="One",
    )

    user_two = create_test_user(
        db,
        user_id=3012,
        username="directoryusertwo",
        email="directorytwo@example.com",
        first_name="Directory",
        last_name="Two",
    )

    db.commit()

    response = client.get(
        "/api/profile/admin/users",
        params={"search": "directoryuser"},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["page"] == 1
    assert data["limit"] == 20
    assert data["total"] == 2
    assert data["pages"] == 1

    returned_ids = {
        item["id"]
        for item in data["items"]
    }

    assert returned_ids == {
        user_one.id,
        user_two.id,
    }


def test_admin_user_directory_requires_admin_role(
    client: TestClient,
    db: Session,
):
    """
    Moderators and normal users cannot access the admin user directory.
    """

    moderator = create_moderator(
        db,
        user_id=3013,
        username="directorymoderator",
        email="directorymoderator@example.com",
    )

    normal_user = create_test_user(
        db,
        user_id=3014,
        username="directorynormal",
        email="directorynormal@example.com",
    )

    moderator_response = client.get(
        "/api/profile/admin/users",
        headers=authenticated_headers(moderator),
    )

    normal_response = client.get(
        "/api/profile/admin/users",
        headers=authenticated_headers(normal_user),
    )

    assert moderator_response.status_code == 403
    assert normal_response.status_code == 403


def test_admin_user_directory_searches_username_name_and_email(
    client: TestClient,
    db: Session,
):
    """
    Directory search matches username, first name, last name, or email.
    """

    admin = create_admin(
        db,
        user_id=3015,
        username="searchdirectoryadmin",
        email="searchdirectoryadmin@example.com",
    )

    username_user = create_test_user(
        db,
        user_id=3016,
        username="uniqueusername",
        email="ordinary-one@example.com",
        first_name="First",
        last_name="Person",
    )

    first_name_user = create_test_user(
        db,
        user_id=3017,
        username="ordinaryuser",
        email="ordinary-two@example.com",
        first_name="UniqueFirstName",
        last_name="Person",
    )

    last_name_user = create_test_user(
        db,
        user_id=3018,
        username="anotheruser",
        email="ordinary-three@example.com",
        first_name="Another",
        last_name="UniqueLastName",
    )

    email_user = create_test_user(
        db,
        user_id=3019,
        username="emailmatchuser",
        email="unique-email@example.com",
        first_name="Email",
        last_name="Person",
    )

    db.commit()

    search_cases = [
        ("uniqueusername", username_user.id),
        ("uniquefirstname", first_name_user.id),
        ("uniquelastname", last_name_user.id),
        ("unique-email@example.com", email_user.id),
    ]

    for search_term, expected_id in search_cases:
        response = client.get(
            "/api/profile/admin/users",
            params={"search": search_term},
            headers=authenticated_headers(admin),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 1
        assert data["pages"] == 1
        assert data["items"][0]["id"] == expected_id


def test_admin_user_directory_filters_by_role_and_status(
    client: TestClient,
    db: Session,
):
    """
    Administrators can filter the directory by role and account status.
    """

    admin = create_admin(
        db,
        user_id=3020,
        username="filterdirectoryadmin",
        email="filterdirectoryadmin@example.com",
    )

    moderator = create_moderator(
        db,
        user_id=3021,
        username="filtermoderator",
        email="filtermoderator@example.com",
    )

    active_user = create_test_user(
        db,
        user_id=3022,
        username="filteractiveuser",
        email="filteractive@example.com",
    )

    inactive_user = create_test_user(
        db,
        user_id=3023,
        username="filterinactiveuser",
        email="filterinactive@example.com",
    )

    inactive_user.is_active = False
    inactive_user.deactivated_at = datetime.now(timezone.utc)
    inactive_user.deactivated_until = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    )
    inactive_user.deactivation_reason = "Test inactivity."

    db.commit()

    role_response = client.get(
        "/api/profile/admin/users",
        params={"role": "moderator"},
        headers=authenticated_headers(admin),
    )

    assert role_response.status_code == 200

    role_data = role_response.json()

    assert role_data["total"] == 1
    assert role_data["items"][0]["id"] == moderator.id
    assert role_data["items"][0]["role"] == UserRole.MODERATOR

    active_response = client.get(
        "/api/profile/admin/users",
        params={
            "search": "filter",
            "status": "active",
        },
        headers=authenticated_headers(admin),
    )

    assert active_response.status_code == 200

    active_data = active_response.json()

    assert active_data["total"] == 3
    assert all(
        item["is_active"] is True
        for item in active_data["items"]
    )

    inactive_response = client.get(
        "/api/profile/admin/users",
        params={
            "search": "filter",
            "status": "inactive",
        },
        headers=authenticated_headers(admin),
    )

    assert inactive_response.status_code == 200

    inactive_data = inactive_response.json()

    assert inactive_data["total"] == 1
    assert inactive_data["items"][0]["id"] == inactive_user.id
    assert inactive_data["items"][0]["is_active"] is False


def test_admin_user_directory_pagination_metadata(
    client: TestClient,
    db: Session,
):
    """
    Directory pagination returns the requested page metadata and totals.
    """

    admin = create_admin(
        db,
        user_id=3024,
        username="paginationadmin",
        email="paginationadmin@example.com",
    )

    for user_id in range(3025, 3030):
        create_test_user(
            db,
            user_id=user_id,
            username=f"paginationuser{user_id}",
            email=f"pagination{user_id}@example.com",
        )

    db.commit()

    first_page = client.get(
        "/api/profile/admin/users",
        params={
            "search": "paginationuser",
            "page": 1,
            "limit": 2,
        },
        headers=authenticated_headers(admin),
    )

    assert first_page.status_code == 200

    first_data = first_page.json()

    assert first_data["page"] == 1
    assert first_data["limit"] == 2
    assert first_data["total"] == 5
    assert first_data["pages"] == 3
    assert len(first_data["items"]) == 2

    second_page = client.get(
        "/api/profile/admin/users",
        params={
            "search": "paginationuser",
            "page": 2,
            "limit": 2,
        },
        headers=authenticated_headers(admin),
    )

    assert second_page.status_code == 200

    second_data = second_page.json()

    assert second_data["page"] == 2
    assert second_data["limit"] == 2
    assert second_data["total"] == 5
    assert second_data["pages"] == 3
    assert len(second_data["items"]) == 2

    first_ids = {
        item["id"]
        for item in first_data["items"]
    }
    second_ids = {
        item["id"]
        for item in second_data["items"]
    }

    assert first_ids.isdisjoint(second_ids)


def test_admin_user_directory_excludes_security_fields(
    client: TestClient,
    db: Session,
):
    """
    Directory responses do not expose authentication or security internals.
    """

    admin = create_admin(
        db,
        user_id=3030,
        username="securitydirectoryadmin",
        email="securitydirectoryadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3031,
        username="securitydirectorytarget",
        email="securitydirectorytarget@example.com",
    )

    target_user.password_changed_at = datetime.now(timezone.utc)

    db.commit()

    response = client.get(
        "/api/profile/admin/users",
        params={"search": target_user.username},
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1

    item = data["items"][0]

    expected_fields = {
        "id",
        "username",
        "first_name",
        "last_name",
        "email",
        "role",
        "is_active",
        "is_verified",
        "deactivated_at",
        "deactivated_until",
        "deactivation_reason",
        "created_at",
    }

    assert set(item) == expected_fields

    forbidden_fields = {
        "password_hash",
        "token_version",
        "password_changed_at",
        "verification_token",
        "password_reset_token",
    }

    assert forbidden_fields.isdisjoint(item)


def test_admin_user_directory_rejects_invalid_filters(
    client: TestClient,
    db: Session,
):
    """
    Invalid role, status, page, and limit values are rejected.
    """

    admin = create_admin(
        db,
        user_id=3032,
        username="invalidfilteradmin",
        email="invalidfilteradmin@example.com",
    )

    invalid_requests = [
        {"role": "super_admin"},
        {"status": "suspended"},
        {"page": 0},
        {"limit": 0},
        {"limit": 101},
    ]

    for params in invalid_requests:
        response = client.get(
            "/api/profile/admin/users",
            params=params,
            headers=authenticated_headers(admin),
        )

        assert response.status_code == 400, (
            f"Expected 400 for params={params}, "
            f"got {response.status_code}: {response.text}"
        )


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
# FIRST ADMINISTRATOR BOOTSTRAP
# ============================================================================


@pytest.fixture
def reset_admin_bootstrap_rate_limit():
    """
    Keep administrator-bootstrap rate-limit state isolated per test.
    """

    clear_rate_limit_store()

    yield

    clear_rate_limit_store()


def configure_admin_bootstrap(
    monkeypatch,
    *,
    username: str,
    secret: str = "test-bootstrap-secret",
):
    """
    Configure the bootstrap settings for an API test.
    """

    monkeypatch.setattr(
        settings,
        "ADMIN_BOOTSTRAP_USERNAME",
        username,
    )
    monkeypatch.setattr(
        settings,
        "ADMIN_BOOTSTRAP_SECRET",
        secret,
    )


def test_admin_bootstrap_requires_authentication(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    Administrator bootstrap requires an authenticated account.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="bootstrapadmin",
    )

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            "X-Admin-Bootstrap-Secret": "test-bootstrap-secret",
        },
    )

    assert response.status_code == 401


def test_admin_bootstrap_requires_verified_account(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    An unverified account cannot become the first administrator.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="unverifiedbootstrap",
    )

    user = create_test_user(
        db,
        user_id=3301,
        username="unverifiedbootstrap",
        email="unverifiedbootstrap@example.com",
        is_verified=False,
    )

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **authenticated_headers(user),
            "X-Admin-Bootstrap-Secret": "test-bootstrap-secret",
        },
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Email verification required."
    )

    db.refresh(user)

    assert user.role == UserRole.USER


def test_admin_bootstrap_rejects_missing_secret(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    The bootstrap secret is mandatory.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="missingsecretbootstrap",
    )

    user = create_test_user(
        db,
        user_id=3302,
        username="missingsecretbootstrap",
        email="missingsecretbootstrap@example.com",
    )

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers=authenticated_headers(user),
    )

    assert response.status_code == 403

    db.refresh(user)

    assert user.role == UserRole.USER


def test_admin_bootstrap_rejects_invalid_secret(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    An incorrect bootstrap secret cannot elevate the account.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="wrongsecretbootstrap",
    )

    user = create_test_user(
        db,
        user_id=3303,
        username="wrongsecretbootstrap",
        email="wrongsecretbootstrap@example.com",
    )

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **authenticated_headers(user),
            "X-Admin-Bootstrap-Secret": "wrong-secret",
        },
    )

    assert response.status_code == 403

    db.refresh(user)

    assert user.role == UserRole.USER


def test_admin_bootstrap_rejects_wrong_username(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    Only the configured bootstrap username can be elevated.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="configuredbootstrap",
    )

    user = create_test_user(
        db,
        user_id=3304,
        username="differentuser",
        email="differentuser@example.com",
    )

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **authenticated_headers(user),
            "X-Admin-Bootstrap-Secret": "test-bootstrap-secret",
        },
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "This account is not authorized for administrator bootstrap."
    )

    db.refresh(user)

    assert user.role == UserRole.USER


def test_admin_bootstrap_requires_configured_secret(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    Bootstrap is unavailable when no secret is configured.
    """

    monkeypatch.setattr(
        settings,
        "ADMIN_BOOTSTRAP_USERNAME",
        "unconfiguredbootstrap",
    )
    monkeypatch.setattr(
        settings,
        "ADMIN_BOOTSTRAP_SECRET",
        "",
    )

    user = create_test_user(
        db,
        user_id=3305,
        username="unconfiguredbootstrap",
        email="unconfiguredbootstrap@example.com",
    )

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **authenticated_headers(user),
            "X-Admin-Bootstrap-Secret": "test-bootstrap-secret",
        },
    )

    assert response.status_code == 403

    db.refresh(user)

    assert user.role == UserRole.USER


def test_admin_bootstrap_rejects_when_active_admin_exists(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    Bootstrap is unavailable once an active administrator exists.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="secondbootstrap",
    )

    existing_admin = create_admin(
        db,
        user_id=3306,
        username="existingbootstrapadmin",
        email="existingbootstrapadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3307,
        username="secondbootstrap",
        email="secondbootstrap@example.com",
    )

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **authenticated_headers(target_user),
            "X-Admin-Bootstrap-Secret": "test-bootstrap-secret",
        },
    )

    assert response.status_code == 409
    assert (
        response.json()["detail"]
        == "Administrator bootstrap is no longer available."
    )

    db.refresh(existing_admin)
    db.refresh(target_user)

    assert existing_admin.role == UserRole.ADMIN
    assert target_user.role == UserRole.USER


def test_admin_bootstrap_successfully_promotes_first_admin(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    The configured verified account can become the first administrator.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="firstbootstrapadmin",
    )

    user = create_test_user(
        db,
        user_id=3308,
        username="firstbootstrapadmin",
        email="firstbootstrapadmin@example.com",
    )

    old_token_version = user.token_version

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **authenticated_headers(user),
            "X-Admin-Bootstrap-Secret": "test-bootstrap-secret",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == user.id
    assert data["username"] == user.username
    assert data["role"] == UserRole.ADMIN
    assert data["is_active"] is True
    assert data["is_verified"] is True

    db.refresh(user)

    assert user.role == UserRole.ADMIN
    assert user.token_version == old_token_version + 1


def test_admin_bootstrap_invalidates_previous_authentication(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    The JWT used for bootstrap is invalid after role promotion.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="tokenbootstrapadmin",
    )

    user = create_test_user(
        db,
        user_id=3309,
        username="tokenbootstrapadmin",
        email="tokenbootstrapadmin@example.com",
    )

    headers = authenticated_headers(user)

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **headers,
            "X-Admin-Bootstrap-Secret": "test-bootstrap-secret",
        },
    )

    assert response.status_code == 200

    response = client.get(
        "/api/profile",
        headers=headers,
    )

    assert response.status_code == 401

    db.refresh(user)

    assert user.role == UserRole.ADMIN


def test_admin_bootstrap_creates_subject_audit_record(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    Successful bootstrap creates an audit record for the affected user.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="auditbootstrapadmin",
    )

    user = create_test_user(
        db,
        user_id=3310,
        username="auditbootstrapadmin",
        email="auditbootstrapadmin@example.com",
    )

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **authenticated_headers(user),
            "X-Admin-Bootstrap-Secret": "test-bootstrap-secret",
        },
    )

    assert response.status_code == 200

    audit_logs = (
        db.query(AuditLog)
        .filter(
            AuditLog.event_type == "admin_action",
            AuditLog.subject_user_id == user.id,
        )
        .all()
    )

    assert len(audit_logs) == 1

    audit_log = audit_logs[0]

    assert audit_log.user_id is None
    assert audit_log.subject_user_id == user.id
    assert audit_log.resource_type == "user"
    assert audit_log.resource_id == user.id
    assert audit_log.success is True
    assert (
        audit_log.description
        == "Initial administrator account was bootstrapped."
    )


def test_admin_bootstrap_cannot_be_reused(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    Once the first administrator exists, bootstrap cannot be reused.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="reusablebootstrapadmin",
    )

    user = create_test_user(
        db,
        user_id=3311,
        username="reusablebootstrapadmin",
        email="reusablebootstrapadmin@example.com",
    )

    first_response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **authenticated_headers(user),
            "X-Admin-Bootstrap-Secret": "test-bootstrap-secret",
        },
    )

    assert first_response.status_code == 200

    db.refresh(user)

    second_response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **authenticated_headers(user),
            "X-Admin-Bootstrap-Secret": "test-bootstrap-secret",
        },
    )

    assert second_response.status_code == 403
    assert (
        second_response.json()["detail"]
        == (
            "Only a regular user account can be used "
            "for administrator bootstrap."
        )
    )


def test_admin_bootstrap_is_rate_limited(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    Administrator bootstrap attempts are rate limited by client IP.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="ratebootstrapadmin",
    )

    user = create_test_user(
        db,
        user_id=3312,
        username="ratebootstrapadmin",
        email="ratebootstrapadmin@example.com",
    )

    headers = {
        **authenticated_headers(user),
        "X-Admin-Bootstrap-Secret": "wrong-secret",
    }

    for _ in range(3):
        response = client.post(
            "/api/profile/admin-bootstrap",
            headers=headers,
        )
        assert response.status_code == 403

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers=headers,
    )

    assert response.status_code == 429
    assert (
        response.json()["detail"]
        == "Too many administrator bootstrap attempts. "
        "Please try again later."
    )
    assert "Retry-After" in response.headers

    db.refresh(user)

    assert user.role == UserRole.USER


def test_admin_bootstrap_failure_does_not_change_role(
    client: TestClient,
    db: Session,
    monkeypatch,
    reset_admin_bootstrap_rate_limit,
):
    """
    A failed bootstrap attempt leaves the account unchanged.
    """

    configure_admin_bootstrap(
        monkeypatch,
        username="rollbackbootstrapadmin",
    )

    user = create_test_user(
        db,
        user_id=3313,
        username="rollbackbootstrapadmin",
        email="rollbackbootstrapadmin@example.com",
    )

    old_token_version = user.token_version

    response = client.post(
        "/api/profile/admin-bootstrap",
        headers={
            **authenticated_headers(user),
            "X-Admin-Bootstrap-Secret": "invalid-secret",
        },
    )

    assert response.status_code == 403

    db.refresh(user)

    assert user.role == UserRole.USER
    assert user.token_version == old_token_version


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



def test_bootstrap_first_admin_service_rejects_missing_secret(
    db: Session,
):
    """
    Administrator bootstrap requires a configured secret.
    """

    target_user = create_test_user(
        db,
        user_id=3601,
        username="bootstrapmissingsecret",
        email="bootstrapmissingsecret@example.com",
    )

    with pytest.raises(
        ValueError,
        match="bootstrap is not configured",
    ):
        bootstrap_first_admin_service(
            db,
            target_user=target_user,
            bootstrap_username=target_user.username,
            provided_secret="test-secret",
            configured_secret="",
        )

    db.refresh(target_user)

    assert target_user.role == UserRole.USER


def test_bootstrap_first_admin_service_rejects_missing_username(
    db: Session,
):
    """
    Administrator bootstrap requires a configured bootstrap username.
    """

    target_user = create_test_user(
        db,
        user_id=3602,
        username="bootstrapmissingusername",
        email="bootstrapmissingusername@example.com",
    )

    with pytest.raises(
        ValueError,
        match="bootstrap username is not configured",
    ):
        bootstrap_first_admin_service(
            db,
            target_user=target_user,
            bootstrap_username="",
            provided_secret="test-secret",
            configured_secret="test-secret",
        )

    db.refresh(target_user)

    assert target_user.role == UserRole.USER


def test_bootstrap_first_admin_service_rejects_invalid_secret(
    db: Session,
):
    """
    Administrator bootstrap rejects an incorrect bootstrap secret.
    """

    target_user = create_test_user(
        db,
        user_id=3603,
        username="bootstrapinvalidsecret",
        email="bootstrapinvalidsecret@example.com",
    )

    with pytest.raises(
        ValueError,
        match="Invalid administrator bootstrap credentials",
    ):
        bootstrap_first_admin_service(
            db,
            target_user=target_user,
            bootstrap_username=target_user.username,
            provided_secret="wrong-secret",
            configured_secret="correct-secret",
        )

    db.refresh(target_user)

    assert target_user.role == UserRole.USER


def test_bootstrap_first_admin_service_rejects_wrong_username(
    db: Session,
):
    """
    Administrator bootstrap cannot elevate an account other than the
    configured bootstrap username.
    """

    target_user = create_test_user(
        db,
        user_id=3604,
        username="notbootstrapaccount",
        email="notbootstrapaccount@example.com",
    )

    with pytest.raises(
        ValueError,
        match="not authorized for administrator bootstrap",
    ):
        bootstrap_first_admin_service(
            db,
            target_user=target_user,
            bootstrap_username="trackit-frontend",
            provided_secret="test-secret",
            configured_secret="test-secret",
        )

    db.refresh(target_user)

    assert target_user.role == UserRole.USER


def test_bootstrap_first_admin_service_rejects_inactive_account(
    db: Session,
):
    """
    An inactive account cannot be used for administrator bootstrap.
    """

    target_user = create_test_user(
        db,
        user_id=3605,
        username="bootstrapinactive",
        email="bootstrapinactive@example.com",
    )

    target_user.is_active = False
    db.flush()

    with pytest.raises(
        ValueError,
        match="bootstrap account must be active",
    ):
        bootstrap_first_admin_service(
            db,
            target_user=target_user,
            bootstrap_username=target_user.username,
            provided_secret="test-secret",
            configured_secret="test-secret",
        )

    db.refresh(target_user)

    assert target_user.role == UserRole.USER
    assert target_user.is_active is False


def test_bootstrap_first_admin_service_rejects_unverified_account(
    db: Session,
):
    """
    An unverified account cannot be used for administrator bootstrap.
    """

    target_user = create_test_user(
        db,
        user_id=3606,
        username="bootstrapunverified",
        email="bootstrapunverified@example.com",
        is_verified=False,
    )

    with pytest.raises(
        ValueError,
        match="Email verification is required",
    ):
        bootstrap_first_admin_service(
            db,
            target_user=target_user,
            bootstrap_username=target_user.username,
            provided_secret="test-secret",
            configured_secret="test-secret",
        )

    db.refresh(target_user)

    assert target_user.role == UserRole.USER
    assert target_user.is_verified is False


def test_bootstrap_first_admin_service_rejects_non_user_target(
    db: Session,
):
    """
    Administrator bootstrap only accepts a regular user account.
    """

    admin = create_admin(
        db,
        user_id=3607,
        username="bootstrapadmintarget",
        email="bootstrapadmintarget@example.com",
    )

    with pytest.raises(
        ValueError,
        match="Only a regular user account",
    ):
        bootstrap_first_admin_service(
            db,
            target_user=admin,
            bootstrap_username=admin.username,
            provided_secret="test-secret",
            configured_secret="test-secret",
        )

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN


def test_bootstrap_first_admin_service_rejects_existing_active_admin(
    db: Session,
):
    """
    Bootstrap cannot create a second active administrator.
    """

    existing_admin = create_admin(
        db,
        user_id=3608,
        username="existingbootstrapadmin",
        email="existingbootstrapadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=3609,
        username="bootstrapsecondadmin",
        email="bootstrapsecondadmin@example.com",
    )

    with pytest.raises(
        ValueError,
        match="Administrator bootstrap is no longer available",
    ):
        bootstrap_first_admin_service(
            db,
            target_user=target_user,
            bootstrap_username=target_user.username,
            provided_secret="test-secret",
            configured_secret="test-secret",
        )

    db.refresh(existing_admin)
    db.refresh(target_user)

    assert existing_admin.role == UserRole.ADMIN
    assert target_user.role == UserRole.USER


def test_bootstrap_first_admin_service_successfully_promotes_first_admin(
    db: Session,
):
    """
    Successful bootstrap promotes the configured verified user and
    invalidates existing authentication by incrementing token_version.
    """

    target_user = create_test_user(
        db,
        user_id=3610,
        username="bootstrapfirstadmin",
        email="bootstrapfirstadmin@example.com",
    )

    original_token_version = target_user.token_version

    promoted_user = bootstrap_first_admin_service(
        db,
        target_user=target_user,
        bootstrap_username=target_user.username,
        provided_secret="test-secret",
        configured_secret="test-secret",
    )

    assert promoted_user.id == target_user.id
    assert promoted_user.role == UserRole.ADMIN
    assert promoted_user.token_version == original_token_version + 1

    db.refresh(target_user)

    assert target_user.role == UserRole.ADMIN
    assert target_user.token_version == original_token_version + 1


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
    Changing a user's role downward invalidates previously issued
    authentication tokens so the old token cannot retain privileges.
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

    assert response.status_code == 401

# ============================================================================
# ROLE MANAGEMENT TRANSACTION BEHAVIOR
# ============================================================================



def test_bootstrap_first_admin_service_can_be_rolled_back(
    db: Session,
):
    """
    Administrator bootstrap is flush-only and can be rolled back.
    """

    target_user = create_test_user(
        db,
        user_id=3611,
        username="bootstraprollback",
        email="bootstraprollback@example.com",
    )

    target_user_id = target_user.id
    original_token_version = target_user.token_version

    nested = db.begin_nested()

    promoted = bootstrap_first_admin_service(
        db,
        target_user=target_user,
        bootstrap_username=target_user.username,
        provided_secret="test-secret",
        configured_secret="test-secret",
    )

    assert promoted.role == UserRole.ADMIN
    assert promoted.token_version == original_token_version + 1

    db.refresh(target_user)

    assert target_user.role == UserRole.ADMIN
    assert target_user.token_version == original_token_version + 1

    nested.rollback()

    db.expire_all()

    restored_user = db.get(
        User,
        target_user_id,
    )

    assert restored_user is not None
    assert restored_user.role == UserRole.USER
    assert restored_user.token_version == original_token_version


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

def test_last_admin_invariant_is_concurrency_safe():
    """
    Concurrent admin demotion operations cannot bypass the last-admin
    invariant.

    Each operation uses an independent PostgreSQL transaction. The
    transaction-level advisory lock serializes the invariant check so
    only one operation can make the final-admin decision at a time.
    """

    engine = create_engine(
        TEST_DATABASE_URL,
        future=True,
    )

    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    setup_session = SessionLocal()

    admin_one = create_admin(
        setup_session,
        user_id=4011,
        username="concurrencyadminone",
        email="concurrencyadminone@example.com",
    )

    admin_two = create_admin(
        setup_session,
        user_id=4012,
        username="concurrencyadmintwo",
        email="concurrencyadmintwo@example.com",
    )

    setup_session.commit()
    setup_session.close()

    barrier = Barrier(2)
    results: list[str] = []
    errors: list[BaseException] = []

    def demote_admin(
        target_user_id: int,
        acting_admin_id: int,
    ) -> None:
        session = SessionLocal()

        try:
            target_user = session.get(User, target_user_id)
            acting_admin = session.get(User, acting_admin_id)

            if target_user is None or acting_admin is None:
                raise AssertionError(
                    "Concurrent test users were not visible "
                    "to the independent transaction."
                )

            barrier.wait()

            try:
                demote_admin_to_moderator_service(
                    session,
                    target_user=target_user,
                    acting_admin=acting_admin,
                )
                session.commit()
                results.append("success")
            except ValueError as exc:
                session.rollback()
                results.append(str(exc))
        except BaseException as exc:
            errors.append(exc)
        finally:
            session.close()

    thread_one = Thread(
        target=demote_admin,
        args=(admin_one.id, admin_two.id),
    )
    thread_two = Thread(
        target=demote_admin,
        args=(admin_two.id, admin_one.id),
    )

    thread_one.start()
    thread_two.start()

    thread_one.join()
    thread_two.join()

    try:
        assert errors == []

        assert len(results) == 2
        assert results.count("success") == 1
        assert results.count("The last administrator cannot be demoted.") == 1

        verification_session = SessionLocal()

        try:
            remaining_admins = (
                verification_session.query(User)
                .filter(
                    User.role == UserRole.ADMIN,
                    User.is_active.is_(True),
                )
                .count()
            )

            assert remaining_admins == 1
        finally:
            verification_session.close()
    finally:
        cleanup_session = SessionLocal()

        try:
            cleanup_session.query(User).filter(
                User.id.in_([admin_one.id, admin_two.id])
            ).delete(synchronize_session=False)

            cleanup_session.commit()
        finally:
            cleanup_session.close()
            engine.dispose()


# ---------------------------------------------------------------------------
# Admin custom email API tests
# ---------------------------------------------------------------------------


def test_admin_email_requires_authentication(
    client: TestClient,
    db: Session,
):
    response = client.post(
        "/api/profile/admin/email",
        json={
            "user_ids": [1001],
            "subject": "Test subject",
            "message": "Test message",
        },
    )

    assert response.status_code == 401


def test_normal_user_cannot_send_admin_email(
    client: TestClient,
    db: Session,
):
    admin_email = "admin-email-test@example.com"

    user = create_test_user(
        db,
        user_id=4701,
        username="admin-email-multiple-test",
        email="normal-user-email-test@example.com",
    )

    recipient = create_test_user(
        db,
        user_id=4702,
        username="recipient-one-email-test",
        email="recipient-email-test@example.com",
    )

    response = client.post(
        "/api/profile/admin/email",
        headers=authenticated_headers(user),
        json={
            "user_ids": [recipient.id],
            "subject": "Test subject",
            "message": "Test message",
        },
    )

    assert response.status_code == 403


def test_moderator_cannot_send_admin_email(
    client: TestClient,
    db: Session,
):
    moderator = create_moderator(
        db,
        user_id=4703,
        username="admin-inactive-recipient-test",
        email="moderator-email-test@example.com",
    )

    recipient = create_test_user(
        db,
        user_id=4704,
        username="inactive-recipient-test",
        email="recipient-email-test@example.com",
    )

    response = client.post(
        "/api/profile/admin/email",
        headers=authenticated_headers(moderator),
        json={
            "user_ids": [recipient.id],
            "subject": "Test subject",
            "message": "Test message",
        },
    )

    assert response.status_code == 403


def test_admin_can_send_email_to_multiple_users(
    client: TestClient,
    db: Session,
):
    admin = create_admin(
        db,
        user_id=4705,
        username="admin-nonexistent-recipient-test",
        email="admin-multiple-email-test@example.com",
    )

    recipient_one = create_test_user(
        db,
        user_id=4706,
        username="existing-recipient-test",
        email="recipient-one-email-test@example.com",
    )

    recipient_two = create_test_user(
        db,
        user_id=4707,
        username="nonexistent-recipient-test",
        email="recipient-two-email-test@example.com",
    )

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        new_callable=AsyncMock,
    ) as mock_send:
        response = client.post(
            "/api/profile/admin/email",
            headers=authenticated_headers(admin),
            json={
                "user_ids": [
                    recipient_one.id,
                    recipient_two.id,
                ],
                "subject": "TRACKIT announcement",
                "message": "This is an administrative message.",
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2
    assert data["sent"] == 2
    assert data["failed"] == 0

    assert data["results"] == [
        {
            "user_id": recipient_one.id,
            "success": True,
            "error": None,
        },
        {
            "user_id": recipient_two.id,
            "success": True,
            "error": None,
        },
    ]

    assert mock_send.await_count == 2

    calls = mock_send.await_args_list

    assert calls[0].kwargs["recipient"] == recipient_one.email
    assert calls[1].kwargs["recipient"] == recipient_two.email

    assert calls[0].kwargs["subject"] == "TRACKIT announcement"
    assert calls[0].kwargs["message"] == "This is an administrative message."


def test_admin_email_allows_inactive_recipient(
    client: TestClient,
    db: Session,
):
    admin = create_admin(
        db,
        user_id=4708,
        username="admin-no-email-test",
        email="admin-inactive-recipient-test@example.com",
    )

    recipient = create_test_user(
        db,
        user_id=4709,
        username="no-email-recipient-test",
        email="inactive-recipient-test@example.com",
    )

    recipient.is_active = False
    recipient.deactivated_at = datetime.now(timezone.utc)
    recipient.deactivated_until = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    )
    recipient.deactivation_reason = "Test suspension"

    db.add(recipient)
    db.commit()
    db.refresh(recipient)

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        new_callable=AsyncMock,
    ) as mock_send:
        response = client.post(
            "/api/profile/admin/email",
            headers=authenticated_headers(admin),
            json={
                "user_ids": [recipient.id],
                "subject": "Administrative message",
                "message": "This message may be sent to inactive users.",
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["sent"] == 1
    assert data["failed"] == 0
    assert data["results"][0]["user_id"] == recipient.id
    assert data["results"][0]["success"] is True

    mock_send.assert_awaited_once()


def test_admin_email_rejects_nonexistent_recipient_before_sending(
    client: TestClient,
    db: Session,
):
    admin = create_admin(
        db,
        user_id=4710,
        username="admin-delivery-failure-test",
        email="admin-missing-recipient-test@example.com",
    )

    existing_recipient = create_test_user(
        db,
        user_id=4711,
        username="failure-recipient-one-test",
        email="existing-recipient-test@example.com",
    )

    nonexistent_user_id = 999999

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        new_callable=AsyncMock,
    ) as mock_send:
        response = client.post(
            "/api/profile/admin/email",
            headers=authenticated_headers(admin),
            json={
                "user_ids": [
                    existing_recipient.id,
                    nonexistent_user_id,
                ],
                "subject": "Administrative message",
                "message": "This should not be delivered.",
            },
        )

    assert response.status_code == 400

    data = response.json()

    assert "not found" in data["detail"].lower()

    mock_send.assert_not_awaited()


def test_admin_email_rejects_user_without_email_before_sending(
    client: TestClient,
    db: Session,
):
    admin = create_admin(
        db,
        user_id=4712,
        username="admin-audit-test",
        email="admin-missing-email-test@example.com",
    )

    recipient = create_test_user(
        db,
        user_id=4713,
        username="audit-recipient-one-test",
        email="recipient-with-email-test@example.com",
    )

    recipient.email = ""

    db.add(recipient)
    db.commit()
    db.refresh(recipient)

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        new_callable=AsyncMock,
    ) as mock_send:
        response = client.post(
            "/api/profile/admin/email",
            headers=authenticated_headers(admin),
            json={
                "user_ids": [recipient.id],
                "subject": "Administrative message",
                "message": "This should not be delivered.",
            },
        )

    assert response.status_code == 400

    data = response.json()

    assert "email address" in data["detail"].lower()

    mock_send.assert_not_awaited()


def test_admin_email_delivery_failure_does_not_stop_other_recipients(
    client: TestClient,
    db: Session,
):
    admin = create_admin(
        db,
        user_id=4714,
        username="admin-response-test",
        email="admin-delivery-failure-test@example.com",
    )

    successful_recipient = create_test_user(
        db,
        user_id=4715,
        username="private-recipient-test",
        email="successful-recipient-test@example.com",
    )

    failed_recipient = create_test_user(
        db,
        user_id=4716,
        username="private-recipient-two-test",
        email="failed-recipient-test@example.com",
    )

    async def send_email_side_effect(
        *,
        recipient: str,
        subject: str,
        message: str,
    ) -> None:
        if recipient == failed_recipient.email:
            raise RuntimeError("Simulated Resend delivery failure.")

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        new_callable=AsyncMock,
        side_effect=send_email_side_effect,
    ) as mock_send:
        response = client.post(
            "/api/profile/admin/email",
            headers=authenticated_headers(admin),
            json={
                "user_ids": [
                    successful_recipient.id,
                    failed_recipient.id,
                ],
                "subject": "Administrative message",
                "message": "Testing isolated delivery failures.",
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2
    assert data["sent"] == 1
    assert data["failed"] == 1

    assert data["results"][0] == {
        "user_id": successful_recipient.id,
        "success": True,
        "error": None,
    }

    assert data["results"][1] == {
        "user_id": failed_recipient.id,
        "success": False,
        "error": "Email delivery failed.",
    }

    assert mock_send.await_count == 2


def test_admin_email_creates_audit_log_for_each_recipient(
    client: TestClient,
    db: Session,
):
    admin = create_admin(
        db,
        user_id=4717,
        username="admin-duplicate-test",
        email="admin-audit-email-test@example.com",
    )

    successful_recipient = create_test_user(
        db,
        user_id=4718,
        username="duplicate-recipient-test",
        email="audit-success-recipient-test@example.com",
    )

    failed_recipient = create_test_user(
        db,
        user_id=4719,
        username="duplicate-recipient-two-test",
        email="audit-failed-recipient-test@example.com",
    )

    async def send_email_side_effect(
        *,
        recipient: str,
        subject: str,
        message: str,
    ) -> None:
        if recipient == failed_recipient.email:
            raise RuntimeError("Simulated Resend delivery failure.")

    email_message = "This private message must not appear in the audit log."

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        new_callable=AsyncMock,
        side_effect=send_email_side_effect,
    ):
        response = client.post(
            "/api/profile/admin/email",
            headers=authenticated_headers(admin),
            json={
                "user_ids": [
                    successful_recipient.id,
                    failed_recipient.id,
                ],
                "subject": "Audit test subject",
                "message": email_message,
            },
        )

    assert response.status_code == 200

    logs = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == admin.id,
            AuditLog.action == "admin_action",
            AuditLog.resource_type == "user",
        )
        .order_by(AuditLog.id.asc())
        .all()
    )

    recipient_logs = [
        log
        for log in logs
        if log.resource_id in {
            successful_recipient.id,
            failed_recipient.id,
        }
    ]

    assert len(recipient_logs) == 2

    for log in recipient_logs:
        assert log.resource_id in {
            successful_recipient.id,
            failed_recipient.id,
        }

        if log.description is not None:
            assert email_message not in log.description


def test_admin_email_response_does_not_expose_recipient_addresses(
    client: TestClient,
    db: Session,
):
    admin = create_admin(
        db,
        user_id=4720,
        username="admin-response-email-test",
        email="admin-response-email-test@example.com",
    )

    recipient = create_test_user(
        db,
        user_id=4721,
        username="Private-recipient-address",
        email="private-recipient-address@example.com",
    )

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        new_callable=AsyncMock,
    ):
        response = client.post(
            "/api/profile/admin/email",
            headers=authenticated_headers(admin),
            json={
                "user_ids": [recipient.id],
                "subject": "Privacy test",
                "message": "Recipient address must not be returned.",
            },
        )

    assert response.status_code == 200

    response_text = response.text

    assert recipient.email not in response_text

    data = response.json()

    assert data["results"][0]["user_id"] == recipient.id
    assert "email" not in data["results"][0]


def test_admin_email_rejects_duplicate_recipient_ids(
    client: TestClient,
    db: Session,
):
    admin = create_admin(
        db,
        user_id=4722,
        username="admin-duplicate-email-test",
        email="admin-duplicate-email-test@example.com",
    )

    recipient = create_test_user(
        db,
        user_id=4723,
        username="duplicate-recipient-test",
        email="duplicate-recipient-test@example.com",
    )

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        new_callable=AsyncMock,
    ) as mock_send:
        response = client.post(
            "/api/profile/admin/email",
            headers=authenticated_headers(admin),
            json={
                "user_ids": [
                    recipient.id,
                    recipient.id,
                ],
                "subject": "Duplicate test",
                "message": "This should fail validation.",
            },
        )

    assert response.status_code == 422
    mock_send.assert_not_awaited()


def test_admin_email_rejects_empty_subject(
    client: TestClient,
    db: Session,
):
    admin = create_admin(
        db,
        user_id=4724,
        username="admin-empty-subject-test",
        email="admin-empty-subject-test@example.com",
    )

    recipient = create_test_user(
        db,
        user_id=4725,
        username="empty-subject-recipient-test",
        email="empty-subject-recipient-test@example.com",
    )

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        new_callable=AsyncMock,
    ) as mock_send:
        response = client.post(
            "/api/profile/admin/email",
            headers=authenticated_headers(admin),
            json={
                "user_ids": [recipient.id],
                "subject": "   ",
                "message": "Valid message.",
            },
        )

    assert response.status_code == 422
    mock_send.assert_not_awaited()


def test_admin_email_rejects_empty_message(
    client: TestClient,
    db: Session,
):
    admin = create_admin(
        db,
        user_id=4726,
        username="admin-empty-subject-test",
        email="admin-empty-message-test@example.com",
    )

    recipient = create_test_user(
        db,
        user_id=4727,
        username="empty-subject-recipient-test",
        email="empty-message-recipient-test@example.com",
    )

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        new_callable=AsyncMock,
    ) as mock_send:
        response = client.post(
            "/api/profile/admin/email",
            headers=authenticated_headers(admin),
            json={
                "user_ids": [recipient.id],
                "subject": "Valid subject",
                "message": "   ",
            },
        )

    assert response.status_code == 422
    mock_send.assert_not_awaited()

# ============================================================================
# ACCOUNT SUSPENSION SERVICE
# ============================================================================


def test_suspend_user_service_successfully_suspends_account(
    db: Session,
):
    """
    A valid suspension deactivates the target account and records the
    suspension metadata.
    """

    admin = create_admin(
        db,
        user_id=4101,
        username="suspendserviceadmin",
        email="suspendserviceadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4102,
        username="suspensiontarget",
        email="suspensiontarget@example.com",
    )

    original_token_version = target_user.token_version

    suspended = suspend_user(
        db,
        target_user=target_user,
        acting_admin=admin,
        duration_hours=24,
        reason="Temporary policy violation.",
    )

    assert suspended is target_user
    assert suspended.is_active is False
    assert suspended.deactivated_at is not None
    assert suspended.deactivated_until is not None
    assert suspended.deactivation_reason == (
        "Temporary policy violation."
    )
    assert suspended.deactivated_until > suspended.deactivated_at
    assert suspended.token_version == (
        original_token_version + 1
    )


def test_suspend_user_service_preserves_role(
    db: Session,
):
    """
    Suspension changes account activity state but never changes the user's
    role.
    """

    admin = create_admin(
        db,
        user_id=4103,
        username="suspendroleadmin",
        email="suspendroleadmin@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=4104,
        username="suspendmoderator",
        email="suspendmoderator@example.com",
    )

    original_role = target_moderator.role

    suspended = suspend_user(
        db,
        target_user=target_moderator,
        acting_admin=admin,
        duration_hours=12,
    )

    assert suspended.role == original_role
    assert suspended.role == UserRole.MODERATOR
    assert suspended.is_active is False


def test_suspend_user_service_rejects_self_suspension(
    db: Session,
):
    """
    An administrator cannot suspend their own account.
    """

    admin = create_admin(
        db,
        user_id=4105,
        username="selfsuspendadmin",
        email="selfsuspendadmin@example.com",
    )

    with pytest.raises(
        ValueError,
        match="cannot suspend themselves",
    ):
        suspend_user(
            db,
            target_user=admin,
            acting_admin=admin,
            duration_hours=24,
        )

    db.refresh(admin)

    assert admin.is_active is True
    assert admin.deactivated_at is None
    assert admin.deactivated_until is None
    assert admin.deactivation_reason is None


@pytest.mark.parametrize(
    "duration_hours",
    [
        0,
        -1,
        2161,
    ],
)
def test_suspend_user_service_rejects_invalid_duration(
    db: Session,
    duration_hours: int,
):
    """
    Suspension duration must be between one hour and ninety days.
    """

    admin = create_admin(
        db,
        user_id=4110 + abs(duration_hours),
        username=f"invaliddurationadmin{abs(duration_hours)}",
        email=f"invaliddurationadmin{abs(duration_hours)}@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4120 + abs(duration_hours),
        username=f"invaliddurationtarget{abs(duration_hours)}",
        email=f"invaliddurationtarget{abs(duration_hours)}@example.com",
    )

    with pytest.raises(
        ValueError,
        match="duration",
    ):
        suspend_user(
            db,
            target_user=target_user,
            acting_admin=admin,
            duration_hours=duration_hours,
        )

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None


def test_suspend_user_service_rejects_boolean_duration(
    db: Session,
):
    """
    Boolean values must not be accepted as suspension durations even though
    bool is a subclass of int in Python.
    """

    admin = create_admin(
        db,
        user_id=4131,
        username="booldurationadmin",
        email="booldurationadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4132,
        username="booldurationtarget",
        email="booldurationtarget@example.com",
    )

    with pytest.raises(
        ValueError,
        match="duration",
    ):
        suspend_user(
            db,
            target_user=target_user,
            acting_admin=admin,
            duration_hours=True,
        )

    db.refresh(target_user)

    assert target_user.is_active is True


def test_suspend_user_service_rejects_already_inactive_user(
    db: Session,
):
    """
    An account that is already inactive cannot be suspended again.
    """

    admin = create_admin(
        db,
        user_id=4141,
        username="alreadyinactiveadmin",
        email="alreadyinactiveadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4142,
        username="alreadyinactive",
        email="alreadyinactive@example.com",
    )

    target_user.is_active = False
    db.flush()

    with pytest.raises(
        ValueError,
        match="already inactive",
    ):
        suspend_user(
            db,
            target_user=target_user,
            acting_admin=admin,
            duration_hours=24,
        )

    db.refresh(target_user)

    assert target_user.is_active is False
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None


def test_suspend_user_service_rejects_last_active_admin(
    db: Session,
):
    """
    The last active administrator cannot be suspended.

    The acting administrator is intentionally not persisted because the
    database must contain exactly one active administrator for this test.
    """

    admin = create_admin(
        db,
        user_id=4151,
        username="lastactiveadmin",
        email="lastactiveadmin@example.com",
    )

    acting_admin = User(
        id=4152,
        username="differentactingadmin",
        first_name="Different",
        last_name="Admin",
        email="differentactingadmin@example.com",
        password_hash="test-password-hash",
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )

    with pytest.raises(
        ValueError,
        match="last active administrator",
    ):
        suspend_user(
            db,
            target_user=admin,
            acting_admin=acting_admin,
            duration_hours=24,
        )

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN
    assert admin.is_active is True
    assert admin.deactivated_at is None
    assert admin.deactivated_until is None
    assert admin.deactivation_reason is None

def test_activate_suspended_user_service_preserves_role(
    db: Session,
):
    """
    Activation restores account access without changing the user's role.
    """

    admin = create_admin(
        db,
        user_id=4211,
        username="activateroleadmin",
        email="activateroleadmin@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=4212,
        username="activaterolemoderator",
        email="activaterolemoderator@example.com",
    )

    suspend_user(
        db,
        target_user=target_moderator,
        acting_admin=admin,
        duration_hours=24,
    )

    activate_suspended_user(
        db,
        target_moderator,
    )

    db.refresh(target_moderator)

    assert target_moderator.is_active is True
    assert target_moderator.role == UserRole.MODERATOR


def test_activate_suspended_user_service_rejects_already_active_user(
    db: Session,
):
    """
    An already-active account cannot be activated again.
    """

    admin = create_admin(
        db,
        user_id=4251,
        username="alreadyactiveadmin",
        email="alreadyactiveadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4252,
        username="alreadyactiveuser",
        email="alreadyactiveuser@example.com",
    )

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None

    with pytest.raises(
        ValueError,
        match="already active",
    ):
        activate_suspended_user(
            db,
            target_user,
        )

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None
    assert target_user.deactivation_reason is None


def test_activate_suspended_user_service_rejects_inactive_user_without_suspension_metadata(
    db: Session,
):
    """
    An inactive account without suspension metadata cannot be treated as
    a suspended account and activated through the suspension workflow.
    """

    admin = create_admin(
        db,
        user_id=4261,
        username="inactivewithoutsuspensionadmin",
        email="inactivewithoutsuspensionadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4262,
        username="inactivewithoutsuspension",
        email="inactivewithoutsuspension@example.com",
    )

    target_user.is_active = False
    target_user.deactivated_at = None
    target_user.deactivated_until = None
    target_user.deactivation_reason = None
    db.flush()

    with pytest.raises(
        ValueError,
        match="not currently suspended",
    ):
        activate_suspended_user(
            db,
            target_user,
        )

    db.refresh(target_user)

    assert target_user.is_active is False
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None
    assert target_user.deactivation_reason is None

def test_reactivate_expired_suspended_users_service_reactivates_expired_account(
    db: Session,
):
    """
    An expired temporary suspension is automatically removed and
    the account is reactivated.
    """

    from app.services.user import (
        reactivate_expired_suspended_users,
        suspend_user,
    )

    admin = create_admin(
        db,
        user_id=4221,
        username="expirationadmin",
        email="expirationadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4222,
        username="expireduser",
        email="expireduser@example.com",
    )

    original_role = target_user.role
    original_token_version = target_user.token_version

    suspend_user(
        db,
        target_user=target_user,
        acting_admin=admin,
        duration_hours=1,
        reason="Temporary suspension.",
    )

    db.refresh(target_user)

    assert target_user.deactivated_until is not None

    expired_time = target_user.deactivated_until + timedelta(
        seconds=1
    )

    reactivated_users = reactivate_expired_suspended_users(
        db,
        now=expired_time,
    )

    db.refresh(target_user)

    assert target_user in reactivated_users
    assert target_user.is_active is True
    assert target_user.role == original_role
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None
    assert target_user.deactivation_reason is None
    assert target_user.token_version == original_token_version + 2


def test_reactivate_expired_suspended_users_service_leaves_future_suspension_untouched(
    db: Session,
):
    """
    A suspension whose deadline has not yet been reached remains
    active.
    """

    from app.services.user import (
        reactivate_expired_suspended_users,
        suspend_user,
    )

    admin = create_admin(
        db,
        user_id=4231,
        username="futureexpirationadmin",
        email="futureexpirationadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4232,
        username="futureuser",
        email="futureuser@example.com",
    )

    suspend_user(
        db,
        target_user=target_user,
        acting_admin=admin,
        duration_hours=24,
    )

    db.refresh(target_user)

    assert target_user.deactivated_until is not None

    suspension_deadline = target_user.deactivated_until

    reactivated_users = reactivate_expired_suspended_users(
        db,
        now=(
            suspension_deadline
            - timedelta(
                seconds=1
            )
        ),
    )

    db.refresh(target_user)

    assert reactivated_users == []
    assert target_user.is_active is False
    assert target_user.deactivated_until == suspension_deadline


def test_reactivate_expired_suspended_users_service_processes_multiple_accounts(
    db: Session,
):
    """
    Multiple expired suspended accounts are reactivated during a
    single expiration run.
    """

    from app.services.user import (
        reactivate_expired_suspended_users,
        suspend_user,
    )

    admin = create_admin(
        db,
        user_id=4241,
        username="multipleexpirationadmin",
        email="multipleexpirationadmin@example.com",
    )

    first_user = create_test_user(
        db,
        user_id=4242,
        username="expiredfirst",
        email="expiredfirst@example.com",
    )

    second_user = create_test_user(
        db,
        user_id=4243,
        username="expiredsecond",
        email="expiredsecond@example.com",
    )

    suspend_user(
        db,
        target_user=first_user,
        acting_admin=admin,
        duration_hours=1,
    )

    suspend_user(
        db,
        target_user=second_user,
        acting_admin=admin,
        duration_hours=2,
    )

    db.refresh(first_user)
    db.refresh(second_user)

    assert first_user.deactivated_until is not None
    assert second_user.deactivated_until is not None

    expiration_time = max(
        first_user.deactivated_until,
        second_user.deactivated_until,
    ) + timedelta(
        seconds=1
    )

    reactivated_users = reactivate_expired_suspended_users(
        db,
        now=expiration_time,
    )

    db.refresh(first_user)
    db.refresh(second_user)

    assert len(reactivated_users) == 2

    assert first_user.is_active is True
    assert second_user.is_active is True

    assert first_user.deactivated_until is None
    assert second_user.deactivated_until is None

    assert first_user.deactivation_reason is None
    assert second_user.deactivation_reason is None


def test_reactivate_expired_suspended_users_service_ignores_unscheduled_inactive_account(
    db: Session,
):
    """
    An inactive account without a scheduled suspension is not
    automatically reactivated.
    """

    from app.services.user import (
        reactivate_expired_suspended_users,
    )

    target_user = create_test_user(
        db,
        user_id=4252,
        username="unscheduledinactive",
        email="unscheduledinactive@example.com",
    )

    target_user.is_active = False
    target_user.deactivated_at = None
    target_user.deactivated_until = None
    target_user.deactivation_reason = None

    db.flush()

    reactivated_users = reactivate_expired_suspended_users(
        db,
        now=datetime.now(timezone.utc) + timedelta(days=365),
    )

    db.refresh(target_user)

    assert reactivated_users == []
    assert target_user.is_active is False
    assert target_user.deactivated_until is None


def test_suspend_and_activate_service_changes_can_be_rolled_back(
    db: Session,
):
    """
    Suspension and activation remain flush-only operations and participate
    correctly in the surrounding transaction.
    """

    admin = create_admin(
        db,
        user_id=4221,
        username="rollbacksuspendadmin",
        email="rollbacksuspendadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4222,
        username="rollbacksuspendtarget",
        email="rollbacksuspendtarget@example.com",
    )

    target_user_id = target_user.id
    original_token_version = target_user.token_version

    nested = db.begin_nested()

    suspended = suspend_user(
        db,
        target_user=target_user,
        acting_admin=admin,
        duration_hours=24,
        reason="Rollback test.",
    )

    assert suspended.is_active is False
    assert suspended.deactivation_reason == "Rollback test."

    nested.rollback()

    db.expire_all()

    restored_user = db.get(
        User,
        target_user_id,
    )

    assert restored_user is not None
    assert restored_user.is_active is True
    assert restored_user.deactivated_at is None
    assert restored_user.deactivated_until is None
    assert restored_user.deactivation_reason is None
    assert restored_user.token_version == original_token_version


# ============================================================================
# ACCOUNT SUSPENSION API
# ============================================================================


def test_admin_can_suspend_user(
    client: TestClient,
    db: Session,
):
    """
    An administrator can temporarily suspend an active user.
    """

    admin = create_admin(
        db,
        user_id=4301,
        username="apisuspendadmin",
        email="apisuspendadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4302,
        username="apisuspendtarget",
        email="apisuspendtarget@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
            "reason": "API suspension test.",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_user.id
    assert data["is_active"] is False
    assert data["role"] == UserRole.USER
    assert data["deactivation_reason"] == (
        "API suspension test."
    )
    assert data["deactivated_at"] is not None
    assert data["deactivated_until"] is not None

    db.refresh(target_user)

    assert target_user.is_active is False
    assert target_user.deactivation_reason == (
        "API suspension test."
    )


def test_admin_suspend_sends_deactivation_email(
    client: TestClient,
    db: Session,
):
    """
    A successful account suspension sends a deactivation email
    after the suspension transaction commits.
    """

    admin = create_admin(
        db,
        user_id=4303,
        username="emailsuspendadmin",
        email="emailsuspendadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4304,
        username="emailsuspendtarget",
        email="emailsuspendtarget@example.com",
    )

    with patch(
        "app.routers.profile.send_account_deactivation_email",
        new_callable=AsyncMock,
    ) as mock_send_email:
        response = client.patch(
            f"/api/profile/admin/{target_user.id}/deactivate",
            headers=authenticated_headers(admin),
            json={
                "duration_hours": 24,
                "reason": "Email suspension test.",
            },
        )

    assert response.status_code == 200
    mock_send_email.assert_awaited_once()

    email_kwargs = mock_send_email.await_args.kwargs

    assert email_kwargs["recipient"] == (
        "emailsuspendtarget@example.com"
    )
    assert email_kwargs["deactivated_at"] is not None
    assert email_kwargs["deactivated_until"] is not None
    assert email_kwargs["reason"] == "Email suspension test."

    db.refresh(target_user)

    assert target_user.is_active is False
    assert email_kwargs["deactivated_at"] == (
        target_user.deactivated_at
    )
    assert email_kwargs["deactivated_until"] == (
        target_user.deactivated_until
    )


def test_admin_suspend_email_failure_does_not_rollback_suspension(
    client: TestClient,
    db: Session,
):
    """
    Email delivery failure does not roll back an already committed
    account suspension.
    """

    admin = create_admin(
        db,
        user_id=4305,
        username="emailfailadmin",
        email="emailfailadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4306,
        username="emailfailtarget",
        email="emailfailtarget@example.com",
    )

    with patch(
        "app.routers.profile.send_account_deactivation_email",
        new_callable=AsyncMock,
        side_effect=RuntimeError("Resend delivery failed."),
    ) as mock_send_email:
        response = client.patch(
            f"/api/profile/admin/{target_user.id}/deactivate",
            headers=authenticated_headers(admin),
            json={
                "duration_hours": 24,
                "reason": "Email failure transaction test.",
            },
        )

    assert response.status_code == 200
    mock_send_email.assert_awaited_once()

    data = response.json()

    assert data["id"] == target_user.id
    assert data["is_active"] is False
    assert data["deactivation_reason"] == (
        "Email failure transaction test."
    )
    assert data["deactivated_at"] is not None
    assert data["deactivated_until"] is not None

    db.refresh(target_user)

    assert target_user.is_active is False
    assert target_user.deactivation_reason == (
        "Email failure transaction test."
    )
    assert target_user.deactivated_at is not None
    assert target_user.deactivated_until is not None


def test_admin_can_suspend_moderator_without_changing_role(
    client: TestClient,
    db: Session,
):
    """
    Suspending a moderator does not alter the moderator's role.
    """

    admin = create_admin(
        db,
        user_id=4311,
        username="apisuspendmoderatoradmin",
        email="apisuspendmoderatoradmin@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=4312,
        username="apisuspendmoderator",
        email="apisuspendmoderator@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_moderator.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 48,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["is_active"] is False
    assert data["role"] == UserRole.MODERATOR

    db.refresh(target_moderator)

    assert target_moderator.is_active is False
    assert target_moderator.role == UserRole.MODERATOR


def test_moderator_cannot_suspend_user(
    client: TestClient,
    db: Session,
):
    """
    Moderators do not have permission to suspend accounts.
    """

    moderator = create_moderator(
        db,
        user_id=4321,
        username="moderatorsuspendattempt",
        email="moderatorsuspendattempt@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4322,
        username="moderatorsuspendtarget",
        email="moderatorsuspendtarget@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(moderator),
        json={
            "duration_hours": 24,
        },
    )

    assert response.status_code == 403

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None


def test_regular_user_cannot_suspend_user(
    client: TestClient,
    db: Session,
):
    """
    Regular users do not have permission to suspend accounts.
    """

    user = create_test_user(
        db,
        user_id=4331,
        username="usersuspendattempt",
        email="usersuspendattempt@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4332,
        username="usersuspendtarget",
        email="usersuspendtarget@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(user),
        json={
            "duration_hours": 24,
        },
    )

    assert response.status_code == 403

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None


def test_unauthenticated_user_cannot_suspend_user(
    client: TestClient,
    db: Session,
):
    """
    Suspension requires authentication.
    """

    target_user = create_test_user(
        db,
        user_id=4341,
        username="unauthenticatedtarget",
        email="unauthenticatedtarget@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        json={
            "duration_hours": 24,
        },
    )

    assert response.status_code == 401

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None


def test_admin_suspend_nonexistent_user_returns_404(
    client: TestClient,
    db: Session,
):
    """
    Suspending a nonexistent user returns 404.
    """

    admin = create_admin(
        db,
        user_id=4351,
        username="missingtargetadmin",
        email="missingtargetadmin@example.com",
    )

    response = client.patch(
        "/api/profile/admin/999999/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
        },
    )

    assert response.status_code == 404


@pytest.mark.parametrize(
    "duration_hours",
    [
        0,
        -1,
        2161,
    ],
)
def test_admin_suspend_invalid_duration_returns_422(
    client: TestClient,
    db: Session,
    duration_hours: int,
):
    """
    The API schema rejects suspension durations outside the supported range.
    """

    admin = create_admin(
        db,
        user_id=4360 + abs(duration_hours),
        username=f"apiinvaliddurationadmin{abs(duration_hours)}",
        email=(
            f"apiinvaliddurationadmin{abs(duration_hours)}"
            "@example.com"
        ),
    )

    target_user = create_test_user(
        db,
        user_id=4370 + abs(duration_hours),
        username=f"apiinvaliddurationtarget{abs(duration_hours)}",
        email=(
            f"apiinvaliddurationtarget{abs(duration_hours)}"
            "@example.com"
        ),
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": duration_hours,
        },
    )

    assert response.status_code == 422

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None


def test_admin_suspend_self_returns_409(
    client: TestClient,
    db: Session,
):
    """
    An administrator cannot suspend their own account.
    """

    admin = create_admin(
        db,
        user_id=4381,
        username="apiselfsuspend",
        email="apiselfsuspend@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{admin.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
        },
    )

    assert response.status_code == 409

    db.refresh(admin)

    assert admin.is_active is True
    assert admin.deactivated_at is None
    assert admin.deactivated_until is None


def test_admin_cannot_suspend_already_inactive_user(
    client: TestClient,
    db: Session,
):
    """
    An already inactive account cannot be suspended again.
    """

    admin = create_admin(
        db,
        user_id=4391,
        username="apiinactiveadmin",
        email="apiinactiveadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4392,
        username="apiinactiveuser",
        email="apiinactiveuser@example.com",
    )

    target_user.is_active = False
    db.flush()

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
        },
    )

    assert response.status_code == 409

    db.refresh(target_user)

    assert target_user.is_active is False
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None


def test_admin_suspend_normalizes_whitespace_reason(
    client: TestClient,
    db: Session,
):
    """
    Whitespace-only suspension reasons are stored as null.
    """

    admin = create_admin(
        db,
        user_id=4401,
        username="apiwhitespacereasonadmin",
        email="apiwhitespacereasonadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4402,
        username="apiwhitespacereasontarget",
        email="apiwhitespacereasontarget@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
            "reason": "     ",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["deactivation_reason"] is None

    db.refresh(target_user)

    assert target_user.deactivation_reason is None


def test_admin_suspend_rejects_reason_over_500_characters(
    client: TestClient,
    db: Session,
):
    """
    Suspension reasons longer than 500 characters are rejected by the API.
    """

    admin = create_admin(
        db,
        user_id=4411,
        username="apilongreasonadmin",
        email="apilongreasonadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4412,
        username="apilongreasontarget",
        email="apilongreasontarget@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
            "reason": "x" * 501,
        },
    )

    assert response.status_code == 422

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None

def test_admin_suspend_invalidates_stored_auth_tokens(
    client: TestClient,
    db: Session,
):
    """
    Suspending a user invalidates all unused stored authentication tokens.
    """

    admin = create_admin(
        db,
        user_id=4421,
        username="tokensuspendadmin",
        email="tokensuspendadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4422,
        username="tokensuspendtarget",
        email="tokensuspendtarget@example.com",
    )

    auth_token = AuthToken(
        user_id=target_user.id,
        token_hash="b" * 64,
        token_type="password_reset",
        expires_at=(
            datetime.now(timezone.utc)
            + timedelta(minutes=15)
        ),
    )

    db.add(auth_token)
    db.flush()

    token_id = auth_token.id

    assert auth_token.used_at is None

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
        },
    )

    assert response.status_code == 200

    db.expire_all()

    stored_token = db.get(
        AuthToken,
        token_id,
    )

    assert stored_token is not None
    assert stored_token.used_at is not None


def test_admin_suspend_creates_audit_log(
    client: TestClient,
    db: Session,
):
    """
    A successful account suspension creates an administrator audit record.
    """

    admin = create_admin(
        db,
        user_id=4431,
        username="auditsuspendadmin",
        email="auditsuspendadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4432,
        username="auditsuspendtarget",
        email="auditsuspendtarget@example.com",
    )

    before_audit_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 48,
            "reason": "Audit suspension test.",
        },
    )

    assert response.status_code == 200

    after_audit_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    assert after_audit_count == (
        before_audit_count + 1
    )

    audit_log = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == admin.id,
            AuditLog.action == "admin_action",
        )
        .order_by(AuditLog.id.desc())
        .first()
    )

    assert audit_log is not None
    assert audit_log.success is True
    assert audit_log.description is not None
    assert "suspended user" in audit_log.description
    assert str(target_user.id) in audit_log.description
    assert "48 hours" in audit_log.description


def test_admin_cannot_suspend_last_active_admin_via_api(
    client: TestClient,
    db: Session,
):
    """
    The API enforces the last-active-administrator protection.
    """

    admin = create_admin(
        db,
        user_id=4441,
        username="apilastactiveadmin",
        email="apilastactiveadmin@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{admin.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
        },
    )

    assert response.status_code == 409

    db.refresh(admin)

    assert admin.role == UserRole.ADMIN
    assert admin.is_active is True
    assert admin.deactivated_at is None
    assert admin.deactivated_until is None
    assert admin.deactivation_reason is None


def test_admin_activate_creates_audit_log(
    client: TestClient,
    db: Session,
):
    """
    A successful manual account reactivation creates an administrator
    audit record.
    """

    admin = create_admin(
        db,
        user_id=4451,
        username="auditactivateadmin",
        email="auditactivateadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4452,
        username="auditactivatetarget",
        email="auditactivatetarget@example.com",
    )

    suspend_response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
            "reason": "Prepare activation audit test.",
        },
    )

    assert suspend_response.status_code == 200

    before_audit_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/activate",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_user.id
    assert data["is_active"] is True
    assert data["deactivated_at"] is None
    assert data["deactivated_until"] is None
    assert data["deactivation_reason"] is None

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None
    assert target_user.deactivation_reason is None

    after_audit_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    assert after_audit_count == (
        before_audit_count + 1
    )

    audit_log = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == admin.id,
            AuditLog.action == "admin_action",
        )
        .order_by(AuditLog.id.desc())
        .first()
    )

    assert audit_log is not None
    assert audit_log.success is True
    assert audit_log.description is not None
    assert "reactivated user" in audit_log.description
    assert str(target_user.id) in audit_log.description

# ============================================================================
# ACCOUNT SUSPENSION SECURITY / ACTIVATION API
# ============================================================================


def test_suspended_user_existing_jwt_is_invalidated(
    client: TestClient,
    db: Session,
):
    """
    Suspending a user invalidates JWT access that was issued before
    the suspension.
    """

    admin = create_admin(
        db,
        user_id=4501,
        username="jwtsuspendadmin",
        email="jwtsuspendadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4502,
        username="jwtsuspendtarget",
        email="jwtsuspendtarget@example.com",
    )

    target_headers = authenticated_headers(target_user)

    response = client.get(
        "/api/profile",
        headers=target_headers,
    )

    assert response.status_code == 200

    original_token_version = target_user.token_version

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
            "reason": "JWT invalidation test.",
        },
    )

    assert response.status_code == 200

    db.refresh(target_user)

    assert target_user.is_active is False
    assert target_user.token_version == (
        original_token_version + 1
    )

    response = client.get(
        "/api/profile",
        headers=target_headers,
    )

    assert response.status_code == 401


def test_admin_can_manually_reactivate_suspended_user(
    client: TestClient,
    db: Session,
):
    """
    An administrator can manually reactivate a suspended account.
    """

    admin = create_admin(
        db,
        user_id=4511,
        username="activateadmin",
        email="activateadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4512,
        username="activatetarget",
        email="activatetarget@example.com",
    )

    suspend_response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
            "reason": "Manual activation test.",
        },
    )

    assert suspend_response.status_code == 200

    db.refresh(target_user)

    assert target_user.is_active is False
    assert target_user.deactivated_at is not None
    assert target_user.deactivated_until is not None
    assert target_user.deactivation_reason == (
        "Manual activation test."
    )

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/activate",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == target_user.id
    assert data["is_active"] is True
    assert data["deactivated_at"] is None
    assert data["deactivated_until"] is None
    assert data["deactivation_reason"] is None

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None
    assert target_user.deactivation_reason is None


def test_admin_activate_sends_reactivation_email(
    client: TestClient,
    db: Session,
):
    """
    A successful manual account reactivation sends a reactivation
    email after the activation transaction commits.
    """

    admin = create_admin(
        db,
        user_id=4513,
        username="emailactivateadmin",
        email="emailactivateadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4514,
        username="emailactivatetarget",
        email="emailactivatetarget@example.com",
    )

    suspend_response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
            "reason": "Manual reactivation email test.",
        },
    )

    assert suspend_response.status_code == 200

    with patch(
        "app.routers.profile.send_account_reactivation_email",
        new_callable=AsyncMock,
    ) as mock_send_email:
        response = client.patch(
            f"/api/profile/admin/{target_user.id}/activate",
            headers=authenticated_headers(admin),
        )

    assert response.status_code == 200
    mock_send_email.assert_awaited_once()

    email_kwargs = mock_send_email.await_args.kwargs

    assert email_kwargs["recipient"] == (
        "emailactivatetarget@example.com"
    )
    assert email_kwargs["reactivated_at"] is not None
    assert email_kwargs["reason"] == (
        "Manual reactivation email test."
    )

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None
    assert target_user.deactivation_reason is None


def test_admin_activate_email_failure_does_not_rollback_activation(
    client: TestClient,
    db: Session,
):
    """
    Email delivery failure does not roll back an already committed
    manual account activation.
    """

    admin = create_admin(
        db,
        user_id=4515,
        username="emailactivatefailadmin",
        email="emailactivatefailadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4516,
        username="emailactivatefailtarget",
        email="emailactivatefailtarget@example.com",
    )

    suspend_response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
            "reason": "Manual activation email failure test.",
        },
    )

    assert suspend_response.status_code == 200

    with patch(
        "app.routers.profile.send_account_reactivation_email",
        new_callable=AsyncMock,
        side_effect=RuntimeError("Resend delivery failed."),
    ) as mock_send_email:
        response = client.patch(
            f"/api/profile/admin/{target_user.id}/activate",
            headers=authenticated_headers(admin),
        )

    assert response.status_code == 200
    mock_send_email.assert_awaited_once()

    data = response.json()

    assert data["id"] == target_user.id
    assert data["is_active"] is True
    assert data["deactivated_at"] is None
    assert data["deactivated_until"] is None
    assert data["deactivation_reason"] is None

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None
    assert target_user.deactivation_reason is None


def test_manual_activation_preserves_user_role(
    client: TestClient,
    db: Session,
):
    """
    Manual activation restores account access without changing the
    suspended user's role.
    """

    admin = create_admin(
        db,
        user_id=4521,
        username="activateuserroleadmin",
        email="activateuserroleadmin@example.com",
    )

    target_moderator = create_moderator(
        db,
        user_id=4522,
        username="activateusermoderator",
        email="activateusermoderator@example.com",
    )

    response = client.patch(
        f"/api/profile/admin/{target_moderator.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
        },
    )

    assert response.status_code == 200

    response = client.patch(
        f"/api/profile/admin/{target_moderator.id}/activate",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["is_active"] is True
    assert data["role"] == UserRole.MODERATOR

    db.refresh(target_moderator)

    assert target_moderator.is_active is True
    assert target_moderator.role == UserRole.MODERATOR


def test_moderator_cannot_manually_activate_user(
    client: TestClient,
    db: Session,
):
    """
    Moderators do not have permission to manually activate accounts.
    """

    moderator = create_moderator(
        db,
        user_id=4531,
        username="moderatoractivateattempt",
        email="moderatoractivateattempt@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4532,
        username="moderatoractivatetarget",
        email="moderatoractivatetarget@example.com",
    )

    target_user.is_active = False
    target_user.deactivated_at = datetime.now(
        timezone.utc
    )
    target_user.deactivated_until = (
        datetime.now(timezone.utc)
        + timedelta(hours=24)
    )
    target_user.deactivation_reason = (
        "Activation authorization test."
    )
    db.flush()

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/activate",
        headers=authenticated_headers(moderator),
    )

    assert response.status_code == 403

    db.refresh(target_user)

    assert target_user.is_active is False
    assert target_user.deactivation_reason == (
        "Activation authorization test."
    )


def test_regular_user_cannot_manually_activate_user(
    client: TestClient,
    db: Session,
):
    """
    Regular users do not have permission to manually activate accounts.
    """

    user = create_test_user(
        db,
        user_id=4541,
        username="useractivateattempt",
        email="useractivateattempt@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4542,
        username="useractivatetarget",
        email="useractivatetarget@example.com",
    )

    target_user.is_active = False
    target_user.deactivated_at = datetime.now(
        timezone.utc
    )
    target_user.deactivated_until = (
        datetime.now(timezone.utc)
        + timedelta(hours=24)
    )
    target_user.deactivation_reason = (
        "Activation authorization test."
    )
    db.flush()

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/activate",
        headers=authenticated_headers(user),
    )

    assert response.status_code == 403

    db.refresh(target_user)

    assert target_user.is_active is False
    assert target_user.deactivation_reason == (
        "Activation authorization test."
    )


def test_unauthenticated_user_cannot_manually_activate_user(
    client: TestClient,
    db: Session,
):
    """
    Manual activation requires authentication.
    """

    target_user = create_test_user(
        db,
        user_id=4551,
        username="unauthenticatedactivationtarget",
        email="unauthenticatedactivationtarget@example.com",
    )

    target_user.is_active = False
    target_user.deactivated_at = datetime.now(
        timezone.utc
    )
    target_user.deactivated_until = (
        datetime.now(timezone.utc)
        + timedelta(hours=24)
    )
    db.flush()

    response = client.patch(
        f"/api/profile/admin/{target_user.id}/activate",
    )

    assert response.status_code == 401

    db.refresh(target_user)

    assert target_user.is_active is False


def test_admin_activate_nonexistent_user_returns_404(
    client: TestClient,
    db: Session,
):
    """
    Activating a nonexistent user returns 404.
    """

    admin = create_admin(
        db,
        user_id=4561,
        username="missingactivationadmin",
        email="missingactivationadmin@example.com",
    )

    response = client.patch(
        "/api/profile/admin/999999/activate",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 404


def test_manual_activation_invalidates_old_jwt(
    client: TestClient,
    db: Session,
):
    """
    Manual activation increments token_version so a JWT issued before
    the suspension/activation cycle cannot be reused.
    """

    admin = create_admin(
        db,
        user_id=4571,
        username="activationtokenadmin",
        email="activationtokenadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4572,
        username="activationtokentarget",
        email="activationtokentarget@example.com",
    )

    old_headers = authenticated_headers(target_user)

    original_token_version = target_user.token_version

    suspend_response = client.patch(
        f"/api/profile/admin/{target_user.id}/deactivate",
        headers=authenticated_headers(admin),
        json={
            "duration_hours": 24,
        },
    )

    assert suspend_response.status_code == 200

    db.refresh(target_user)

    assert target_user.is_active is False
    assert target_user.token_version == (
        original_token_version + 1
    )

    suspended_token_version = target_user.token_version

    activate_response = client.patch(
        f"/api/profile/admin/{target_user.id}/activate",
        headers=authenticated_headers(admin),
    )

    assert activate_response.status_code == 200

    db.refresh(target_user)

    assert target_user.is_active is True
    assert target_user.token_version == (
        suspended_token_version + 1
    )

    response = client.get(
        "/api/profile",
        headers=old_headers,
    )

    assert response.status_code == 401

# ============================================================================
# ADMIN PERMANENT ACCOUNT DELETION
# ============================================================================


def test_admin_can_permanently_delete_user(
    client: TestClient,
    db: Session,
):
    """
    An administrator can permanently delete another user account.
    """

    admin = create_admin(
        db,
        user_id=4601,
        username="permanentdeleteadmin",
        email="permanentdeleteadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4602,
        username="permanentdeletetarget",
        email="permanentdeletetarget@example.com",
    )

    target_user_id = target_user.id

    response = client.delete(
        f"/api/profile/admin/{target_user_id}",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 204
    assert response.content == b""

    db.expire_all()

    assert db.get(User, target_user_id) is None
    assert db.get(User, admin.id) is not None


def test_admin_delete_removes_target_owned_data(
    client: TestClient,
    db: Session,
):
    """
    Administrator deletion reuses the existing account-deletion
    cascades for user-owned data.
    """

    admin = create_admin(
        db,
        user_id=4611,
        username="admindatacleanup",
        email="admindatacleanup@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4612,
        username="admindatacleanuptarget",
        email="admindatacleanuptarget@example.com",
    )

    item = Item(
        user_id=target_user.id,
        title="Admin deletion item",
        description="Item owned by deleted account.",
        type="lost",
        category="Electronics",
        location="Nairobi",
        status="approved",
    )

    db.add(item)
    db.flush()

    claim = Claim(
        item_id=item.id,
        claimant_id=target_user.id,
        reason="I believe this item belongs to me.",
    )

    report = Report(
        item_id=item.id,
        reporter_id=target_user.id,
        reason="Admin deletion test.",
        description="Report owned by deleted account.",
    )

    notification = Notification(
        user_id=target_user.id,
        type="account",
        category="system",
        priority="normal",
        title="Deletion test",
        message="Deletion test notification.",
    )

    comment = Comment(
        item_id=item.id,
        user_id=target_user.id,
        content="Comment owned by deleted account.",
    )

    auth_token = AuthToken(
        user_id=target_user.id,
        token_hash="b" * 64,
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
        reason="Administrator deletion cleanup test.",
    )

    db.add(match)
    db.flush()

    ids = {
        "user": target_user.id,
        "item": item.id,
        "claim": claim.id,
        "report": report.id,
        "notification": notification.id,
        "comment": comment.id,
        "auth_token": auth_token.id,
        "match": match.id,
    }

    response = client.delete(
        f"/api/profile/admin/{target_user.id}",
        headers=authenticated_headers(admin),
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
    assert db.get(User, admin.id) is not None


def test_admin_delete_creates_audit_log_for_deleted_target(
    client: TestClient,
    db: Session,
):
    """
    Administrator deletion creates an audit record identifying the
    acting administrator and the deleted user as the resource.
    """

    admin = create_admin(
        db,
        user_id=4621,
        username="auditdeleteadmin",
        email="auditdeleteadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4622,
        username="auditdeletetarget",
        email="auditdeletetarget@example.com",
    )

    target_user_id = target_user.id

    existing_admin_action_count = count_audit_logs(
        db,
        user_id=admin.id,
    )

    response = client.delete(
        f"/api/profile/admin/{target_user_id}",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 204

    db.expire_all()

    logs = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == admin.id,
            AuditLog.action == "admin_action",
            AuditLog.resource_type == "user",
            AuditLog.resource_id == target_user_id,
        )
        .all()
    )

    assert count_audit_logs(
        db,
        user_id=admin.id,
    ) == existing_admin_action_count + 1

    assert len(logs) == 1

    audit_log = logs[0]

    assert audit_log.user_id == admin.id
    assert audit_log.resource_type == "user"
    assert audit_log.resource_id == target_user_id
    assert audit_log.success is True
    assert "permanently deleted user" in (
        audit_log.details or ""
    )

    assert db.get(User, target_user_id) is None
    assert db.get(User, admin.id) is not None


def test_admin_delete_removes_target_media_after_commit(
    client: TestClient,
    db: Session,
):
    """
    Administrator deletion removes the target's stored media after
    the database transaction commits.
    """

    admin = create_admin(
        db,
        user_id=4631,
        username="medialdeleteadmin",
        email="medialdeleteadmin@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4632,
        username="mediadeletetarget",
        email="mediadeletetarget@example.com",
    )

    storage_key_one = "items/admin-delete-item-one.webp"
    storage_key_two = "items/admin-delete-item-two.webp"

    media_root = Path(settings.MEDIA_ROOT)

    image_path_one = media_root / storage_key_one
    image_path_two = media_root / storage_key_two

    image_path_one.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    image_path_one.write_bytes(b"admin-delete-image-one")
    image_path_two.write_bytes(b"admin-delete-image-two")

    target_user.profile_picture = storage_key_one

    item = Item(
        user_id=target_user.id,
        title="Admin media deletion item",
        description="Item containing stored media.",
        type="found",
        category="Other",
        location="Nairobi",
        image=storage_key_two,
        status="approved",
    )

    db.add(item)
    db.flush()

    target_user_id = target_user.id

    assert image_path_one.exists()
    assert image_path_two.exists()

    response = client.delete(
        f"/api/profile/admin/{target_user_id}",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 204

    assert not image_path_one.exists()
    assert not image_path_two.exists()

    db.expire_all()

    assert db.get(User, target_user_id) is None
    assert db.get(User, admin.id) is not None


def test_admin_cannot_delete_themselves(
    client: TestClient,
    db: Session,
):
    """
    An administrator cannot permanently delete their own account.
    """

    admin = create_admin(
        db,
        user_id=4641,
        username="selfdeleteadmin",
        email="selfdeleteadmin@example.com",
    )

    admin_id = admin.id

    response = client.delete(
        f"/api/profile/admin/{admin_id}",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "An administrator cannot delete their own account."
    )

    db.expire_all()

    assert db.get(User, admin_id) is not None


def test_admin_cannot_delete_last_active_administrator(
    client: TestClient,
    db: Session,
):
    """
    The final active administrator cannot be permanently deleted.
    """

    admin = create_admin(
        db,
        user_id=4651,
        username="lastadmin",
        email="lastadmin@example.com",
    )

    response = client.delete(
        f"/api/profile/admin/{admin.id}",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "An administrator cannot delete their own account."
    )

    db.expire_all()

    assert db.get(User, admin.id) is not None


def test_admin_can_delete_another_administrator_when_multiple_active_admins_exist(
    client: TestClient,
    db: Session,
):
    """
    When multiple active administrators exist, one administrator may
    permanently delete another while preserving the final administrator.
    """

    acting_admin = create_admin(
        db,
        user_id=4661,
        username="actingadmin",
        email="actingadmin@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=4662,
        username="targetadmin",
        email="targetadmin@example.com",
    )

    target_admin_id = target_admin.id

    response = client.delete(
        f"/api/profile/admin/{target_admin_id}",
        headers=authenticated_headers(acting_admin),
    )

    assert response.status_code == 204

    db.expire_all()

    assert db.get(User, target_admin_id) is None

    remaining_admin = db.get(
        User,
        acting_admin.id,
    )

    assert remaining_admin is not None
    assert remaining_admin.role == UserRole.ADMIN
    assert remaining_admin.is_active is True


def test_admin_can_delete_inactive_administrator_when_another_active_admin_exists(
    client: TestClient,
    db: Session,
):
    """
    An inactive administrator may be permanently deleted when another
    active administrator remains.
    """

    acting_admin = create_admin(
        db,
        user_id=4671,
        username="inactiveadminremovalactor",
        email="inactiveadminremovalactor@example.com",
    )

    target_admin = create_admin(
        db,
        user_id=4672,
        username="inactiveadmintarget",
        email="inactiveadmintarget@example.com",
    )

    target_admin.is_active = False
    target_admin.deactivated_at = datetime.now(timezone.utc)
    target_admin.deactivated_until = (
        datetime.now(timezone.utc)
        + timedelta(hours=24)
    )
    target_admin.deactivation_reason = (
        "Inactive administrator deletion test."
    )

    db.flush()

    target_admin_id = target_admin.id

    response = client.delete(
        f"/api/profile/admin/{target_admin_id}",
        headers=authenticated_headers(acting_admin),
    )

    assert response.status_code == 204

    db.expire_all()

    assert db.get(User, target_admin_id) is None

    remaining_admin = db.get(
        User,
        acting_admin.id,
    )

    assert remaining_admin is not None
    assert remaining_admin.role == UserRole.ADMIN
    assert remaining_admin.is_active is True


def test_moderator_cannot_permanently_delete_user(
    client: TestClient,
    db: Session,
):
    """
    Moderators cannot permanently delete user accounts.
    """

    moderator = create_moderator(
        db,
        user_id=4681,
        username="deletepermissionmoderator",
        email="deletepermissionmoderator@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4682,
        username="deletepermissiontarget",
        email="deletepermissiontarget@example.com",
    )

    target_user_id = target_user.id

    response = client.delete(
        f"/api/profile/admin/{target_user_id}",
        headers=authenticated_headers(moderator),
    )

    assert response.status_code == 403

    db.expire_all()

    assert db.get(User, target_user_id) is not None


def test_normal_user_cannot_permanently_delete_user(
    client: TestClient,
    db: Session,
):
    """
    Normal users cannot permanently delete another user's account.
    """

    user = create_test_user(
        db,
        user_id=4691,
        username="deletepermissionuser",
        email="deletepermissionuser@example.com",
    )

    target_user = create_test_user(
        db,
        user_id=4692,
        username="deletepermissionusertarget",
        email="deletepermissionusertarget@example.com",
    )

    target_user_id = target_user.id

    response = client.delete(
        f"/api/profile/admin/{target_user_id}",
        headers=authenticated_headers(user),
    )

    assert response.status_code == 403

    db.expire_all()

    assert db.get(User, target_user_id) is not None


def test_unauthenticated_user_cannot_permanently_delete_user(
    client: TestClient,
    db: Session,
):
    """
    Permanent administrator deletion requires authentication.
    """

    target_user = create_test_user(
        db,
        user_id=4701,
        username="unauthenticateddeletetarget",
        email="unauthenticateddeletetarget@example.com",
    )

    target_user_id = target_user.id

    response = client.delete(
        f"/api/profile/admin/{target_user_id}",
    )

    assert response.status_code == 401

    db.expire_all()

    assert db.get(User, target_user_id) is not None


def test_admin_delete_nonexistent_user_returns_404(
    client: TestClient,
    db: Session,
):
    """
    Permanently deleting a nonexistent user returns 404.
    """

    admin = create_admin(
        db,
        user_id=4711,
        username="missingdeleteadmin",
        email="missingdeleteadmin@example.com",
    )

    response = client.delete(
        "/api/profile/admin/999999",
        headers=authenticated_headers(admin),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."
