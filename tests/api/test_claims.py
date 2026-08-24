"""
TRACKIT Claim API Integration Tests.

Tests the HTTP/API layer for:
- authentication
- claim creation
- duplicate active claims
- multiple claimants
- rejection and re-claiming
- approval
- item status transition
- authorization
- one approved claim per item
"""

from app.core.security import create_access_token
from app.models.item import Item
from app.models.user import User


# ============================================================================
# HELPERS
# ============================================================================


def create_user(
    db,
    *,
    user_id: int,
    username: str,
    role: str = "user",
):
    user = User(
        id=user_id,
        username=username,
        first_name="Test",
        last_name="User",
        email=f"{username}@trackit.test",
        password_hash="test-password-hash",
        role=role,
        is_active=True,
        is_verified=True,
        token_version=0,
    )

    db.add(user)
    db.flush()

    return user


def create_item(
    db,
    *,
    owner_id: int,
    status: str = "approved",
):
    item = Item(
        user_id=owner_id,
        title="Found Test Phone",
        description="API integration test item.",
        type="found",
        category="Electronics",
        location="Main Library",
        status=status,
    )

    db.add(item)
    db.flush()

    return item


def auth_headers(user):
    """
    Generate a real TRACKIT access token using
    the same JWT structure as the production login flow.
    """

    token = create_access_token(
        data={
            "sub": str(user.id),
            "role": user.role,
            "token_version": user.token_version,
        }
    )

    return {
        "Authorization": f"Bearer {token}",
    }


# ============================================================================
# CLAIM CREATION
# ============================================================================


def test_unauthenticated_user_cannot_create_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1001,
        username="apiowner1",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/claims/items/{item.id}",
        json={
            "reason": "This item belongs to me.",
        },
    )

    assert response.status_code == 401


def test_verified_user_can_create_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1002,
        username="apiowner2",
    )

    claimant = create_user(
        db,
        user_id=1003,
        username="apiclaimant1",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove this phone belongs to me.",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["item_id"] == item.id
    assert data["claimant_id"] == claimant.id
    assert data["status"] == "pending"


def test_user_cannot_claim_own_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1004,
        username="apiowner3",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(owner),
        json={
            "reason": "Trying to claim my own item.",
        },
    )

    assert response.status_code == 403


# ============================================================================
# DUPLICATE CLAIMS
# ============================================================================


def test_same_user_cannot_have_two_active_claims(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1005,
        username="apiowner4",
    )

    claimant = create_user(
        db,
        user_id=1006,
        username="apiclaimant2",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    headers = auth_headers(claimant)

    first = client.post(
        f"/api/claims/items/{item.id}",
        headers=headers,
        json={
            "reason": "First claim.",
        },
    )

    assert first.status_code == 201

    second = client.post(
        f"/api/claims/items/{item.id}",
        headers=headers,
        json={
            "reason": "Second claim.",
        },
    )

    assert second.status_code == 400
    assert "active claim" in second.json()["detail"].lower()


def test_multiple_users_can_claim_same_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1007,
        username="apiowner5",
    )

    claimant_one = create_user(
        db,
        user_id=1008,
        username="apiclaimant3",
    )

    claimant_two = create_user(
        db,
        user_id=1009,
        username="apiclaimant4",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response_one = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant_one),
        json={
            "reason": "I have proof of ownership.",
        },
    )

    response_two = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant_two),
        json={
            "reason": "I can identify the item.",
        },
    )

    assert response_one.status_code == 201
    assert response_two.status_code == 201

    assert (
        response_one.json()["claimant_id"]
        != response_two.json()["claimant_id"]
    )


# ============================================================================
# REJECTION → NEW CLAIM
# ============================================================================


def test_rejected_claim_can_be_replaced_by_new_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1010,
        username="apiowner6",
    )

    claimant = create_user(
        db,
        user_id=1011,
        username="apiclaimant5",
    )

    admin = create_user(
        db,
        user_id=1012,
        username="apiadmin1",
        role="admin",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claimant_headers = auth_headers(claimant)

    first = client.post(
        f"/api/claims/items/{item.id}",
        headers=claimant_headers,
        json={
            "reason": "First ownership explanation.",
        },
    )

    assert first.status_code == 201

    first_claim_id = first.json()["id"]

    rejected = client.patch(
        f"/api/claims/admin/{first_claim_id}/reject",
        headers=auth_headers(admin),
        json={
            "rejection_reason": "Insufficient proof.",
        },
    )

    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"

    second = client.post(
        f"/api/claims/items/{item.id}",
        headers=claimant_headers,
        json={
            "reason": "I now have stronger proof of ownership.",
        },
    )

    assert second.status_code == 201

    second_data = second.json()

    assert second_data["id"] != first_claim_id
    assert second_data["status"] == "pending"


# ============================================================================
# APPROVAL → ITEM CLAIMED
# ============================================================================


def test_approving_claim_marks_item_claimed(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1013,
        username="apiowner7",
    )

    claimant = create_user(
        db,
        user_id=1014,
        username="apiclaimant6",
    )

    admin = create_user(
        db,
        user_id=1015,
        username="apiadmin2",
        role="admin",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claim_response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove ownership.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    approval_response = client.patch(
        f"/api/claims/admin/{claim_id}/approve",
        headers=auth_headers(admin),
    )

    assert approval_response.status_code == 200

    approval_data = approval_response.json()

    assert approval_data["status"] == "approved"

    db.refresh(item)

    assert item.status == "claimed"


# ============================================================================
# ONE APPROVED CLAIM PER ITEM
# ============================================================================


def test_second_claim_cannot_be_approved_after_item_is_claimed(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1016,
        username="apiowner8",
    )

    claimant_one = create_user(
        db,
        user_id=1017,
        username="apiclaimant7",
    )

    claimant_two = create_user(
        db,
        user_id=1018,
        username="apiclaimant8",
    )

    admin = create_user(
        db,
        user_id=1019,
        username="apiadmin3",
        role="admin",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    first = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant_one),
        json={
            "reason": "First claimant proof.",
        },
    )

    second = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant_two),
        json={
            "reason": "Second claimant proof.",
        },
    )

    assert first.status_code == 201
    assert second.status_code == 201

    first_claim_id = first.json()["id"]
    second_claim_id = second.json()["id"]

    approved = client.patch(
        f"/api/claims/admin/{first_claim_id}/approve",
        headers=auth_headers(admin),
    )

    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    second_approval = client.patch(
        f"/api/claims/admin/{second_claim_id}/approve",
        headers=auth_headers(admin),
    )

    assert second_approval.status_code == 400

    assert (
        "already has an approved claim"
        in second_approval.json()["detail"].lower()
    )


# ============================================================================
# ADMIN AUTHORIZATION
# ============================================================================


def test_normal_user_cannot_approve_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1020,
        username="apiowner9",
    )

    claimant = create_user(
        db,
        user_id=1021,
        username="apiclaimant9",
    )

    normal_user = create_user(
        db,
        user_id=1022,
        username="apinormaluser",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claim_response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "This belongs to me.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.patch(
        f"/api/claims/admin/{claim_id}/approve",
        headers=auth_headers(normal_user),
    )

    assert response.status_code == 403