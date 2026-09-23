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

    assert data["item"] == {
        "id": item.id,
        "title": "Found Test Phone",
        "type": "found",
        "category": "Electronics",
        "location": "Main Library",
        "image": None,
    }

    assert "description" not in data["item"]


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
# CLAIM CREATION VALIDATION
# ============================================================================


def test_user_cannot_claim_lost_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1023,
        username="apiowner_lost",
    )

    claimant = create_user(
        db,
        user_id=1024,
        username="apiclaimant_lost",
    )

    item = Item(
        user_id=owner.id,
        title="Lost Test Phone",
        description="A lost item cannot receive claims.",
        type="lost",
        category="Electronics",
        location="Main Library",
        status="approved",
    )

    db.add(item)
    db.flush()

    response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I believe this item belongs to me.",
        },
    )

    assert response.status_code == 400

    assert (
        "found items"
        in response.json()["detail"].lower()
    )


def test_user_cannot_claim_pending_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1025,
        username="apiowner_pending",
    )

    claimant = create_user(
        db,
        user_id=1026,
        username="apiclaimant_pending",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="pending",
    )

    response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can provide proof that this is mine.",
        },
    )

    assert response.status_code == 400

    assert (
        "approved"
        in response.json()["detail"].lower()
    )


def test_user_cannot_claim_rejected_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1027,
        username="apiowner_rejected",
    )

    claimant = create_user(
        db,
        user_id=1028,
        username="apiclaimant_rejected",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="rejected",
    )

    response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I have proof that this item belongs to me.",
        },
    )

    assert response.status_code == 400

    assert (
        "approved"
        in response.json()["detail"].lower()
    )


def test_user_cannot_claim_already_claimed_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1029,
        username="apiowner_claimed",
    )

    claimant = create_user(
        db,
        user_id=1030,
        username="apiclaimant_claimed",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="claimed",
    )

    response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can provide evidence of ownership.",
        },
    )

    assert response.status_code == 400

    assert (
        "approved"
        in response.json()["detail"].lower()
    )


def test_cannot_claim_nonexistent_item(
    client,
    db,
):
    claimant = create_user(
        db,
        user_id=1031,
        username="apiclaimant_missing_item",
    )

    response = client.post(
        "/api/claims/items/999999",
        headers=auth_headers(claimant),
        json={
            "reason": "I am trying to claim a nonexistent item.",
        },
    )

    assert response.status_code == 404

    assert (
        response.json()["detail"]
        == "Item not found."
    )


def test_claim_reason_too_short_returns_validation_error(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1032,
        username="apiowner_short_reason",
    )

    claimant = create_user(
        db,
        user_id=1033,
        username="apiclaimant_short_reason",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "Short",
        },
    )

    assert response.status_code == 422


def test_claim_reason_whitespace_is_normalized(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1034,
        username="apiowner_whitespace",
    )

    claimant = create_user(
        db,
        user_id=1035,
        username="apiclaimant_whitespace",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "   I can prove ownership of this item.   ",
        },
    )

    assert response.status_code == 201

    assert (
        response.json()["reason"]
        == "I can prove ownership of this item."
    )


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


def test_moderator_can_approve_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1070,
        username="apimoderator_owner_approve",
    )

    claimant = create_user(
        db,
        user_id=1071,
        username="apimoderator_claimant_approve",
    )

    moderator = create_user(
        db,
        user_id=1072,
        username="apimoderator_approve",
        role="moderator",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claim_response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove ownership of this item.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.patch(
        f"/api/claims/admin/{claim_id}/approve",
        headers=auth_headers(moderator),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "approved"


def test_moderator_can_list_pending_claims(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1073,
        username="apimoderator_owner_list",
    )

    claimant = create_user(
        db,
        user_id=1074,
        username="apimoderator_claimant_list",
    )

    moderator = create_user(
        db,
        user_id=1075,
        username="apimoderator_list",
        role="moderator",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claim_response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove ownership of this item.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.get(
        "/api/claims/admin/pending",
        headers=auth_headers(moderator),
    )

    assert response.status_code == 200

    claim_ids = {
        claim["id"]
        for claim in response.json()
    }

    assert claim_id in claim_ids


def test_moderator_can_reject_pending_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1076,
        username="apimoderator_owner_reject",
    )

    claimant = create_user(
        db,
        user_id=1077,
        username="apimoderator_claimant_reject",
    )

    moderator = create_user(
        db,
        user_id=1078,
        username="apimoderator_reject",
        role="moderator",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claim_response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove ownership of this item.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.patch(
        f"/api/claims/admin/{claim_id}/reject",
        headers=auth_headers(moderator),
        json={
            "rejection_reason": "Insufficient proof of ownership.",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    assert (
        response.json()["rejection_reason"]
        == "Insufficient proof of ownership."
    )


# ============================================================================
# CLAIM RETRIEVAL AUTHORIZATION
# ============================================================================


def test_claimant_can_view_own_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1040,
        username="apiowner_view_own",
    )

    claimant = create_user(
        db,
        user_id=1041,
        username="apiclaimant_view_own",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claim_response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove this item belongs to me.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.get(
        f"/api/claims/{claim_id}",
        headers=auth_headers(claimant),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == claim_id
    assert data["claimant_id"] == claimant.id

    assert data["item"] == {
        "id": item.id,
        "title": "Found Test Phone",
        "type": "found",
        "category": "Electronics",
        "location": "Main Library",
        "image": None,
    }

    assert "description" not in data["item"]


def test_normal_user_cannot_view_another_users_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1042,
        username="apiowner_view_other",
    )

    claimant = create_user(
        db,
        user_id=1043,
        username="apiclaimant_view_other",
    )

    other_user = create_user(
        db,
        user_id=1044,
        username="apiother_view_other",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claim_response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove this item belongs to me.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.get(
        f"/api/claims/{claim_id}",
        headers=auth_headers(other_user),
    )

    assert response.status_code == 403


def test_admin_can_view_any_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1045,
        username="apiowner_admin_view",
    )

    claimant = create_user(
        db,
        user_id=1046,
        username="apiclaimant_admin_view",
    )

    admin = create_user(
        db,
        user_id=1047,
        username="apiadmin_view_claim",
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
            "reason": "I can prove this item belongs to me.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.get(
        f"/api/claims/{claim_id}",
        headers=auth_headers(admin),
    )

    assert response.status_code == 200
    assert response.json()["id"] == claim_id


def test_nonexistent_claim_returns_404(
    client,
    db,
):
    user = create_user(
        db,
        user_id=1048,
        username="apiclaimant_missing_claim",
    )

    response = client.get(
        "/api/claims/999999",
        headers=auth_headers(user),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Claim not found."


# ============================================================================
# MY CLAIMS
# ============================================================================


def test_user_can_list_own_claims(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1049,
        username="apiowner_my_claims",
    )

    claimant = create_user(
        db,
        user_id=1050,
        username="apiclaimant_my_claims",
    )

    item_one = create_item(
        db,
        owner_id=owner.id,
    )

    item_two = create_item(
        db,
        owner_id=owner.id,
    )

    first = client.post(
        f"/api/claims/items/{item_one.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove ownership of this item.",
        },
    )

    second = client.post(
        f"/api/claims/items/{item_two.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can provide proof for this item.",
        },
    )

    assert first.status_code == 201
    assert second.status_code == 201

    response = client.get(
        "/api/claims/me",
        headers=auth_headers(claimant),
    )

    assert response.status_code == 200

    claim_ids = {
        claim["id"]
        for claim in response.json()
    }

    assert first.json()["id"] in claim_ids
    assert second.json()["id"] in claim_ids

    claims = response.json()

    assert all(
        claim["claimant_id"] == claimant.id
        for claim in claims
    )

    claims_by_item_id = {
        claim["item_id"]: claim
        for claim in claims
    }

    assert claims_by_item_id[item_one.id]["item"] == {
        "id": item_one.id,
        "title": "Found Test Phone",
        "type": "found",
        "category": "Electronics",
        "location": "Main Library",
        "image": None,
    }

    assert claims_by_item_id[item_two.id]["item"] == {
        "id": item_two.id,
        "title": "Found Test Phone",
        "type": "found",
        "category": "Electronics",
        "location": "Main Library",
        "image": None,
    }

    assert all(
        "description" not in claim["item"]
        for claim in claims
    )


def test_unauthenticated_user_cannot_list_own_claims(
    client,
    db,
):
    response = client.get(
        "/api/claims/me",
    )

    assert response.status_code == 401


# ============================================================================
# WITHDRAW AUTHORIZATION
# ============================================================================


def test_claimant_can_withdraw_own_pending_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1051,
        username="apiowner_withdraw",
    )

    claimant = create_user(
        db,
        user_id=1052,
        username="apiclaimant_withdraw",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claim_response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove that this item belongs to me.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.post(
        f"/api/claims/{claim_id}/withdraw",
        headers=auth_headers(claimant),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "withdrawn"


def test_another_user_cannot_withdraw_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1053,
        username="apiowner_withdraw_other",
    )

    claimant = create_user(
        db,
        user_id=1054,
        username="apiclaimant_withdraw_other",
    )

    other_user = create_user(
        db,
        user_id=1055,
        username="apiother_withdraw",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claim_response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove that this item belongs to me.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.post(
        f"/api/claims/{claim_id}/withdraw",
        headers=auth_headers(other_user),
    )

    assert response.status_code == 403


def test_nonexistent_claim_cannot_be_withdrawn(
    client,
    db,
):
    claimant = create_user(
        db,
        user_id=1056,
        username="apiwithdraw_missing",
    )

    response = client.post(
        "/api/claims/999999/withdraw",
        headers=auth_headers(claimant),
    )

    assert response.status_code == 404


# ============================================================================
# ADMIN PENDING CLAIMS
# ============================================================================


def test_admin_can_list_pending_claims(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1057,
        username="apiowner_pending_list",
    )

    claimant = create_user(
        db,
        user_id=1058,
        username="apiclaimant_pending_list",
    )

    admin = create_user(
        db,
        user_id=1059,
        username="apiadmin_pending_list",
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
            "reason": "I can prove ownership of this item.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.get(
        "/api/claims/admin/pending",
        headers=auth_headers(admin),
    )

    assert response.status_code == 200

    claim_ids = {
        claim["id"]
        for claim in response.json()
    }

    assert claim_id in claim_ids


def test_normal_user_cannot_list_pending_claims(
    client,
    db,
):
    user = create_user(
        db,
        user_id=1060,
        username="apinormal_pending_list",
    )

    response = client.get(
        "/api/claims/admin/pending",
        headers=auth_headers(user),
    )

    assert response.status_code == 403


def test_unauthenticated_user_cannot_list_pending_claims(
    client,
    db,
):
    response = client.get(
        "/api/claims/admin/pending",
    )

    assert response.status_code == 401


# ============================================================================
# ADMIN REJECTION
# ============================================================================


def test_admin_can_reject_pending_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1061,
        username="apiowner_reject",
    )

    claimant = create_user(
        db,
        user_id=1062,
        username="apiclaimant_reject",
    )

    admin = create_user(
        db,
        user_id=1063,
        username="apiadmin_reject",
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
            "reason": "I can prove ownership of this item.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.patch(
        f"/api/claims/admin/{claim_id}/reject",
        headers=auth_headers(admin),
        json={
            "rejection_reason": "Insufficient proof of ownership.",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    assert (
        response.json()["rejection_reason"]
        == "Insufficient proof of ownership."
    )


def test_normal_user_cannot_reject_claim(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1064,
        username="apiowner_normal_reject",
    )

    claimant = create_user(
        db,
        user_id=1065,
        username="apiclaimant_normal_reject",
    )

    normal_user = create_user(
        db,
        user_id=1066,
        username="apinormal_reject",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    claim_response = client.post(
        f"/api/claims/items/{item.id}",
        headers=auth_headers(claimant),
        json={
            "reason": "I can prove ownership of this item.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.patch(
        f"/api/claims/admin/{claim_id}/reject",
        headers=auth_headers(normal_user),
        json={
            "rejection_reason": "Insufficient proof.",
        },
    )

    assert response.status_code == 403


def test_rejection_requires_a_reason_at_api_level(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=1067,
        username="apiowner_reject_validation",
    )

    claimant = create_user(
        db,
        user_id=1068,
        username="apiclaimant_reject_validation",
    )

    admin = create_user(
        db,
        user_id=1069,
        username="apiadmin_reject_validation",
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
            "reason": "I can prove ownership of this item.",
        },
    )

    assert claim_response.status_code == 201

    claim_id = claim_response.json()["id"]

    response = client.patch(
        f"/api/claims/admin/{claim_id}/reject",
        headers=auth_headers(admin),
        json={
            "rejection_reason": "No",
        },
    )

    assert response.status_code == 422