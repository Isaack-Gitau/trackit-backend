"""
TRACKIT Item API Tests.

Tests HTTP-level security, authorization, public visibility,
and secure image-upload behavior for item endpoints.

Coverage:

- Public visibility of approved and claimed items.
- Public hiding of pending and rejected items.
- Public filtering cannot expose hidden statuses.
- Public pagination uses the secure visibility boundary.
- Authentication requirements for item management.
- Authenticated owner access.
- Protection against modifying another user's item.
- Protection against deleting another user's item.
- Protection against user_id spoofing.
- Administrator moderation access.
- Secure image upload behavior.
- Image content validation.
- Image size and dimension limits.
- Server-generated image storage keys.
- Client filenames cannot control storage paths.
"""

from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy.orm import Session

from app.utils.images import sanitize_and_store_image
from app.core.config import settings
from app.core.security import create_access_token
from app.models.item import Item
from app.models.user import User
from datetime import datetime, timezone

# ============================================================================
# TEST HELPERS
# ============================================================================


def create_test_user(
    db: Session,
    user_id: int,
    username: str,
    email: str,
    first_name: str = "Test",
    last_name: str = "User",
    role: str = "user",
    is_verified: bool = True,
):
    user = User(
        id=user_id,
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password_hash="test-password-hash",
        role=role,
        is_active=True,
        is_verified=is_verified,
    )

    db.add(user)
    db.flush()

    return user


def authenticated_headers(user: User) -> dict[str, str]:
    """
    Generate Authorization headers using the same JWT structure
    expected by the production authentication dependencies.
    """

    token = create_access_token(
        data={
            "sub": str(user.id),
            "role": user.role,
            "token_version": user.token_version,
        },
    )

    return {
        "Authorization": f"Bearer {token}",
    }


def create_test_item(
    db: Session,
    item_id: int,
    user_id: int,
    title: str = "Lost Phone",
    description: str = "A black smartphone lost near the main gate.",
    item_type: str = "lost",
    category: str = "electronics",
    location: str = "Main Gate",
    item_status: str = "approved",
    image: str | None = None,
):
    item = Item(
        id=item_id,
        user_id=user_id,
        title=title,
        description=description,
        type=item_type,
        category=category,
        location=location,
        image=image,
        status=item_status,
    )

    db.add(item)
    db.flush()

    return item


def make_image_bytes(
    image_format: str = "JPEG",
    width: int = 100,
    height: int = 100,
) -> bytes:
    image = Image.new("RGB", (width, height), color="red")

    buffer = BytesIO()
    image.save(buffer, format=image_format)

    return buffer.getvalue()


def make_png_with_transparency(
    width: int = 100,
    height: int = 100,
) -> bytes:
    image = Image.new("RGBA", (width, height), color=(255, 0, 0, 128))

    buffer = BytesIO()
    image.save(buffer, format="PNG")

    return buffer.getvalue()


def make_oversized_image_bytes() -> bytes:
    """
    Create an image payload whose encoded byte size exceeds the
    configured upload limit.

    The implementation deliberately creates incompressible-ish
    image data rather than relying on a fake Content-Length header.
    """

    width = 3000
    height = 3000

    image = Image.effect_noise((width, height), 100)

    buffer = BytesIO()
    image.save(
        buffer,
        format="PNG",
        compress_level=0,
    )

    return buffer.getvalue()


def create_multipart_item(
    client: TestClient,
    user: User,
    *,
    title: str = "Lost Phone",
    description: str = "A black smartphone lost near the main gate.",
    item_type: str = "lost",
    category: str = "electronics",
    location: str = "Main Gate",
    image_bytes: bytes | None = None,
    filename: str = "photo.jpg",
    content_type: str = "image/jpeg",
):
    files = None

    if image_bytes is not None:
        files = {
            "image": (
                filename,
                image_bytes,
                content_type,
            )
        }

    data = {
        "title": title,
        "description": description,
        "type": item_type,
        "category": category,
        "location": location,
    }

    return client.post(
        "/api/items",
        headers=authenticated_headers(user),
        data=data,
        files=files,
    )


# ============================================================================
# PUBLIC VISIBILITY
# ============================================================================


def test_public_get_approved_item(
    client: TestClient,
    db: Session,
):
    """
    Approved items are publicly accessible.
    """

    user = create_test_user(
        db,
        user_id=2001,
        username="publicapproved",
        email="publicapproved@example.com",
    )

    item = create_test_item(
        db,
        item_id=3001,
        user_id=user.id,
        item_status="approved",
    )

    response = client.get(
        f"/api/items/{item.id}",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == item.id
    assert data["status"] == "approved"


def test_public_get_claimed_item(
    client: TestClient,
    db: Session,
):
    """
    Claimed items remain publicly visible.
    """

    user = create_test_user(
        db,
        user_id=2002,
        username="publicclaimed",
        email="publicclaimed@example.com",
    )

    item = create_test_item(
        db,
        item_id=3002,
        user_id=user.id,
        item_status="claimed",
    )

    response = client.get(
        f"/api/items/{item.id}",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == item.id
    assert data["status"] == "claimed"


def test_public_get_pending_item_is_hidden(
    client: TestClient,
    db: Session,
):
    """
    Pending items must not be publicly accessible.
    """

    user = create_test_user(
        db,
        user_id=2003,
        username="publicpending",
        email="publicpending@example.com",
    )

    item = create_test_item(
        db,
        item_id=3003,
        user_id=user.id,
        item_status="pending",
    )

    response = client.get(
        f"/api/items/{item.id}",
    )

    assert response.status_code == 404


def test_public_get_rejected_item_is_hidden(
    client: TestClient,
    db: Session,
):
    """
    Rejected items must not be publicly accessible.
    """

    user = create_test_user(
        db,
        user_id=2004,
        username="publicrejected",
        email="publicrejected@example.com",
    )

    item = create_test_item(
        db,
        item_id=3004,
        user_id=user.id,
        item_status="rejected",
    )

    response = client.get(
        f"/api/items/{item.id}",
    )

    assert response.status_code == 404


def test_public_get_nonexistent_item_returns_404(
    client: TestClient,
):
    """
    A nonexistent item must return 404.
    """

    response = client.get(
        "/api/items/99999999",
    )

    assert response.status_code == 404


# ============================================================================
# PUBLIC LISTING
# ============================================================================


def test_public_list_returns_only_visible_items(
    client: TestClient,
    db: Session,
):
    """
    Public listing exposes approved and claimed items only.
    """

    user = create_test_user(
        db,
        user_id=2010,
        username="publiclist",
        email="publiclist@example.com",
    )

    approved = create_test_item(
        db,
        item_id=3010,
        user_id=user.id,
        item_status="approved",
    )

    claimed = create_test_item(
        db,
        item_id=3011,
        user_id=user.id,
        item_status="claimed",
    )

    pending = create_test_item(
        db,
        item_id=3012,
        user_id=user.id,
        item_status="pending",
    )

    rejected = create_test_item(
        db,
        item_id=3013,
        user_id=user.id,
        item_status="rejected",
    )

    response = client.get(
        "/api/items",
    )

    assert response.status_code == 200

    data = response.json()
    returned_ids = {item["id"] for item in data}

    assert approved.id in returned_ids
    assert claimed.id in returned_ids
    assert pending.id not in returned_ids
    assert rejected.id not in returned_ids

    assert all(
        item["status"] in {"approved", "claimed"}
        for item in data
    )


def test_public_list_cannot_be_bypassed_with_pending_status(
    client: TestClient,
    db: Session,
):
    """
    Supplying status=pending must not expose pending items.
    """

    user = create_test_user(
        db,
        user_id=2014,
        username="pendingbypass",
        email="pendingbypass@example.com",
    )

    pending = create_test_item(
        db,
        item_id=3014,
        user_id=user.id,
        item_status="pending",
    )

    response = client.get(
        "/api/items?status=pending",
    )

    assert response.status_code == 200

    data = response.json()
    returned_ids = {item["id"] for item in data}

    assert pending.id not in returned_ids

    assert all(
        item["status"] in {"approved", "claimed"}
        for item in data
    )


def test_public_list_cannot_be_bypassed_with_rejected_status(
    client: TestClient,
    db: Session,
):
    """
    Supplying status=rejected must not expose rejected items.
    """

    user = create_test_user(
        db,
        user_id=2015,
        username="rejectedbypass",
        email="rejectedbypass@example.com",
    )

    rejected = create_test_item(
        db,
        item_id=3015,
        user_id=user.id,
        item_status="rejected",
    )

    response = client.get(
        "/api/items?status=rejected",
    )

    assert response.status_code == 200

    data = response.json()
    returned_ids = {item["id"] for item in data}

    assert rejected.id not in returned_ids

    assert all(
        item["status"] in {"approved", "claimed"}
        for item in data
    )


def test_public_list_combines_approved_and_claimed_with_database_pagination(
    client: TestClient,
    db: Session,
):
    """
    Public pagination operates over the combined visible dataset.
    """

    user = create_test_user(
        db,
        user_id=2016,
        username="paginationuser",
        email="paginationuser@example.com",
    )

    statuses = [
        "approved",
        "claimed",
        "approved",
        "claimed",
        "approved",
        "claimed",
    ]

    for offset, item_status in enumerate(statuses):
        create_test_item(
            db,
            item_id=3016 + offset,
            user_id=user.id,
            item_status=item_status,
        )

    first_page = client.get(
        "/api/items?page=1&limit=3",
    )

    second_page = client.get(
        "/api/items?page=2&limit=3",
    )

    assert first_page.status_code == 200
    assert second_page.status_code == 200

    first_data = first_page.json()
    second_data = second_page.json()

    assert len(first_data) == 3
    assert len(second_data) == 3

    first_ids = {item["id"] for item in first_data}
    second_ids = {item["id"] for item in second_data}

    assert first_ids.isdisjoint(second_ids)

    assert all(
        item["status"] in {"approved", "claimed"}
        for item in first_data + second_data
    )


# ============================================================================
# AUTHENTICATION
# ============================================================================


def test_create_item_requires_authentication(
    client: TestClient,
):
    """
    Item creation requires authentication.
    """

    response = client.post(
        "/api/items",
        json={
            "title": "Lost Wallet",
            "description": "A brown wallet lost near the parking area.",
            "type": "lost",
            "category": "wallet",
            "location": "Parking Area",
        },
    )

    assert response.status_code == 401


def test_update_item_requires_authentication(
    client: TestClient,
):
    """
    Item updates require authentication.
    """

    response = client.patch(
        "/api/items/3000",
        json={
            "title": "Updated Item",
        },
    )

    assert response.status_code == 401


def test_delete_item_requires_authentication(
    client: TestClient,
):
    """
    Item deletion requires authentication.
    """

    response = client.delete(
        "/api/items/3000",
    )

    assert response.status_code == 401


# ============================================================================
# OWNERSHIP
# ============================================================================


def test_owner_can_update_own_item(
    client: TestClient,
    db: Session,
):
    """
    An authenticated owner can update their own item.
    """

    owner = create_test_user(
        db,
        user_id=2020,
        username="itemowner",
        email="itemowner@example.com",
    )

    item = create_test_item(
        db,
        item_id=3020,
        user_id=owner.id,
    )

    response = client.patch(
        f"/api/items/{item.id}",
        headers=authenticated_headers(owner),
        json={
            "title": "Updated Phone",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == item.id
    assert data["title"] == "Updated Phone"


def test_non_owner_cannot_update_item(
    client: TestClient,
    db: Session,
):
    """
    An authenticated user cannot update another user's item.
    """

    owner = create_test_user(
        db,
        user_id=2021,
        username="realowner",
        email="realowner@example.com",
    )

    other_user = create_test_user(
        db,
        user_id=2022,
        username="otheruser",
        email="otheruser@example.com",
    )

    item = create_test_item(
        db,
        item_id=3021,
        user_id=owner.id,
    )

    response = client.patch(
        f"/api/items/{item.id}",
        headers=authenticated_headers(other_user),
        json={
            "title": "Unauthorized Update",
        },
    )

    assert response.status_code == 403


def test_owner_can_delete_own_item(
    client: TestClient,
    db: Session,
):
    """
    An authenticated owner can delete their own item.
    """

    owner = create_test_user(
        db,
        user_id=2023,
        username="deleteowner",
        email="deleteowner@example.com",
    )

    item = create_test_item(
        db,
        item_id=3023,
        user_id=owner.id,
    )

    response = client.delete(
        f"/api/items/{item.id}",
        headers=authenticated_headers(owner),
    )

    assert response.status_code == 204


# ============================================================================
# ITEM LIFECYCLE
# ============================================================================

def test_approved_item_is_resubmitted_when_image_is_replaced(
    client: TestClient,
    db: Session,
):
    """
    Replacing an approved item's image is a substantive change and
    sends the item back to pending moderation.
    """

    owner = create_test_user(
        db,
        user_id=2058,
        username="imagechangeowner",
        email="imagechangeowner@example.com",
    )

    admin = create_test_user(
        db,
        user_id=2059,
        username="imagechangeadmin",
        email="imagechangeadmin@example.com",
        role="admin",
    )

    original_image = make_image_bytes(
        image_format="JPEG",
        width=100,
        height=100,
    )

    replacement_image = make_image_bytes(
        image_format="PNG",
        width=200,
        height=200,
    )

    item = create_test_item(
        db,
        item_id=3058,
        user_id=owner.id,
        item_status="approved",
    )

    original_storage_key = sanitize_and_store_image(
        BytesIO(original_image),
    )

    item.image = original_storage_key
    item.reviewed_by = admin.id
    item.reviewed_at = datetime.now(timezone.utc)
    db.flush()

    response = client.patch(
        f"/api/items/{item.id}",
        headers=authenticated_headers(owner),
        data={
            "title": item.title,
        },
        files={
            "image": (
                "replacement.png",
                replacement_image,
                "image/png",
            ),
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "pending"
    assert data["image"] is not None
    assert data["image"] != original_storage_key

    db.refresh(item)

    assert item.status == "pending"
    assert item.image is not None
    assert item.image != original_storage_key
    assert item.rejection_reason is None
    assert item.reviewed_by is None
    assert item.reviewed_at is None

def test_pending_item_stays_pending_after_substantive_update(
    client: TestClient,
    db: Session,
):
    """
    A substantive update to a pending item does not bypass moderation.
    """

    owner = create_test_user(
        db,
        user_id=2050,
        username="pendingowner",
        email="pendingowner@example.com",
    )

    item = create_test_item(
        db,
        item_id=3050,
        user_id=owner.id,
        item_status="pending",
    )

    response = client.patch(
        f"/api/items/{item.id}",
        headers=authenticated_headers(owner),
        json={
            "title": "Updated Pending Phone",
            "description": "Updated description for moderation.",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["title"] == "Updated Pending Phone"
    assert data["status"] == "pending"

    db.refresh(item)

    assert item.status == "pending"


def test_rejected_item_is_resubmitted_after_substantive_update(
    client: TestClient,
    db: Session,
):
    """
    A substantive update to a rejected item automatically resubmits it.
    """

    owner = create_test_user(
        db,
        user_id=2051,
        username="rejectedowner",
        email="rejectedowner@example.com",
    )

    admin = create_test_user(
        db,
        user_id=2052,
        username="rejectedadmin",
        email="rejectedadmin@example.com",
        role="admin",
    )

    item = create_test_item(
        db,
        item_id=3051,
        user_id=owner.id,
        item_status="rejected",
    )

    item.rejection_reason = "The item description needs more detail."
    item.reviewed_by = admin.id
    item.reviewed_at = datetime.now(timezone.utc)
    db.flush()

    response = client.patch(
        f"/api/items/{item.id}",
        headers=authenticated_headers(owner),
        json={
            "description": "Updated description with the requested details.",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "pending"
    assert data["description"] == (
        "Updated description with the requested details."
    )

    db.refresh(item)

    assert item.status == "pending"
    assert item.rejection_reason is None
    assert item.reviewed_by is None
    assert item.reviewed_at is None


def test_approved_item_is_resubmitted_after_substantive_update(
    client: TestClient,
    db: Session,
):
    """
    A substantive update to an approved item invalidates its approval
    and sends it back through moderation.
    """

    owner = create_test_user(
        db,
        user_id=2053,
        username="approvedowner",
        email="approvedowner@example.com",
    )

    admin = create_test_user(
        db,
        user_id=2054,
        username="approvedadmin",
        email="approvedadmin@example.com",
        role="admin",
    )

    item = create_test_item(
        db,
        item_id=3053,
        user_id=owner.id,
        item_status="approved",
    )

    item.reviewed_by = admin.id
    item.reviewed_at = datetime.now(timezone.utc)
    db.flush()

    response = client.patch(
        f"/api/items/{item.id}",
        headers=authenticated_headers(owner),
        json={
            "title": "Changed Approved Phone",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "pending"
    assert data["title"] == "Changed Approved Phone"

    db.refresh(item)

    assert item.status == "pending"
    assert item.rejection_reason is None
    assert item.reviewed_by is None
    assert item.reviewed_at is None


def test_approved_item_stays_approved_when_update_changes_nothing(
    client: TestClient,
    db: Session,
):
    """
    Sending the same substantive values does not unnecessarily invalidate
    an existing approval.
    """

    owner = create_test_user(
        db,
        user_id=2055,
        username="noopowner",
        email="noopowner@example.com",
    )

    admin = create_test_user(
        db,
        user_id=2056,
        username="noopadmin",
        email="noopadmin@example.com",
        role="admin",
    )

    item = create_test_item(
        db,
        item_id=3055,
        user_id=owner.id,
        item_status="approved",
    )

    item.reviewed_by = admin.id
    item.reviewed_at = datetime.now(timezone.utc)
    db.flush()

    response = client.patch(
        f"/api/items/{item.id}",
        headers=authenticated_headers(owner),
        json={
            "title": item.title,
            "description": item.description,
            "type": item.type,
            "category": item.category,
            "location": item.location,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "approved"

    db.refresh(item)

    assert item.status == "approved"
    assert item.reviewed_by == admin.id
    assert item.reviewed_at is not None


def test_owner_cannot_modify_claimed_item(
    client: TestClient,
    db: Session,
):
    """
    Once an item is claimed, its owner cannot modify it.
    """

    owner = create_test_user(
        db,
        user_id=2057,
        username="claimedowner",
        email="claimedowner@example.com",
    )

    item = create_test_item(
        db,
        item_id=3057,
        user_id=owner.id,
        item_status="claimed",
    )

    response = client.patch(
        f"/api/items/{item.id}",
        headers=authenticated_headers(owner),
        json={
            "title": "Attempted Claimed Update",
        },
    )

    assert response.status_code == 403

    db.refresh(item)

    assert item.status == "claimed"
    assert item.title == "Lost Phone"


def test_non_owner_cannot_delete_item(
    client: TestClient,
    db: Session,
):
    """
    An authenticated user cannot delete another user's item.
    """

    owner = create_test_user(
        db,
        user_id=2024,
        username="deleteowner2",
        email="deleteowner2@example.com",
    )

    other_user = create_test_user(
        db,
        user_id=2025,
        username="deleteother",
        email="deleteother@example.com",
    )

    item = create_test_item(
        db,
        item_id=3024,
        user_id=owner.id,
    )

    response = client.delete(
        f"/api/items/{item.id}",
        headers=authenticated_headers(other_user),
    )

    assert response.status_code == 403

    db.refresh(item)

    assert item.user_id == owner.id


def test_owner_cannot_delete_claimed_item(
    client: TestClient,
    db: Session,
):
    """
    Once an item is claimed, its owner cannot delete it.
    """

    owner = create_test_user(
        db,
        user_id=2026,
        username="claimeddeleteowner",
        email="claimeddeleteowner@example.com",
    )

    item = create_test_item(
        db,
        item_id=3026,
        user_id=owner.id,
        item_status="claimed",
    )

    response = client.delete(
        f"/api/items/{item.id}",
        headers=authenticated_headers(owner),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Claimed items cannot be deleted."

    db.refresh(item)

    assert item.user_id == owner.id
    assert item.status == "claimed"


# ============================================================================
# IDENTITY SPOOFING
# ============================================================================


def test_create_item_ignores_client_user_id(
    client: TestClient,
    db: Session,
):
    """
    A client cannot create an item belonging to another user.

    user_id is not part of ItemCreate, so sending it must not
    override the authenticated identity.
    """

    user = create_test_user(
        db,
        user_id=2030,
        username="spoofuser",
        email="spoofuser@example.com",
    )

    response = client.post(
        "/api/items",
        headers=authenticated_headers(user),
        json={
            "title": "Lost Wallet",
            "description": "A brown wallet lost near the parking area.",
            "type": "lost",
            "category": "wallet",
            "location": "Parking Area",
            "user_id": 9999,
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["user_id"] == user.id
    assert data["user_id"] != 9999


# ============================================================================
# ADMIN MODERATION
# ============================================================================


def test_admin_can_approve_pending_item(
    client: TestClient,
    db: Session,
):
    """
    Administrators can access pending items through the internal
    moderation endpoint even though pending items are hidden
    from public GET endpoints.
    """

    owner = create_test_user(
        db,
        user_id=2040,
        username="moderationowner",
        email="moderationowner@example.com",
    )

    admin = create_test_user(
        db,
        user_id=2041,
        username="itemadmin",
        email="itemadmin@example.com",
        role="admin",
    )

    item = create_test_item(
        db,
        item_id=3040,
        user_id=owner.id,
        item_status="pending",
    )

    public_response = client.get(
        f"/api/items/{item.id}",
    )

    assert public_response.status_code == 404

    moderation_response = client.patch(
        f"/api/items/{item.id}/approve",
        headers=authenticated_headers(admin),
    )

    assert moderation_response.status_code == 200

    data = moderation_response.json()

    assert data["id"] == item.id
    assert data["status"] == "approved"


def test_non_admin_cannot_approve_item(
    client: TestClient,
    db: Session,
):
    """
    Ordinary users cannot access the item approval endpoint.
    """

    owner = create_test_user(
        db,
        user_id=2042,
        username="moderationowner2",
        email="moderationowner2@example.com",
    )

    user = create_test_user(
        db,
        user_id=2043,
        username="ordinaryuser",
        email="ordinaryuser@example.com",
    )

    item = create_test_item(
        db,
        item_id=3042,
        user_id=owner.id,
        item_status="pending",
    )

    response = client.patch(
        f"/api/items/{item.id}/approve",
        headers=authenticated_headers(user),
    )

    assert response.status_code == 403

    db.refresh(item)

    assert item.status == "pending"


# ============================================================================
# IMAGE UPLOAD SECURITY
# ============================================================================


def test_image_upload_requires_authentication(
    client: TestClient,
):
    """
    An unauthenticated client cannot upload an item image.
    """

    response = client.post(
        "/api/items",
        data={
            "title": "Lost Phone",
            "description": "A black smartphone lost near the main gate.",
            "type": "lost",
            "category": "electronics",
            "location": "Main Gate",
        },
        files={
            "image": (
                "photo.jpg",
                make_image_bytes("JPEG"),
                "image/jpeg",
            )
        },
    )

    assert response.status_code == 401


def test_verified_user_can_upload_jpeg(
    client: TestClient,
    db: Session,
    tmp_path: Path,
):
    """
    A verified authenticated user can upload a valid JPEG image.
    """

    original_media_root = settings.MEDIA_ROOT
    settings.MEDIA_ROOT = str(tmp_path / "media")

    try:
        user = create_test_user(
            db,
            user_id=2050,
            username="jpeguser",
            email="jpeguser@example.com",
        )

        image_bytes = make_image_bytes("JPEG")

        response = create_multipart_item(
            client,
            user,
            image_bytes=image_bytes,
            filename="my-photo.jpg",
            content_type="image/jpeg",
        )

        assert response.status_code == 201

        data = response.json()

        assert data["image"] is not None
        assert data["image"] != "my-photo.jpg"

        stored_key = data["image"]

        assert not Path(stored_key).is_absolute()
        assert ".." not in Path(stored_key).parts

        stored_path = Path(settings.MEDIA_ROOT) / stored_key

        assert stored_path.exists()
        assert stored_path.is_file()

    finally:
        settings.MEDIA_ROOT = original_media_root


def test_verified_user_can_upload_png(
    client: TestClient,
    db: Session,
    tmp_path: Path,
):
    """
    A verified authenticated user can upload a valid PNG image.
    """

    original_media_root = settings.MEDIA_ROOT
    settings.MEDIA_ROOT = str(tmp_path / "media")

    try:
        user = create_test_user(
            db,
            user_id=2051,
            username="pnguser",
            email="pnguser@example.com",
        )

        image_bytes = make_image_bytes("PNG")

        response = create_multipart_item(
            client,
            user,
            image_bytes=image_bytes,
            filename="picture.png",
            content_type="image/png",
        )

        assert response.status_code == 201

        data = response.json()

        assert data["image"] is not None

        stored_path = Path(settings.MEDIA_ROOT) / data["image"]

        assert stored_path.exists()
        assert stored_path.is_file()

    finally:
        settings.MEDIA_ROOT = original_media_root


def test_verified_user_can_upload_webp(
    client: TestClient,
    db: Session,
    tmp_path: Path,
):
    """
    A verified authenticated user can upload a valid WebP image.
    """

    original_media_root = settings.MEDIA_ROOT
    settings.MEDIA_ROOT = str(tmp_path / "media")

    try:
        user = create_test_user(
            db,
            user_id=2052,
            username="webpuser",
            email="webpuser@example.com",
        )

        image_bytes = make_image_bytes("WEBP")

        response = create_multipart_item(
            client,
            user,
            image_bytes=image_bytes,
            filename="picture.webp",
            content_type="image/webp",
        )

        assert response.status_code == 201

        data = response.json()

        assert data["image"] is not None

        stored_path = Path(settings.MEDIA_ROOT) / data["image"]

        assert stored_path.exists()
        assert stored_path.is_file()

    finally:
        settings.MEDIA_ROOT = original_media_root


def test_fake_mime_type_does_not_bypass_image_validation(
    client: TestClient,
    db: Session,
):
    """
    A non-image payload cannot become valid merely by claiming
    an image MIME type.
    """

    user = create_test_user(
        db,
        user_id=2053,
        username="fakemime",
        email="fakemime@example.com",
    )

    response = create_multipart_item(
        client,
        user,
        image_bytes=b"This is not an image.",
        filename="fake.jpg",
        content_type="image/jpeg",
    )

    assert response.status_code in {400, 422}


def test_svg_upload_is_rejected(
    client: TestClient,
    db: Session,
):
    """
    SVG uploads are rejected because they can contain active content
    and are not part of the allowed image formats.
    """

    user = create_test_user(
        db,
        user_id=2054,
        username="svguser",
        email="svguser@example.com",
    )

    svg_payload = b"""
    <svg xmlns="http://www.w3.org/2000/svg">
        <script>alert("xss")</script>
        <rect width="100" height="100"/>
    </svg>
    """

    response = create_multipart_item(
        client,
        user,
        image_bytes=svg_payload,
        filename="malicious.svg",
        content_type="image/svg+xml",
    )

    assert response.status_code in {400, 422}


def test_gif_upload_is_rejected(
    client: TestClient,
    db: Session,
):
    """
    GIF is rejected because only JPEG, PNG and WebP are allowed.
    """

    user = create_test_user(
        db,
        user_id=2055,
        username="gifuser",
        email="gifuser@example.com",
    )

    image_bytes = make_image_bytes("GIF")

    response = create_multipart_item(
        client,
        user,
        image_bytes=image_bytes,
        filename="picture.gif",
        content_type="image/gif",
    )

    assert response.status_code in {400, 422}


def test_client_filename_cannot_control_storage_path(
    client: TestClient,
    db: Session,
    tmp_path: Path,
):
    """
    A malicious client filename cannot create a path traversal
    outside the configured media directory.
    """

    original_media_root = settings.MEDIA_ROOT
    settings.MEDIA_ROOT = str(tmp_path / "media")

    try:
        user = create_test_user(
            db,
            user_id=2056,
            username="pathuser",
            email="pathuser@example.com",
        )

        image_bytes = make_image_bytes("JPEG")

        response = create_multipart_item(
            client,
            user,
            image_bytes=image_bytes,
            filename="../../../../evil.jpg",
            content_type="image/jpeg",
        )

        assert response.status_code == 201

        data = response.json()

        stored_key = data["image"]
        stored_path = (Path(settings.MEDIA_ROOT) / stored_key).resolve()
        media_root = Path(settings.MEDIA_ROOT).resolve()

        assert stored_path.is_relative_to(media_root)
        assert stored_path.exists()

        outside_path = media_root.parent / "evil.jpg"

        assert not outside_path.exists()

    finally:
        settings.MEDIA_ROOT = original_media_root


def test_server_generates_random_storage_name(
    client: TestClient,
    db: Session,
    tmp_path: Path,
):
    """
    The stored image key must not simply reuse the client filename.
    """

    original_media_root = settings.MEDIA_ROOT
    settings.MEDIA_ROOT = str(tmp_path / "media")

    try:
        user = create_test_user(
            db,
            user_id=2057,
            username="randomname",
            email="randomname@example.com",
        )

        image_bytes = make_image_bytes("JPEG")

        first_response = create_multipart_item(
            client,
            user,
            image_bytes=image_bytes,
            filename="same-name.jpg",
            content_type="image/jpeg",
        )

        second_response = create_multipart_item(
            client,
            user,
            image_bytes=image_bytes,
            filename="same-name.jpg",
            content_type="image/jpeg",
        )

        assert first_response.status_code == 201
        assert second_response.status_code == 201

        first_key = first_response.json()["image"]
        second_key = second_response.json()["image"]

        assert first_key != "same-name.jpg"
        assert second_key != "same-name.jpg"
        assert first_key != second_key

    finally:
        settings.MEDIA_ROOT = original_media_root


def test_uploaded_image_is_reencoded_and_not_raw_client_bytes(
    client: TestClient,
    db: Session,
    tmp_path: Path,
):
    """
    The stored image should be a sanitized server-generated image,
    not the original raw upload.
    """

    original_media_root = settings.MEDIA_ROOT
    settings.MEDIA_ROOT = str(tmp_path / "media")

    try:
        user = create_test_user(
            db,
            user_id=2058,
            username="sanitizeuser",
            email="sanitizeuser@example.com",
        )

        image_bytes = make_image_bytes("JPEG")

        response = create_multipart_item(
            client,
            user,
            image_bytes=image_bytes,
            filename="original.jpg",
            content_type="image/jpeg",
        )

        assert response.status_code == 201

        stored_key = response.json()["image"]
        stored_path = Path(settings.MEDIA_ROOT) / stored_key

        assert stored_path.exists()

        stored_bytes = stored_path.read_bytes()

        assert stored_bytes != image_bytes

        with Image.open(BytesIO(stored_bytes)) as stored_image:
            stored_image.verify()

    finally:
        settings.MEDIA_ROOT = original_media_root


def test_transparent_png_is_supported_without_becoming_active_content(
    client: TestClient,
    db: Session,
    tmp_path: Path,
):
    """
    Transparent PNG images remain valid image data after sanitization.
    """

    original_media_root = settings.MEDIA_ROOT
    settings.MEDIA_ROOT = str(tmp_path / "media")

    try:
        user = create_test_user(
            db,
            user_id=2059,
            username="transparentuser",
            email="transparentuser@example.com",
        )

        image_bytes = make_png_with_transparency()

        response = create_multipart_item(
            client,
            user,
            image_bytes=image_bytes,
            filename="transparent.png",
            content_type="image/png",
        )

        assert response.status_code == 201

        stored_key = response.json()["image"]
        stored_path = Path(settings.MEDIA_ROOT) / stored_key

        assert stored_path.exists()

        with Image.open(stored_path) as stored_image:
            stored_image.load()

            assert stored_image.format in {
                "PNG",
                "JPEG",
                "WEBP",
            }

    finally:
        settings.MEDIA_ROOT = original_media_root


def test_oversized_image_is_rejected(
    client: TestClient,
    db: Session,
):
    """
    Images larger than IMAGE_MAX_SIZE_BYTES are rejected.
    """

    user = create_test_user(
        db,
        user_id=2060,
        username="largeimage",
        email="largeimage@example.com",
    )

    image_bytes = make_oversized_image_bytes()

    assert len(image_bytes) > settings.IMAGE_MAX_SIZE_BYTES

    response = create_multipart_item(
        client,
        user,
        image_bytes=image_bytes,
        filename="large.png",
        content_type="image/png",
    )

    assert response.status_code in {400, 413, 422}


def test_image_dimensions_are_limited(
    client: TestClient,
    db: Session,
):
    """
    Images exceeding the configured width/height limits are rejected.
    """

    user = create_test_user(
        db,
        user_id=2061,
        username="dimensionuser",
        email="dimensionuser@example.com",
    )

    width = settings.IMAGE_MAX_WIDTH + 1
    height = 100

    image_bytes = make_image_bytes(
        "JPEG",
        width=width,
        height=height,
    )

    response = create_multipart_item(
        client,
        user,
        image_bytes=image_bytes,
        filename="wide.jpg",
        content_type="image/jpeg",
    )

    assert response.status_code in {400, 422}


def test_image_pixel_limit_is_enforced(
    client: TestClient,
    db: Session,
):
    """
    Images exceeding the configured total pixel limit are rejected.
    """

    user = create_test_user(
        db,
        user_id=2062,
        username="pixeluser",
        email="pixeluser@example.com",
    )

    width = 4096
    height = 4096

    assert width * height <= settings.IMAGE_MAX_PIXELS

    width = settings.IMAGE_MAX_WIDTH
    height = (
        settings.IMAGE_MAX_PIXELS // width
    ) + 1

    image_bytes = make_image_bytes(
        "JPEG",
        width=width,
        height=height,
    )

    response = create_multipart_item(
        client,
        user,
        image_bytes=image_bytes,
        filename="pixels.jpg",
        content_type="image/jpeg",
    )

    assert response.status_code in {400, 422}


def test_no_image_upload_still_allows_normal_item_creation(
    client: TestClient,
    db: Session,
):
    """
    Image upload remains optional.
    """

    user = create_test_user(
        db,
        user_id=2063,
        username="noimageuser",
        email="noimageuser@example.com",
    )

    response = client.post(
        "/api/items",
        headers=authenticated_headers(user),
        json={
            "title": "Lost Keys",
            "description": "A set of keys lost near the reception desk.",
            "type": "lost",
            "category": "keys",
            "location": "Reception",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["user_id"] == user.id
    assert data["image"] is None
