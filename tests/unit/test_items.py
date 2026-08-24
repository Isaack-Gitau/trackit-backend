"""
TRACKIT Item Service Unit Tests.

Tests the item business-logic layer independently of the HTTP API.

Coverage:
- item creation
- lost/found validation
- default moderation status
- item retrieval
- user-owned item retrieval
- searching
- filtering
- pagination
- ownership authorization
- updating
- deleting

Architecture under test:

    Service
       ↓
    Repository
       ↓
    SQLAlchemy Model
"""

import pytest

from app.models.user import User
from app.services.item import (
    approve_item,
    create_item,
    delete_item,
    get_item,
    list_items,
    list_user_items,
    reject_item,
    update_item,
)


# ============================================================================
# TEST HELPERS
# ============================================================================


def create_test_user(
    db,
    *,
    user_id: int,
    role: str = "user",
):
    """
    Create a minimal valid User required by Item.user_id.

    The helper deliberately creates the user directly because these
    tests focus on item business logic rather than user registration.
    """

    user = db.get(User, user_id)

    if user is not None:
        return user

    user = User(
        id=user_id,
        username=f"testuser{user_id}",
        first_name="Test",
        last_name="User",
        email=f"testuser{user_id}@trackit.test",
        password_hash="test-password-hash",
        role=role,
        is_active=True,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    return user


def create_test_item(
    db,
    *,
    user_id: int = 1,
    title: str = "Lost Laptop",
    description: str = "Black laptop lost yesterday.",
    item_type: str = "lost",
    category: str = "Electronics",
    location: str = "Library",
    image: str | None = None,
):
    """
    Create an item through the service layer.

    A valid User is automatically created first so that the
    items.user_id foreign-key constraint remains valid.
    """

    create_test_user(
        db,
        user_id=user_id,
    )

    return create_item(
        db,
        user_id=user_id,
        title=title,
        description=description,
        item_type=item_type,
        category=category,
        location=location,
        image=image,
    )


# ============================================================================
# CREATE
# ============================================================================


def test_create_lost_item(db):
    """
    A valid lost item should be created successfully.
    """

    item = create_test_item(db)

    assert item.id is not None
    assert item.user_id == 1
    assert item.title == "Lost Laptop"
    assert item.type == "lost"
    assert item.status == "pending"


def test_create_found_item(db):
    """
    A valid found item should be created successfully.
    """

    item = create_test_item(
        db,
        item_type="found",
        title="Found Phone",
        description="A smartphone found outside administration.",
        location="Administration Block",
    )

    assert item.id is not None
    assert item.type == "found"
    assert item.status == "pending"


def test_new_items_always_start_pending(db):
    """
    Item creation must never automatically approve an item.

    Moderation is handled separately.
    """

    lost_item = create_test_item(
        db,
        item_type="lost",
    )

    found_item = create_test_item(
        db,
        item_type="found",
        title="Found Wallet",
        description="A wallet found near the cafeteria.",
    )

    assert lost_item.status == "pending"
    assert found_item.status == "pending"


def test_invalid_item_type_is_rejected(db):
    """
    Only 'lost' and 'found' are valid item types.
    """

    with pytest.raises(
        ValueError,
        match="Item type",
    ):
        create_test_item(
            db,
            item_type="invalid",
        )


def test_empty_item_type_is_rejected(db):
    """
    Empty item types must not be accepted by the service layer.
    """

    with pytest.raises(
        ValueError,
        match="Item type",
    ):
        create_test_item(
            db,
            item_type="",
        )


# ============================================================================
# READ
# ============================================================================


def test_get_item_by_id(db):
    """
    An existing item should be retrievable by ID.
    """

    item = create_test_item(db)

    result = get_item(
        db,
        item_id=item.id,
    )

    assert result is not None
    assert result.id == item.id
    assert result.title == item.title


def test_get_nonexistent_item_returns_none(db):
    """
    Requesting a nonexistent item should return None.
    """

    result = get_item(
        db,
        item_id=999999,
    )

    assert result is None


def test_list_user_items_returns_only_owned_items(db):
    """
    User item listing must not return another user's items.
    """

    create_test_item(
        db,
        user_id=1,
        title="User One Item",
    )

    create_test_item(
        db,
        user_id=1,
        title="User One Second Item",
    )

    create_test_item(
        db,
        user_id=2,
        title="User Two Item",
    )

    results = list_user_items(
        db,
        user_id=1,
    )

    assert len(results) == 2
    assert all(item.user_id == 1 for item in results)


def test_list_user_items_returns_empty_for_user_without_items(db):
    """
    A valid user without items should receive an empty list.
    """

    create_test_user(
        db,
        user_id=50,
    )

    results = list_user_items(
        db,
        user_id=50,
    )

    assert results == []


# ============================================================================
# SEARCH
# ============================================================================


def test_search_items_by_title(db):
    """
    Search should match item titles.
    """

    create_test_item(
        db,
        title="Lost Student ID",
        description="Identification card lost yesterday.",
    )

    create_test_item(
        db,
        title="Found Backpack",
        description="Black backpack found near the hall.",
    )

    results = list_items(
        db,
        search="student id",
    )

    assert len(results) == 1
    assert results[0].title == "Lost Student ID"


def test_search_items_by_description(db):
    """
    Search should match item descriptions.
    """

    create_test_item(
        db,
        title="Lost Item One",
        description="Silver Samsung phone with cracked screen.",
    )

    create_test_item(
        db,
        title="Lost Item Two",
        description="Black leather wallet.",
    )

    results = list_items(
        db,
        search="Samsung",
    )

    assert len(results) == 1
    assert results[0].title == "Lost Item One"


def test_search_items_by_category(db):
    """
    Search should match categories.
    """

    create_test_item(
        db,
        title="Lost Item One",
        category="Electronics",
    )

    create_test_item(
        db,
        title="Lost Item Two",
        category="Documents",
    )

    results = list_items(
        db,
        search="electronics",
    )

    assert len(results) == 1
    assert results[0].category == "Electronics"


def test_search_items_by_location(db):
    """
    Search should match locations.

    Test descriptions intentionally do not contain the search term
    so that this test specifically verifies location searching.
    """

    create_test_item(
        db,
        title="Lost Laptop",
        description="Black laptop lost yesterday.",
        location="Main Library",
    )

    create_test_item(
        db,
        title="Lost Wallet",
        description="Brown wallet lost yesterday.",
        location="Cafeteria",
    )

    results = list_items(
        db,
        search="library",
    )

    assert len(results) == 1
    assert results[0].title == "Lost Laptop"
    assert results[0].location == "Main Library"


def test_search_is_case_insensitive(db):
    """
    Search should be case-insensitive.
    """

    create_test_item(
        db,
        title="Lost Laptop",
        description="Laptop lost yesterday.",
    )

    results = list_items(
        db,
        search="LOST LAPTOP",
    )

    assert len(results) == 1
    assert results[0].title == "Lost Laptop"


# ============================================================================
# FILTERING
# ============================================================================


def test_filter_items_by_type(db):
    """
    Filtering by type should return only matching items.
    """

    create_test_item(
        db,
        item_type="lost",
        title="Lost Wallet",
    )

    create_test_item(
        db,
        item_type="found",
        title="Found Wallet",
    )

    results = list_items(
        db,
        item_type="found",
    )

    assert len(results) == 1
    assert results[0].type == "found"


def test_filter_items_by_category(db):
    """
    Filtering by category should be case-insensitive.
    """

    create_test_item(
        db,
        category="Electronics",
        title="Lost Phone",
    )

    create_test_item(
        db,
        category="Documents",
        title="Lost ID",
    )

    results = list_items(
        db,
        category="electronics",
    )

    assert len(results) == 1
    assert results[0].category == "Electronics"


def test_filter_items_by_location(db):
    """
    Filtering by location should be case-insensitive.
    """

    create_test_item(
        db,
        location="Main Library",
        title="Lost Laptop",
    )

    create_test_item(
        db,
        location="Cafeteria",
        title="Lost Wallet",
    )

    results = list_items(
        db,
        location="main library",
    )

    assert len(results) == 1
    assert results[0].location == "Main Library"


def test_filter_items_by_status(db):
    """
    Filtering by moderation status should work.

    Newly-created items are pending.
    """

    create_test_item(
        db,
        title="Pending Laptop",
    )

    create_test_item(
        db,
        title="Another Pending Item",
    )

    results = list_items(
        db,
        status="pending",
    )

    assert len(results) == 2
    assert all(item.status == "pending" for item in results)


# ============================================================================
# COMBINED FILTERS
# ============================================================================


def test_combined_filters(db):
    """
    Multiple filters should be applied together.
    """

    create_test_item(
        db,
        title="Lost Phone",
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    create_test_item(
        db,
        title="Found Phone",
        item_type="found",
        category="Electronics",
        location="Library",
    )

    create_test_item(
        db,
        title="Lost Book",
        item_type="lost",
        category="Books",
        location="Library",
    )

    results = list_items(
        db,
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    assert len(results) == 1
    assert results[0].title == "Lost Phone"


# ============================================================================
# PAGINATION
# ============================================================================


def test_item_pagination(db):
    """
    Pagination should divide results into separate pages.
    """

    for number in range(5):
        create_test_item(
            db,
            title=f"Test Item {number}",
            description=f"Unique item description number {number}.",
        )

    first_page = list_items(
        db,
        page=1,
        limit=2,
    )

    second_page = list_items(
        db,
        page=2,
        limit=2,
    )

    third_page = list_items(
        db,
        page=3,
        limit=2,
    )

    assert len(first_page) == 2
    assert len(second_page) == 2
    assert len(third_page) == 1

    first_ids = {item.id for item in first_page}
    second_ids = {item.id for item in second_page}
    third_ids = {item.id for item in third_page}

    assert first_ids.isdisjoint(second_ids)
    assert first_ids.isdisjoint(third_ids)
    assert second_ids.isdisjoint(third_ids)


def test_invalid_page_is_rejected(db):
    """
    Page numbers must start at one.
    """

    with pytest.raises(
        ValueError,
        match="Page",
    ):
        list_items(
            db,
            page=0,
        )


def test_invalid_limit_is_rejected(db):
    """
    Service-level pagination limit must not exceed 100.
    """

    with pytest.raises(
        ValueError,
        match="Limit",
    ):
        list_items(
            db,
            limit=101,
        )


def test_zero_limit_is_rejected(db):
    """
    A zero pagination limit is invalid.
    """

    with pytest.raises(
        ValueError,
        match="Limit",
    ):
        list_items(
            db,
            limit=0,
        )


# ============================================================================
# UPDATE AUTHORIZATION
# ============================================================================


def test_owner_can_update_item(db):
    """
    The item owner may update their item.
    """

    item = create_test_item(
        db,
        user_id=10,
    )

    updated = update_item(
        db,
        item=item,
        user_id=10,
        title="Updated Laptop",
        location="Main Hall",
    )

    assert updated.title == "Updated Laptop"
    assert updated.location == "Main Hall"


def test_owner_can_update_multiple_fields(db):
    """
    The owner may update multiple permitted fields.
    """

    item = create_test_item(
        db,
        user_id=10,
    )

    updated = update_item(
        db,
        item=item,
        user_id=10,
        title="Updated Phone",
        description="Updated phone description.",
        item_type="found",
        category="Electronics",
        location="Administration Block",
        image="/uploads/items/phone.jpg",
    )

    assert updated.title == "Updated Phone"
    assert updated.description == "Updated phone description."
    assert updated.type == "found"
    assert updated.category == "Electronics"
    assert updated.location == "Administration Block"
    assert updated.image == "/uploads/items/phone.jpg"


def test_non_owner_cannot_update_item(db):
    """
    A different user must not update another user's item.
    """

    item = create_test_item(
        db,
        user_id=10,
    )

    with pytest.raises(
        PermissionError,
        match="not authorized",
    ):
        update_item(
            db,
            item=item,
            user_id=20,
            title="Unauthorized Update",
        )


def test_invalid_update_type_is_rejected(db):
    """
    Invalid item types must also be rejected during updates.
    """

    item = create_test_item(
        db,
        user_id=10,
    )

    with pytest.raises(
        ValueError,
        match="Item type",
    ):
        update_item(
            db,
            item=item,
            user_id=10,
            item_type="invalid",
        )


# ============================================================================
# DELETE AUTHORIZATION
# ============================================================================


def test_owner_can_delete_item(db):
    """
    The owner may delete their item.
    """

    item = create_test_item(
        db,
        user_id=10,
    )

    item_id = item.id

    delete_item(
        db,
        item=item,
        user_id=10,
    )

    assert get_item(
        db,
        item_id=item_id,
    ) is None


def test_non_owner_cannot_delete_item(db):
    """
    A different user must not delete another user's item.
    """

    item = create_test_item(
        db,
        user_id=10,
    )

    with pytest.raises(
        PermissionError,
        match="not authorized",
    ):
        delete_item(
            db,
            item=item,
            user_id=20,
        )

    assert get_item(
        db,
        item_id=item.id,
    ) is not None


# ============================================================================
# UPDATE PRESERVATION
# ============================================================================


def test_update_preserves_unspecified_fields(db):
    """
    PATCH-style updates must preserve fields that were not supplied.
    """

    item = create_test_item(
        db,
        title="Original Laptop",
        description="Original laptop description.",
        category="Electronics",
        location="Library",
    )

    updated = update_item(
        db,
        item=item,
        user_id=item.user_id,
        title="Updated Laptop",
    )

    assert updated.title == "Updated Laptop"
    assert updated.description == "Original laptop description."
    assert updated.category == "Electronics"
    assert updated.location == "Library"

    # ============================================================================
# MODERATION
# ============================================================================


def test_admin_can_approve_pending_item(db, admin_user):
    """
    A pending item can be approved by the moderation service.
    """

    item = create_test_item(db)

    assert item.status == "pending"

    approved = approve_item(
        db,
        item=item,
        reviewer_id=admin_user.id,
    )

    assert approved.status == "approved"


def test_admin_can_reject_pending_item(db, admin_user):
    """
    A pending item can be rejected.
    """

    item = create_test_item(db)

    rejected = reject_item(
        db,
        item=item,
        reviewer_id=admin_user.id,
        rejection_reason="Insufficient information.",
    )

    assert rejected.status == "rejected"


def test_cannot_approve_already_approved_item(db, admin_user):
    """
    An approved item cannot be approved again.
    """

    item = create_test_item(db)

    approve_item(
        db,
        item=item,
        reviewer_id= admin_user.id,
    )

    with pytest.raises(
        ValueError,
        match="Only pending items",
    ):
        approve_item(
            db,
            item=item,
            reviewer_id=admin_user.id,
        )


def test_cannot_reject_approved_item(db, admin_user):
    """
    An approved item cannot subsequently be rejected.
    """

    item = create_test_item(db)

    approve_item(
        db,
        item=item,
        reviewer_id=admin_user.id,
    )

    with pytest.raises(
        ValueError,
        match="Only pending items",
    ):
        reject_item(
            db,
            item=item,
            reviewer_id=99,
            rejection_reason="Too late.",
        )


def test_cannot_approve_rejected_item(db, admin_user):
    """
    A rejected item cannot subsequently be approved.
    """

    item = create_test_item(db)

    reject_item(
        db,
        item=item,
        reviewer_id=admin_user.id,
        rejection_reason="Invalid submission.",
    )

    with pytest.raises(
        ValueError,
        match="Only pending items",
    ):
        approve_item(
            db,
            item=item,
            reviewer_id=admin_user.id,
        )


def test_cannot_reject_rejected_item_again(db, admin_user):
    """
    A rejected item cannot be rejected again.
    """

    item = create_test_item(db)

    reject_item(
        db,
        item=item,
        reviewer_id=admin_user.id,
        rejection_reason="Invalid submission.",
    )

    with pytest.raises(
        ValueError,
        match="Only pending items",
    ):
        reject_item(
            db,
            item=item,
            reviewer_id=admin_user.id,
            rejection_reason="Another reason.",
        )


def test_rejection_requires_reason(db):
    """
    Rejection must contain a non-empty reason.
    """

    item = create_test_item(db)

    with pytest.raises(
        ValueError,
        match="Rejection reason",
    ):
        reject_item(
            db,
            item=item,
            reviewer_id=99,
            rejection_reason="   ",
        )