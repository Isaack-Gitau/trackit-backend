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
- item moderation
- approval-triggered matching
- approval-triggered match notifications
- prevention of automatic claim creation

Architecture under test:

    Service
       ↓
    Repository
       ↓
    SQLAlchemy Model
"""

import pytest

from app.models.claim import Claim
from app.models.item import Item
from app.models.match import Match
from app.models.notification import Notification
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
from app.services.notification import (
    NOTIFICATION_ITEM_APPROVED,
    NOTIFICATION_MATCH_FOUND,
)

from app.repositories.items import (
    get_items,
    get_public_items,
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


def approve_test_item_directly(
    db,
    *,
    item: Item,
) -> Item:
    """
    Mark an item approved directly for test setup.

    This is intentionally different from approve_item().

    It allows integration tests to prepare an already-approved
    opposite-type candidate without triggering the workflow under test.
    """

    item.status = "approved"
    db.flush()

    return item


def get_match_notifications_for_match(
    db,
    *,
    match_id: int,
) -> list[Notification]:
    """
    Return persisted match-found notifications for a specific Match.
    """

    return (
        db.query(Notification)
        .filter(
            Notification.type == NOTIFICATION_MATCH_FOUND,
            Notification.entity_type == "match",
            Notification.entity_id == match_id,
        )
        .all()
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
# PUBLIC VISIBILITY
# ============================================================================


def test_get_public_items_returns_approved_items(db):
    """
    Public item queries should return approved items.
    """

    item = create_test_item(
        db,
        title="Approved Laptop",
    )

    approve_test_item_directly(
        db,
        item=item,
    )

    results = get_public_items(db)

    assert len(results) == 1
    assert results[0].id == item.id
    assert results[0].status == "approved"


def test_get_public_items_returns_claimed_items(db):
    """
    Claimed items remain publicly visible.
    """

    item = create_test_item(
        db,
        title="Claimed Laptop",
    )

    item.status = "claimed"
    db.flush()

    results = get_public_items(db)

    assert len(results) == 1
    assert results[0].id == item.id
    assert results[0].status == "claimed"


def test_get_public_items_excludes_pending_items(db):
    """
    Pending items must never appear in the public query.
    """

    item = create_test_item(
        db,
        title="Pending Laptop",
    )

    assert item.status == "pending"

    results = get_public_items(db)

    assert results == []


def test_get_public_items_excludes_rejected_items(db):
    """
    Rejected items must never appear in the public query.
    """

    item = create_test_item(
        db,
        title="Rejected Laptop",
    )

    item.status = "rejected"
    db.flush()

    results = get_public_items(db)

    assert results == []


def test_get_public_items_returns_only_public_statuses(db):
    """
    A mixture of moderation states should return only approved
    and claimed items.
    """

    approved = create_test_item(
        db,
        title="Approved Item",
    )

    claimed = create_test_item(
        db,
        title="Claimed Item",
    )

    pending = create_test_item(
        db,
        title="Pending Item",
    )

    rejected = create_test_item(
        db,
        title="Rejected Item",
    )

    approve_test_item_directly(
        db,
        item=approved,
    )

    claimed.status = "claimed"
    rejected.status = "rejected"
    db.flush()

    results = get_public_items(db)

    result_ids = {item.id for item in results}

    assert result_ids == {
        approved.id,
        claimed.id,
    }

    assert pending.id not in result_ids
    assert rejected.id not in result_ids

    assert all(
        item.status in {"approved", "claimed"}
        for item in results
    )


def test_get_public_items_filters_by_type(db):
    """
    Public queries should preserve item-type filtering.
    """

    approved_lost = create_test_item(
        db,
        item_type="lost",
        title="Approved Lost Laptop",
    )

    approved_found = create_test_item(
        db,
        item_type="found",
        title="Approved Found Laptop",
    )

    approve_test_item_directly(
        db,
        item=approved_lost,
    )

    approve_test_item_directly(
        db,
        item=approved_found,
    )

    results = get_public_items(
        db,
        item_type="found",
    )

    assert len(results) == 1
    assert results[0].id == approved_found.id
    assert results[0].type == "found"


def test_get_public_items_filters_by_category(db):
    """
    Public queries should preserve category filtering.
    """

    electronics = create_test_item(
        db,
        title="Approved Phone",
        category="Electronics",
    )

    books = create_test_item(
        db,
        title="Approved Book",
        category="Books",
    )

    approve_test_item_directly(
        db,
        item=electronics,
    )

    approve_test_item_directly(
        db,
        item=books,
    )

    results = get_public_items(
        db,
        category="electronics",
    )

    assert len(results) == 1
    assert results[0].id == electronics.id


def test_get_public_items_filters_by_location(db):
    """
    Public queries should preserve location filtering.
    """

    library_item = create_test_item(
        db,
        title="Approved Library Laptop",
        location="Main Library",
    )

    cafeteria_item = create_test_item(
        db,
        title="Approved Cafeteria Wallet",
        location="Cafeteria",
    )

    approve_test_item_directly(
        db,
        item=library_item,
    )

    approve_test_item_directly(
        db,
        item=cafeteria_item,
    )

    results = get_public_items(
        db,
        location="main library",
    )

    assert len(results) == 1
    assert results[0].id == library_item.id


def test_get_public_items_searches_only_public_items(db):
    """
    Search results must not expose pending or rejected items,
    even when those items match the search term.
    """

    approved = create_test_item(
        db,
        title="Approved Black Laptop",
        description="Black laptop available.",
    )

    pending = create_test_item(
        db,
        title="Pending Black Laptop",
        description="Black laptop awaiting review.",
    )

    rejected = create_test_item(
        db,
        title="Rejected Black Laptop",
        description="Black laptop submission rejected.",
    )

    approve_test_item_directly(
        db,
        item=approved,
    )

    rejected.status = "rejected"
    db.flush()

    results = get_public_items(
        db,
        search="black laptop",
    )

    assert len(results) == 1
    assert results[0].id == approved.id

    result_ids = {item.id for item in results}

    assert pending.id not in result_ids
    assert rejected.id not in result_ids


def test_get_public_items_paginates_approved_and_claimed_items_together(
    db,
):
    """
    Pagination must operate over the combined public dataset,
    rather than separately paginating approved and claimed items.
    """

    items = []

    for number in range(5):
        item = create_test_item(
            db,
            title=f"Public Item {number}",
        )

        if number == 4:
            item.status = "claimed"
            db.flush()
        else:
            approve_test_item_directly(
                db,
                item=item,
            )

        items.append(item)

    first_page = get_public_items(
        db,
        offset=0,
        limit=2,
    )

    second_page = get_public_items(
        db,
        offset=2,
        limit=2,
    )

    third_page = get_public_items(
        db,
        offset=4,
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

    all_public_ids = first_ids | second_ids | third_ids

    assert all_public_ids == {
        item.id
        for item in items
    }


def test_get_items_remains_unrestricted_for_internal_use(db):
    """
    The generic repository query must remain capable of retrieving
    non-public moderation states for internal/admin workflows.
    """

    pending = create_test_item(
        db,
        title="Pending Internal Item",
    )

    rejected = create_test_item(
        db,
        title="Rejected Internal Item",
    )

    rejected.status = "rejected"
    db.flush()

    results = get_items(db)

    result_ids = {item.id for item in results}

    assert pending.id in result_ids
    assert rejected.id in result_ids

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


def test_owner_cannot_approve_own_pending_item(db, admin_user):
    """
    A moderator or administrator cannot approve their own item.
    """

    item = create_test_item(
        db,
        user_id=admin_user.id,
    )

    with pytest.raises(
        PermissionError,
        match="cannot moderate your own item",
    ):
        approve_item(
            db,
            item=item,
            reviewer_id=admin_user.id,
        )

    assert item.status == "pending"


def test_owner_cannot_reject_own_pending_item(db, admin_user):
    """
    A moderator or administrator cannot reject their own item.
    """

    item = create_test_item(
        db,
        user_id=admin_user.id,
    )

    with pytest.raises(
        PermissionError,
        match="cannot moderate your own item",
    ):
        reject_item(
            db,
            item=item,
            reviewer_id=admin_user.id,
            rejection_reason="Insufficient information.",
        )

    assert item.status == "pending"


# ============================================================================
# RESTORED MODERATION AND MATCHING REGRESSION TESTS
# ============================================================================

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


def test_approving_lost_item_generates_match(db, admin_user):
    """
    Approving a LOST item should generate a match against an
    already-approved FOUND item when the score qualifies.
    """

    from app.models.match import Match

    found_item = create_test_item(
        db,
        user_id=2,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="found",
        category="Electronics",
        location="Library",
    )

    found_item.status = "approved"
    db.flush()

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    assert lost_item.status == "pending"

    approved = approve_item(
        db,
        item=lost_item,
        reviewer_id=admin_user.id,
    )

    assert approved.status == "approved"

    matches = db.query(Match).all()

    assert len(matches) == 1
    assert matches[0].lost_item_id == lost_item.id
    assert matches[0].found_item_id == found_item.id
    assert matches[0].score >= 60


def test_approving_found_item_generates_match(db, admin_user):
    """
    Approving a FOUND item should generate a match against an
    already-approved LOST item when the score qualifies.
    """

    from app.models.match import Match

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    lost_item.status = "approved"
    db.flush()

    found_item = create_test_item(
        db,
        user_id=2,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="found",
        category="Electronics",
        location="Library",
    )

    assert found_item.status == "pending"

    approved = approve_item(
        db,
        item=found_item,
        reviewer_id=admin_user.id,
    )

    assert approved.status == "approved"

    matches = db.query(Match).all()

    assert len(matches) == 1
    assert matches[0].lost_item_id == lost_item.id
    assert matches[0].found_item_id == found_item.id
    assert matches[0].score >= 60


def test_approving_item_ignores_pending_opposite_item(db, admin_user):
    """
    An approved item must not be matched against an opposite-type
    item that is still pending.
    """

    from app.models.match import Match

    pending_found_item = create_test_item(
        db,
        user_id=2,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="found",
        category="Electronics",
        location="Library",
    )

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    approve_item(
        db,
        item=lost_item,
        reviewer_id=admin_user.id,
    )

    assert lost_item.status == "approved"
    assert pending_found_item.status == "pending"

    assert db.query(Match).all() == []


def test_approving_item_ignores_rejected_opposite_item(db, admin_user):
    """
    An approved item must not be matched against a rejected
    opposite-type item.
    """

    from app.models.match import Match

    rejected_found_item = create_test_item(
        db,
        user_id=2,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="found",
        category="Electronics",
        location="Library",
    )

    reject_item(
        db,
        item=rejected_found_item,
        reviewer_id=admin_user.id,
        rejection_reason="Test rejection.",
    )

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    approve_item(
        db,
        item=lost_item,
        reviewer_id=admin_user.id,
    )

    assert lost_item.status == "approved"
    assert rejected_found_item.status == "rejected"

    assert db.query(Match).all() == []


def test_approving_item_does_not_create_weak_match(db, admin_user):
    """
    Approval must not create a match when the candidate score
    is below the possible-match threshold.
    """

    from app.models.match import Match

    found_item = create_test_item(
        db,
        user_id=2,
        title="Red Bicycle",
        description="Red mountain bicycle.",
        item_type="found",
        category="Sports",
        location="City Stadium",
    )

    found_item.status = "approved"
    db.flush()

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Black Laptop",
        description="Black laptop with silver logo.",
        item_type="lost",
        category="Electronics",
        location="Main Library",
    )

    approve_item(
        db,
        item=lost_item,
        reviewer_id=admin_user.id,
    )

    assert lost_item.status == "approved"
    assert db.query(Match).all() == []


def test_approving_item_does_not_duplicate_existing_match(
    db,
    admin_user,
):
    """
    Approval-driven matching must not create duplicate records
    when the same matching workflow is triggered again.
    """

    from app.models.match import Match
    from app.services.match import generate_matches_for_item

    found_item = create_test_item(
        db,
        user_id=2,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="found",
        category="Electronics",
        location="Library",
    )

    found_item.status = "approved"
    db.flush()

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    approve_item(
        db,
        item=lost_item,
        reviewer_id=admin_user.id,
    )

    first_matches = db.query(Match).all()

    assert len(first_matches) == 1

    generate_matches_for_item(
        db,
        item=lost_item,
    )

    second_matches = db.query(Match).all()

    assert len(second_matches) == 1
    assert second_matches[0].id == first_matches[0].id


def test_approving_item_still_creates_approval_notification(
    db,
    admin_user,
):
    """
    Integrating matching must not remove the existing approval
    notification behavior.
    """

    from app.models.notification import Notification

    item = create_test_item(
        db,
        user_id=10,
        title="Approval Test Laptop",
    )

    approve_item(
        db,
        item=item,
        reviewer_id=admin_user.id,
    )

    notifications = db.query(Notification).filter(
        Notification.user_id == item.user_id,
    ).all()

    assert len(notifications) == 1
    assert notifications[0].type == "item_approved"


def test_approving_item_still_creates_audit_log(
    db,
    admin_user,
):
    """
    Integrating matching must not remove the existing approval
    audit behavior.
    """

    from app.models.audit_log import AuditLog

    item = create_test_item(
        db,
        user_id=10,
        title="Audit Test Laptop",
    )

    approve_item(
        db,
        item=item,
        reviewer_id=admin_user.id,
    )

    logs = db.query(AuditLog).filter(
        AuditLog.user_id == admin_user.id,
    ).all()

    assert any(
        f"Item {item.id} approved by administrator." in log.description
        for log in logs
    )

# ============================================================================
# APPROVAL → MATCHING → NOTIFICATIONS
# ============================================================================


def test_approving_lost_item_generates_match_and_notifies_both_users(
    db,
    admin_user,
):
    """
    Approving a LOST item should generate a qualifying match against
    an already-approved FOUND item and notify both participating users.
    """

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    found_item = create_test_item(
        db,
        user_id=2,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="found",
        category="Electronics",
        location="Library",
    )

    approve_test_item_directly(
        db,
        item=found_item,
    )

    approved_lost_item = approve_item(
        db,
        item=lost_item,
        reviewer_id=admin_user.id,
    )

    assert approved_lost_item.status == "approved"

    matches = (
        db.query(Match)
        .filter(
            Match.lost_item_id == lost_item.id,
            Match.found_item_id == found_item.id,
        )
        .all()
    )

    assert len(matches) == 1

    match = matches[0]

    assert match.score >= 60
    assert match.match_level in {"possible", "strong"}

    notifications = get_match_notifications_for_match(
        db,
        match_id=match.id,
    )

    assert len(notifications) == 2

    recipient_ids = {
        notification.user_id
        for notification in notifications
    }

    assert recipient_ids == {1, 2}


def test_approving_found_item_generates_match_and_notifies_both_users(
    db,
    admin_user,
):
    """
    Approving a FOUND item should generate a qualifying match against
    an already-approved LOST item and notify both participating users.
    """

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    approve_test_item_directly(
        db,
        item=lost_item,
    )

    found_item = create_test_item(
        db,
        user_id=2,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="found",
        category="Electronics",
        location="Library",
    )

    approved_found_item = approve_item(
        db,
        item=found_item,
        reviewer_id=admin_user.id,
    )

    assert approved_found_item.status == "approved"

    matches = (
        db.query(Match)
        .filter(
            Match.lost_item_id == lost_item.id,
            Match.found_item_id == found_item.id,
        )
        .all()
    )

    assert len(matches) == 1

    match = matches[0]

    assert match.score >= 60
    assert match.match_level in {"possible", "strong"}

    notifications = get_match_notifications_for_match(
        db,
        match_id=match.id,
    )

    assert len(notifications) == 2

    recipient_ids = {
        notification.user_id
        for notification in notifications
    }

    assert recipient_ids == {1, 2}


def test_approving_item_does_not_notify_for_non_matching_item(
    db,
    admin_user,
):
    """
    An approved item should not generate a match notification when
    the available opposite-type item scores below the possible threshold.
    """

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Red Bicycle",
        description="Red mountain bicycle with basket.",
        item_type="lost",
        category="Sports",
        location="North Campus",
    )

    found_item = create_test_item(
        db,
        user_id=2,
        title="Blue Wallet",
        description="Small leather wallet found downtown.",
        item_type="found",
        category="Personal Items",
        location="South Gate",
    )

    approve_test_item_directly(
        db,
        item=found_item,
    )

    approve_item(
        db,
        item=lost_item,
        reviewer_id=admin_user.id,
    )

    match_notifications = (
        db.query(Notification)
        .filter(
            Notification.type == NOTIFICATION_MATCH_FOUND,
        )
        .all()
    )

    assert match_notifications == []


def test_approving_item_with_same_user_match_creates_one_notification(
    db,
    admin_user,
):
    """
    If the LOST and FOUND items belong to the same user, matching should
    still occur but only one match notification should be created.
    """

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    found_item = create_test_item(
        db,
        user_id=1,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="found",
        category="Electronics",
        location="Library",
    )

    approve_test_item_directly(
        db,
        item=found_item,
    )

    approve_item(
        db,
        item=lost_item,
        reviewer_id=admin_user.id,
    )

    matches = (
        db.query(Match)
        .filter(
            Match.lost_item_id == lost_item.id,
            Match.found_item_id == found_item.id,
        )
        .all()
    )

    assert len(matches) == 1

    match_notifications = get_match_notifications_for_match(
        db,
        match_id=matches[0].id,
    )

    assert len(match_notifications) == 1
    assert match_notifications[0].user_id == 1


def test_approving_item_does_not_create_claim(
    db,
    admin_user,
):
    """
    Matching is informational only.

    Approving an item and generating a potential match must never
    automatically create a claim.
    """

    lost_item = create_test_item(
        db,
        user_id=1,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="lost",
        category="Electronics",
        location="Library",
    )

    found_item = create_test_item(
        db,
        user_id=2,
        title="Black Dell Laptop",
        description="Black Dell laptop with silver logo.",
        item_type="found",
        category="Electronics",
        location="Library",
    )

    approve_test_item_directly(
        db,
        item=found_item,
    )

    approve_item(
        db,
        item=lost_item,
        reviewer_id=admin_user.id,
    )

    claims = db.query(Claim).all()

    assert claims == []