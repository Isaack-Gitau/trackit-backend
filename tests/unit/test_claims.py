
"""
TRACKIT Claim Service Unit Tests.

Tests the claim business-logic layer independently of the HTTP API.

Coverage:
- claim creation
- found-item restriction
- ownership restriction
- empty-reason validation
- duplicate active claims
- claim retrieval
- user claim listing
- item claim listing
- pending claim listing
- claim withdrawal
- withdrawal authorization
- withdrawal status restriction
- claim approval
- approval status restriction
- claim rejection
- rejection reason validation
- rejection status restriction
- reviewer tracking
- claim lifecycle
- rejected claim resubmission
- audit logging through service execution

Architecture under test:

    Service
       ↓
    Repository
       ↓
    SQLAlchemy Model
"""

from datetime import datetime

import pytest

from app.models.item import Item
from app.models.user import User

from app.services.claim import (
    CLAIM_STATUS_APPROVED,
    CLAIM_STATUS_PENDING,
    CLAIM_STATUS_REJECTED,
    CLAIM_STATUS_WITHDRAWN,
    approve_claim,
    create_claim,
    get_claim,
    list_item_claims,
    list_pending_claims,
    list_user_claims,
    reject_claim,
    withdraw_claim,
)

from app.services.notification import (
    NOTIFICATION_CLAIM_APPROVED,
    NOTIFICATION_CLAIM_CREATED,
    NOTIFICATION_CLAIM_REJECTED,
    NOTIFICATION_CLAIM_WITHDRAWN,
    list_user_notifications,
)

# ============================================================================
# TEST CONSTANTS
# ============================================================================

TEST_ITEM_OWNER_ID = 1
TEST_CLAIMANT_ID = 2

TEST_REVIEWER_ID = 99
TEST_SECOND_REVIEWER_ID = 100
TEST_APPROVAL_REVIEWER_ID = 123
TEST_REJECTION_REVIEWER_ID = 456


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
    Create a minimal valid User required by foreign keys.

    Reviewer IDs must correspond to real users because
    Claim.reviewed_by has a foreign-key constraint to users.id.
    """

    user = db.get(User, user_id)

    if user is not None:
        return user

    user = User(
        id=user_id,
        username=f"claimuser{user_id}",
        first_name="Claim",
        last_name="User",
        email=f"claimuser{user_id}@trackit.test",
        password_hash="test-password-hash",
        role=role,
        is_active=True,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    return user


def create_test_reviewer(
    db,
    *,
    user_id: int,
):
    """
    Create a valid administrator/reviewer user.
    """

    return create_test_user(
        db,
        user_id=user_id,
        role="admin",
    )


def create_test_item(
    db,
    *,
    user_id: int = TEST_ITEM_OWNER_ID,
    item_type: str = "found",
    title: str = "Found Phone",
):
    """
    Create a minimal valid item for claim tests.

    Claims are only allowed against approved found items.
    """

    create_test_user(
        db,
        user_id=user_id,
    )

    item = Item(
        user_id=user_id,
        title=title,
        description="A valid test item for TRACKIT claim testing.",
        type=item_type,
        category="Electronics",
        location="Main Library",
        status="approved",
    )

    db.add(item)
    db.flush()

    return item


def create_test_claim(
    db,
    *,
    item_user_id: int = TEST_ITEM_OWNER_ID,
    claimant_id: int = TEST_CLAIMANT_ID,
    title: str = "Found Phone",
    reason: str = (
        "This phone belongs to me because I can identify "
        "the lock screen."
    ),
):
    """
    Create a valid claim through the service layer.
    """

    item = create_test_item(
        db,
        user_id=item_user_id,
        title=title,
    )

    create_test_user(
        db,
        user_id=claimant_id,
    )

    claim = create_claim(
        db,
        item=item,
        claimant_id=claimant_id,
        reason=reason,
    )

    return item, claim


# ============================================================================
# CREATE CLAIM
# ============================================================================


def test_create_claim_successfully(db):
    """
    A valid claim against a found item should be created.
    """

    item, claim = create_test_claim(db)

    assert claim.id is not None
    assert claim.item_id == item.id
    assert claim.claimant_id == TEST_CLAIMANT_ID
    assert claim.reason.startswith("This phone belongs")
    assert claim.status == CLAIM_STATUS_PENDING

def test_create_claim_notifies_item_owner(db):
    """
    Creating a claim should notify the owner of the found item.
    """

    item, claim = create_test_claim(db)

    notifications = list_user_notifications(
        db,
        user_id=TEST_ITEM_OWNER_ID,
    )

    matching = [
        notification
        for notification in notifications
        if notification.type == NOTIFICATION_CLAIM_CREATED
    ]

    assert len(matching) == 1

    notification = matching[0]

    assert notification.user_id == TEST_ITEM_OWNER_ID
    assert notification.is_read is False
    assert "claim" in notification.message.lower()
    assert item.title in notification.message
    assert claim.id is not None


def test_create_claim_strips_reason_whitespace(db):
    """
    Claim reasons should be normalized by removing surrounding whitespace.
    """

    item = create_test_item(db)

    create_test_user(
        db,
        user_id=TEST_CLAIMANT_ID,
    )

    claim = create_claim(
        db,
        item=item,
        claimant_id=TEST_CLAIMANT_ID,
        reason="   I can prove ownership.   ",
    )

    assert claim.reason == "I can prove ownership."


def test_claim_must_be_for_found_item(db):
    """
    Claims against lost items must be rejected.
    """

    item = create_test_item(
        db,
        item_type="lost",
    )

    create_test_user(
        db,
        user_id=TEST_CLAIMANT_ID,
    )

    with pytest.raises(
        ValueError,
        match="Claims can only be submitted for found items",
    ):
        create_claim(
            db,
            item=item,
            claimant_id=TEST_CLAIMANT_ID,
            reason="This belongs to me.",
        )


def test_user_cannot_claim_own_item(db):
    """
    An item owner must not be allowed to claim their own item.
    """

    item = create_test_item(
        db,
        user_id=TEST_ITEM_OWNER_ID,
    )

    with pytest.raises(
        PermissionError,
        match="cannot claim your own item",
    ):
        create_claim(
            db,
            item=item,
            claimant_id=TEST_ITEM_OWNER_ID,
            reason="This is my item.",
        )


def test_claim_reason_cannot_be_empty(db):
    """
    Empty or whitespace-only claim reasons must be rejected.
    """

    item = create_test_item(db)

    create_test_user(
        db,
        user_id=TEST_CLAIMANT_ID,
    )

    with pytest.raises(
        ValueError,
        match="Claim reason cannot be empty",
    ):
        create_claim(
            db,
            item=item,
            claimant_id=TEST_CLAIMANT_ID,
            reason="   ",
        )


def test_duplicate_active_claim_is_rejected(db):
    """
    A user cannot have more than one active claim for the same item.
    """

    item, first_claim = create_test_claim(db)

    assert first_claim.status == CLAIM_STATUS_PENDING

    with pytest.raises(
        ValueError,
        match="already have an active claim",
    ):
        create_claim(
            db,
            item=item,
            claimant_id=TEST_CLAIMANT_ID,
            reason="I am submitting the claim again.",
        )


def test_different_users_can_claim_same_found_item(db):
    """
    Different users may submit claims against the same found item.

    The duplicate restriction applies to the same claimant/item pair.
    """

    item = create_test_item(db)

    create_test_user(
        db,
        user_id=2,
    )

    create_test_user(
        db,
        user_id=3,
    )

    claim_one = create_claim(
        db,
        item=item,
        claimant_id=2,
        reason="I can identify the device.",
    )

    claim_two = create_claim(
        db,
        item=item,
        claimant_id=3,
        reason="I can provide proof of ownership.",
    )

    assert claim_one.id != claim_two.id
    assert claim_one.claimant_id == 2
    assert claim_two.claimant_id == 3


def test_rejected_claim_can_be_resubmitted(db):
    """
    A rejected claim is historical and should not prevent
    the same user from submitting a new claim.
    """

    item, first_claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    rejected = reject_claim(
        db,
        claim=first_claim,
        reviewer_id=reviewer.id,
        rejection_reason="Insufficient proof of ownership.",
    )

    assert rejected.status == CLAIM_STATUS_REJECTED

    second_claim = create_claim(
        db,
        item=item,
        claimant_id=TEST_CLAIMANT_ID,
        reason="I am providing additional identifying information.",
    )

    assert second_claim.id != first_claim.id
    assert second_claim.status == CLAIM_STATUS_PENDING
    assert first_claim.status == CLAIM_STATUS_REJECTED


def test_withdrawn_claim_can_be_resubmitted(db):
    """
    A withdrawn claim is historical and should not prevent
    the same user from submitting a new claim.
    """

    item, first_claim = create_test_claim(db)

    withdrawn = withdraw_claim(
        db,
        claim=first_claim,
        claimant_id=TEST_CLAIMANT_ID,
    )

    assert withdrawn.status == CLAIM_STATUS_WITHDRAWN

    second_claim = create_claim(
        db,
        item=item,
        claimant_id=TEST_CLAIMANT_ID,
        reason="I want to submit the claim again.",
    )

    assert second_claim.id != first_claim.id
    assert second_claim.status == CLAIM_STATUS_PENDING


# ============================================================================
# GET CLAIM
# ============================================================================


def test_get_claim_returns_existing_claim(db):
    """
    Looking up an existing claim should return that claim.
    """

    _, claim = create_test_claim(db)

    result = get_claim(
        db,
        claim_id=claim.id,
    )

    assert result is not None
    assert result.id == claim.id


def test_get_claim_returns_none_for_missing_claim(db):
    """
    Looking up a nonexistent claim should return None.
    """

    result = get_claim(
        db,
        claim_id=999999,
    )

    assert result is None


# ============================================================================
# LIST USER CLAIMS
# ============================================================================


def test_list_user_claims(db):
    """
    A user should receive only their own claims.
    """

    item_one, claim_one = create_test_claim(
        db,
        item_user_id=1,
        claimant_id=2,
        title="Found Phone",
    )

    item_two, claim_two = create_test_claim(
        db,
        item_user_id=1,
        claimant_id=3,
        title="Found Laptop",
    )

    user_claims = list_user_claims(
        db,
        claimant_id=2,
    )

    claim_ids = {
        claim.id
        for claim in user_claims
    }

    assert claim_one.id in claim_ids
    assert claim_two.id not in claim_ids

    assert all(
        claim.claimant_id == 2
        for claim in user_claims
    )

    assert item_one.id != item_two.id


def test_list_user_claims_returns_empty_for_user_without_claims(db):
    """
    A user without claims should receive an empty list.
    """

    create_test_user(
        db,
        user_id=10,
    )

    claims = list_user_claims(
        db,
        claimant_id=10,
    )

    assert claims == []


# ============================================================================
# LIST ITEM CLAIMS
# ============================================================================


def test_list_item_claims(db):
    """
    Listing claims for an item should return claims belonging
    to that item only.
    """

    item_one, claim_one = create_test_claim(
        db,
        item_user_id=1,
        claimant_id=2,
        title="Found Phone",
    )

    item_two, claim_two = create_test_claim(
        db,
        item_user_id=1,
        claimant_id=3,
        title="Found Laptop",
    )

    claims = list_item_claims(
        db,
        item_id=item_one.id,
    )

    claim_ids = {
        claim.id
        for claim in claims
    }

    assert claim_one.id in claim_ids
    assert claim_two.id not in claim_ids

    assert all(
        claim.item_id == item_one.id
        for claim in claims
    )

    assert item_one.id != item_two.id


def test_list_item_claims_returns_empty_for_item_without_claims(db):
    """
    An item without claims should return an empty list.
    """

    item = create_test_item(db)

    claims = list_item_claims(
        db,
        item_id=item.id,
    )

    assert claims == []


# ============================================================================
# LIST PENDING CLAIMS
# ============================================================================


def test_list_pending_claims(db):
    """
    Pending claims should be returned for administrative review.
    """

    _, pending_claim = create_test_claim(
        db,
        claimant_id=2,
        title="Pending Phone",
    )

    _, second_pending_claim = create_test_claim(
        db,
        claimant_id=3,
        title="Pending Laptop",
    )

    claims = list_pending_claims(db)

    claim_ids = {
        claim.id
        for claim in claims
    }

    assert pending_claim.id in claim_ids
    assert second_pending_claim.id in claim_ids

    assert all(
        claim.status == CLAIM_STATUS_PENDING
        for claim in claims
    )


def test_approved_claim_is_not_pending(db):
    """
    An approved claim should not be returned as pending.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    approved = approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    assert approved.status == CLAIM_STATUS_APPROVED

    pending_claims = list_pending_claims(db)

    assert all(
        pending.id != claim.id
        for pending in pending_claims
    )


def test_rejected_claim_is_not_pending(db):
    """
    A rejected claim should not be returned as pending.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    rejected = reject_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
        rejection_reason="Ownership could not be verified.",
    )

    assert rejected.status == CLAIM_STATUS_REJECTED

    pending_claims = list_pending_claims(db)

    assert all(
        pending.id != claim.id
        for pending in pending_claims
    )


# ============================================================================
# WITHDRAW CLAIM
# ============================================================================


def test_claimant_can_withdraw_pending_claim(db):
    """
    The claimant may withdraw their own pending claim.
    """

    _, claim = create_test_claim(db)

    result = withdraw_claim(
        db,
        claim=claim,
        claimant_id=TEST_CLAIMANT_ID,
    )

    assert result.status == CLAIM_STATUS_WITHDRAWN

def test_withdraw_claim_notifies_item_owner(db):
    """
    Withdrawing a claim should notify the owner of the found item.
    """

    item, claim = create_test_claim(db)

    result = withdraw_claim(
        db,
        claim=claim,
        claimant_id=TEST_CLAIMANT_ID,
    )

    assert result.status == CLAIM_STATUS_WITHDRAWN

    notifications = list_user_notifications(
        db,
        user_id=TEST_ITEM_OWNER_ID,
    )

    matching = [
        notification
        for notification in notifications
        if notification.type == NOTIFICATION_CLAIM_WITHDRAWN
    ]

    assert len(matching) == 1

    notification = matching[0]

    assert notification.user_id == TEST_ITEM_OWNER_ID
    assert notification.is_read is False
    assert item.title in notification.message
    assert "withdrawn" in notification.message.lower()

def test_non_claimant_cannot_withdraw_claim(db):
    """
    A different user must not be allowed to withdraw the claim.
    """

    _, claim = create_test_claim(db)

    with pytest.raises(
        PermissionError,
        match="not authorized to withdraw",
    ):
        withdraw_claim(
            db,
            claim=claim,
            claimant_id=3,
        )


def test_only_pending_claim_can_be_withdrawn(db):
    """
    Approved claims cannot be withdrawn.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    with pytest.raises(
        ValueError,
        match="Only pending claims can be withdrawn",
    ):
        withdraw_claim(
            db,
            claim=claim,
            claimant_id=TEST_CLAIMANT_ID,
        )


# ============================================================================
# APPROVE CLAIM
# ============================================================================


def test_admin_can_approve_pending_claim(db):
    """
    A pending claim can be approved by the review service.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    result = approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    assert result.status == CLAIM_STATUS_APPROVED
    assert result.reviewed_by == reviewer.id
    assert result.reviewed_at is not None
    assert isinstance(
        result.reviewed_at,
        datetime,
    )

def test_approve_claim_notifies_claimant(db):
    """
    Approving a claim should notify the claimant.
    """

    item, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    result = approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    assert result.status == CLAIM_STATUS_APPROVED

    notifications = list_user_notifications(
        db,
        user_id=TEST_CLAIMANT_ID,
    )

    matching = [
        notification
        for notification in notifications
        if notification.type == NOTIFICATION_CLAIM_APPROVED
    ]

    assert len(matching) == 1

    notification = matching[0]

    assert notification.user_id == TEST_CLAIMANT_ID
    assert notification.is_read is False
    assert item.title in notification.message
    assert "approved" in notification.message.lower()

def test_approving_claim_marks_item_as_claimed(db):
    """
    Approving a claim must automatically mark the associated
    found item as claimed.
    """

    item, claim = create_test_claim(db)

    assert item.status == "approved"

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    result = approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    assert result.status == CLAIM_STATUS_APPROVED
    assert item.status == "claimed"


def test_only_one_claim_can_be_approved_for_an_item(db):
    """
    Multiple users may have pending claims, but only one claim
    may be approved for the same item.
    """

    item = create_test_item(db)

    create_test_user(
        db,
        user_id=2,
    )

    create_test_user(
        db,
        user_id=3,
    )

    first_claim = create_claim(
        db,
        item=item,
        claimant_id=2,
        reason="I can identify this item.",
    )

    second_claim = create_claim(
        db,
        item=item,
        claimant_id=3,
        reason="I have identifying information.",
    )

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    approve_claim(
        db,
        claim=first_claim,
        reviewer_id=reviewer.id,
    )

    assert first_claim.status == CLAIM_STATUS_APPROVED
    assert item.status == "claimed"

    with pytest.raises(
        ValueError,
        match="already has an approved claim",
    ):
        approve_claim(
            db,
            claim=second_claim,
            reviewer_id=reviewer.id,
        )

    assert second_claim.status == CLAIM_STATUS_PENDING
    assert item.status == "claimed"


def test_rejected_claim_does_not_change_item_status(db):
    """
    Rejecting a claim must leave the item available for
    future claims.
    """

    item, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    rejected = reject_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
        rejection_reason="Ownership could not be verified.",
    )

    assert rejected.status == CLAIM_STATUS_REJECTED
    assert item.status == "approved"


def test_withdrawn_claim_does_not_change_item_status(db):
    """
    Withdrawing a claim must leave the item available for
    future claims.
    """

    item, claim = create_test_claim(db)

    withdrawn = withdraw_claim(
        db,
        claim=claim,
        claimant_id=TEST_CLAIMANT_ID,
    )

    assert withdrawn.status == CLAIM_STATUS_WITHDRAWN
    assert item.status == "approved"


def test_only_pending_claim_can_be_approved(db):
    """
    A claim that has already been rejected cannot be approved.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    second_reviewer = create_test_reviewer(
        db,
        user_id=TEST_SECOND_REVIEWER_ID,
    )

    reject_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
        rejection_reason="Test rejection.",
    )

    with pytest.raises(
        ValueError,
        match="Only pending claims can be approved",
    ):
        approve_claim(
            db,
            claim=claim,
            reviewer_id=second_reviewer.id,
        )


def test_approved_claim_cannot_be_approved_again(db):
    """
    An already approved claim cannot be approved a second time.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    second_reviewer = create_test_reviewer(
        db,
        user_id=TEST_SECOND_REVIEWER_ID,
    )

    approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    with pytest.raises(
        ValueError,
        match="Only pending claims can be approved",
    ):
        approve_claim(
            db,
            claim=claim,
            reviewer_id=second_reviewer.id,
        )


# ============================================================================
# REJECT CLAIM
# ============================================================================


def test_admin_can_reject_pending_claim(db):
    """
    A pending claim can be rejected with a valid reason.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    result = reject_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
        rejection_reason="The claimant could not provide proof.",
    )

    assert result.status == CLAIM_STATUS_REJECTED
    assert result.reviewed_by == reviewer.id
    assert result.reviewed_at is not None
    assert (
        result.rejection_reason
        == "The claimant could not provide proof."
    )

def test_reject_claim_notifies_claimant(db):
    """
    Rejecting a claim should notify the claimant and include
    the rejection reason.
    """

    item, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REJECTION_REVIEWER_ID,
    )

    rejection_reason = "Ownership could not be verified."

    result = reject_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
        rejection_reason=rejection_reason,
    )

    assert result.status == CLAIM_STATUS_REJECTED

    notifications = list_user_notifications(
        db,
        user_id=TEST_CLAIMANT_ID,
    )

    matching = [
        notification
        for notification in notifications
        if notification.type == NOTIFICATION_CLAIM_REJECTED
    ]

    assert len(matching) == 1

    notification = matching[0]

    assert notification.user_id == TEST_CLAIMANT_ID
    assert notification.is_read is False
    assert item.title in notification.message
    assert "rejected" in notification.message.lower()
    assert rejection_reason in notification.message

def test_rejection_reason_is_stripped(db):
    """
    Rejection reasons should be normalized by removing
    surrounding whitespace.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    result = reject_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
        rejection_reason="   Insufficient proof.   ",
    )

    assert result.rejection_reason == "Insufficient proof."


def test_rejection_requires_reason(db):
    """
    A rejection reason is mandatory.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    with pytest.raises(
        ValueError,
        match=r"(?i)rejection.*reason|reason.*rejection",
    ):
        reject_claim(
            db,
            claim=claim,
            reviewer_id=reviewer.id,
            rejection_reason="   ",
        )


def test_only_pending_claim_can_be_rejected(db):
    """
    An approved claim cannot later be rejected.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    second_reviewer = create_test_reviewer(
        db,
        user_id=TEST_SECOND_REVIEWER_ID,
    )

    approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    with pytest.raises(
        ValueError,
        match="Only pending claims can be rejected",
    ):
        reject_claim(
            db,
            claim=claim,
            reviewer_id=second_reviewer.id,
            rejection_reason="Late rejection.",
        )


def test_rejected_claim_cannot_be_rejected_again(db):
    """
    A rejected claim cannot be rejected a second time.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    second_reviewer = create_test_reviewer(
        db,
        user_id=TEST_SECOND_REVIEWER_ID,
    )

    reject_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
        rejection_reason="Initial rejection.",
    )

    with pytest.raises(
        ValueError,
        match="Only pending claims can be rejected",
    ):
        reject_claim(
            db,
            claim=claim,
            reviewer_id=second_reviewer.id,
            rejection_reason="Second rejection.",
        )


# ============================================================================
# CLAIM LIFECYCLE
# ============================================================================


def test_claim_lifecycle_pending_to_approved(db):
    """
    Verify the normal pending → approved lifecycle.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    assert claim.status == CLAIM_STATUS_PENDING

    approved = approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    assert approved.status == CLAIM_STATUS_APPROVED
    assert approved.reviewed_by == reviewer.id
    assert approved.reviewed_at is not None


def test_claim_lifecycle_pending_to_rejected(db):
    """
    Verify the normal pending → rejected lifecycle.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    assert claim.status == CLAIM_STATUS_PENDING

    rejected = reject_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
        rejection_reason="Proof of ownership was insufficient.",
    )

    assert rejected.status == CLAIM_STATUS_REJECTED
    assert rejected.reviewed_by == reviewer.id
    assert rejected.reviewed_at is not None
    assert (
        rejected.rejection_reason
        == "Proof of ownership was insufficient."
    )


def test_claim_lifecycle_pending_to_withdrawn(db):
    """
    Verify the normal pending → withdrawn lifecycle.
    """

    _, claim = create_test_claim(db)

    assert claim.status == CLAIM_STATUS_PENDING

    withdrawn = withdraw_claim(
        db,
        claim=claim,
        claimant_id=TEST_CLAIMANT_ID,
    )

    assert withdrawn.status == CLAIM_STATUS_WITHDRAWN


# ============================================================================
# ACTIVE CLAIM BEHAVIOR
# ============================================================================


def test_withdrawn_claim_does_not_remain_active(db):
    """
    Once a claim is withdrawn, it should no longer block
    the claimant from submitting a new claim.
    """

    item, claim = create_test_claim(db)

    withdrawn = withdraw_claim(
        db,
        claim=claim,
        claimant_id=TEST_CLAIMANT_ID,
    )

    assert withdrawn.status == CLAIM_STATUS_WITHDRAWN

    new_claim = create_claim(
        db,
        item=item,
        claimant_id=TEST_CLAIMANT_ID,
        reason="I am submitting a corrected claim.",
    )

    assert new_claim.id != claim.id
    assert new_claim.status == CLAIM_STATUS_PENDING


def test_approved_claim_remains_active(db):
    """
    Approved claims belong to the active claim status set.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REVIEWER_ID,
    )

    approved = approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    assert approved.status == CLAIM_STATUS_APPROVED


# ============================================================================
# REVIEWER TRACKING
# ============================================================================


def test_approval_records_reviewer(db):
    """
    Approval must record the administrator/reviewer ID.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_APPROVAL_REVIEWER_ID,
    )

    result = approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    assert result.reviewed_by == reviewer.id
    assert result.reviewed_at is not None


def test_rejection_records_reviewer(db):
    """
    Rejection must record the administrator/reviewer ID.
    """

    _, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_REJECTION_REVIEWER_ID,
    )

    result = reject_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
        rejection_reason="Ownership evidence was insufficient.",
    )

    assert result.reviewed_by == reviewer.id
    assert result.reviewed_at is not None
    assert result.rejection_reason == (
        "Ownership evidence was insufficient."
    )


# ============================================================================
# REJECTED → RESUBMITTED → APPROVED
# ============================================================================


def test_rejected_claim_can_be_resubmitted_and_approved(db):
    """
    A rejected claim should remain in history while allowing
    the claimant to submit a new claim for the same item.

    Lifecycle:

        PENDING
          ↓
        REJECTED
          ↓
        NEW CLAIM
          ↓
        PENDING
          ↓
        APPROVED
          ↓
        ITEM = CLAIMED
    """

    # ------------------------------------------------------------
    # 1. Create the item and first claim.
    # ------------------------------------------------------------

    item, first_claim = create_test_claim(
        db,
        claimant_id=TEST_CLAIMANT_ID,
        title="Resubmission Test Backpack",
    )

    assert first_claim.status == CLAIM_STATUS_PENDING
    assert item.status == "approved"

    # ------------------------------------------------------------
    # 2. Reject the first claim.
    # ------------------------------------------------------------

    rejection_reviewer = create_test_reviewer(
        db,
        user_id=TEST_REJECTION_REVIEWER_ID,
    )

    rejected_claim = reject_claim(
        db,
        claim=first_claim,
        reviewer_id=rejection_reviewer.id,
        rejection_reason=(
            "The claimant could not provide sufficient proof."
        ),
    )

    assert rejected_claim.status == CLAIM_STATUS_REJECTED
    assert rejected_claim.rejection_reason == (
        "The claimant could not provide sufficient proof."
    )

    # The original claim remains in history.
    assert rejected_claim.id == first_claim.id

    # Rejecting a claim does not make the item unavailable.
    assert item.status == "approved"

    # ------------------------------------------------------------
    # 3. Submit a NEW claim from the same user.
    # ------------------------------------------------------------

    second_claim = create_claim(
        db,
        item=item,
        claimant_id=TEST_CLAIMANT_ID,
        reason="I can now provide additional proof of ownership.",
    )

    # A new database record must be created.
    assert second_claim.id != first_claim.id

    # The new claim starts as pending.
    assert second_claim.status == CLAIM_STATUS_PENDING

    # The old rejected claim remains rejected.
    assert first_claim.status == CLAIM_STATUS_REJECTED

    # ------------------------------------------------------------
    # 4. Approve the NEW claim.
    # ------------------------------------------------------------

    approval_reviewer = create_test_reviewer(
        db,
        user_id=TEST_APPROVAL_REVIEWER_ID,
    )

    approved_claim = approve_claim(
        db,
        claim=second_claim,
        reviewer_id=approval_reviewer.id,
    )

    assert approved_claim.status == CLAIM_STATUS_APPROVED
    assert approved_claim.reviewed_by == approval_reviewer.id
    assert approved_claim.reviewed_at is not None

    # ------------------------------------------------------------
    # 5. Approval must mark the item as claimed.
    # ------------------------------------------------------------

    assert item.status == "claimed"

    # ------------------------------------------------------------
    # 6. Both claim records must remain in history.
    # ------------------------------------------------------------

    claims = list_item_claims(
        db,
        item_id=item.id,
    )

    claim_ids = {
        claim.id
        for claim in claims
    }

    assert first_claim.id in claim_ids
    assert second_claim.id in claim_ids

    # ------------------------------------------------------------
    # 7. Verify historical states were preserved.
    # ------------------------------------------------------------

    historical_claim = next(
        claim
        for claim in claims
        if claim.id == first_claim.id
    )

    final_claim = next(
        claim
        for claim in claims
        if claim.id == second_claim.id
    )

    assert historical_claim.status == CLAIM_STATUS_REJECTED
    assert final_claim.status == CLAIM_STATUS_APPROVED


def test_approve_claim_notification_is_sent_only_to_claimant(db):
    """
    An approval notification must belong to the claimant and
    must not be sent to the item owner.
    """

    item, claim = create_test_claim(db)

    reviewer = create_test_reviewer(
        db,
        user_id=TEST_APPROVAL_REVIEWER_ID,
    )

    approve_claim(
        db,
        claim=claim,
        reviewer_id=reviewer.id,
    )

    claimant_notifications = list_user_notifications(
        db,
        user_id=TEST_CLAIMANT_ID,
    )

    owner_notifications = list_user_notifications(
        db,
        user_id=TEST_ITEM_OWNER_ID,
    )

    assert any(
        notification.type == NOTIFICATION_CLAIM_APPROVED
        for notification in claimant_notifications
    )

    assert not any(
        notification.type == NOTIFICATION_CLAIM_APPROVED
        for notification in owner_notifications
    )