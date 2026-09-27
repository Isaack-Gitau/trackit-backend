"""
TRACKIT Claim Service.

Business logic for creating, retrieving, withdrawing,
and administratively reviewing claims against FOUND items.

Architecture:

Router
    ↓
Schema / Validation
    ↓
Service / Business Rules
    ↓
Repository / Database Access
    ↓
Model

Security principles:

- Claimant identity always comes from the authenticated user.
- Reviewer identity always comes from the authenticated administrator.
- Clients cannot directly choose claim status.
- Only FOUND items may receive claims.
- Users cannot claim their own items.
- Duplicate active claims are prevented.
- Only pending claims may be reviewed or withdrawn.
- Rejection requires a reason.
- Moderators and administrators cannot review their own claims.
- Security-relevant actions are audited.
- Claim lifecycle events generate user notifications.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.claim import Claim
from app.models.item import Item

from app.repositories.claims import (
    create_claim as repository_create_claim,
    get_active_claim_by_user_and_item,
    get_claim_by_id,
    get_claim_by_id_for_update,
    get_claims_by_item,
    get_claims_by_user,
    get_pending_claims,
    update_claim as repository_update_claim,
    withdraw_claim as repository_withdraw_claim,
)

from app.repositories.items import (
    get_item_by_id_for_update,
    update_item_status as repository_update_item_status,
)

from app.services.audit_log import (
    AUDIT_CLAIM_CREATED,
    AUDIT_CLAIM_UPDATED,
    create_audit_log,
)

from app.services.notification import (
    NOTIFICATION_CLAIM_APPROVED,
    NOTIFICATION_CLAIM_CREATED,
    NOTIFICATION_CLAIM_REJECTED,
    NOTIFICATION_CLAIM_WITHDRAWN,
    create_notification,
)


# ============================================================================
# CONSTANTS
# ============================================================================

CLAIM_STATUS_PENDING = "pending"
CLAIM_STATUS_APPROVED = "approved"
CLAIM_STATUS_REJECTED = "rejected"
CLAIM_STATUS_WITHDRAWN = "withdrawn"

ACTIVE_CLAIM_STATUSES = {
    CLAIM_STATUS_PENDING,
    CLAIM_STATUS_APPROVED,
}


# ============================================================================
# CREATE
# ============================================================================


def create_claim(
    db: Session,
    *,
    item: Item,
    claimant_id: int,
    reason: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Claim:
    """
    Create a claim against a FOUND item.

    Business rules:

    - Item must exist.
    - Item must be FOUND.
    - Item must be approved.
    - Claimant cannot own the item.
    - Claimant cannot already have an active claim.
    - Claim starts as pending.
    - Claim creation is audited.
    - The item owner receives a notification.

    The claimant ID must come from the authenticated user.
    """

    locked_item = get_item_by_id_for_update(
        db,
        item.id,
    )

    if locked_item is None:
        raise ValueError(
            "The item no longer exists."
        )

    item = locked_item

    if item.type != "found":
        raise ValueError(
            "Claims can only be submitted for found items."
        )

    if item.status != "approved":
        raise ValueError(
            "claims can only be submitted for approved items."
        )

    if item.user_id == claimant_id:
        raise PermissionError(
            "You cannot claim your own item."
        )

    normalized_reason = reason.strip()

    if not normalized_reason:
        raise ValueError(
            "Claim reason cannot be empty."
        )

    existing_claim = get_active_claim_by_user_and_item(
        db,
        claimant_id=claimant_id,
        item_id=item.id,
    )

    if existing_claim is not None:
        raise ValueError(
            "You already have an active claim for this item."
        )

    claim = repository_create_claim(
        db,
        item_id=item.id,
        claimant_id=claimant_id,
        reason=normalized_reason,
    )

    claim.item = item

    create_audit_log(
        db,
        event_type=AUDIT_CLAIM_CREATED,
        success=True,
        description=(
            f"Claim {claim.id} created for item {item.id}."
        ),
        user_id=claimant_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    create_notification(
        db,
        user_id=item.user_id,
        notification_type=NOTIFICATION_CLAIM_CREATED,
        title="New claim submitted",
        message=(
            f"Someone has submitted a claim for your found item "
            f"\"{item.title}\"."
        ),
        entity_type="claim",
        entity_id=claim.id,
    )

    return claim


# ============================================================================
# READ — SINGLE CLAIM
# ============================================================================


def get_claim(
    db: Session,
    *,
    claim_id: int,
) -> Claim | None:
    """
    Retrieve a claim by ID.
    """

    return get_claim_by_id(
        db,
        claim_id,
    )


# ============================================================================
# READ — USER CLAIMS
# ============================================================================


def list_user_claims(
    db: Session,
    *,
    claimant_id: int,
) -> list[Claim]:
    """
    Retrieve claims belonging to the authenticated user.
    """

    return get_claims_by_user(
        db,
        claimant_id=claimant_id,
    )


# ============================================================================
# READ — ITEM CLAIMS
# ============================================================================


def list_item_claims(
    db: Session,
    *,
    item_id: int,
) -> list[Claim]:
    """
    Retrieve claims associated with an item.

    Authorization for who may view these claims belongs to
    the router/service boundary.
    """

    return get_claims_by_item(
        db,
        item_id=item_id,
    )


# ============================================================================
# READ — PENDING CLAIMS
# ============================================================================


def list_pending_claims(
    db: Session,
) -> list[Claim]:
    """
    Retrieve pending claims for administrative review.

    Admin authorization must be enforced by the caller.
    """

    return get_pending_claims(db)


# ============================================================================
# WITHDRAW
# ============================================================================


def withdraw_claim(
    db: Session,
    *,
    claim: Claim,
    claimant_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Claim:
    """
    Withdraw a pending claim.

    Only the claimant may withdraw their own claim.

    The item owner receives a notification after a successful
    withdrawal.
    """

    if claim.claimant_id != claimant_id:
        raise PermissionError(
            "You are not authorized to withdraw this claim."
        )

    if claim.status != CLAIM_STATUS_PENDING:
        raise ValueError(
            "Only pending claims can be withdrawn."
        )

    updated_claim = repository_withdraw_claim(
        db,
        claim,
    )

    create_audit_log(
        db,
        event_type=AUDIT_CLAIM_UPDATED,
        success=True,
        description=(
            f"Claim {claim.id} withdrawn."
        ),
        user_id=claimant_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    create_notification(
        db,
        user_id=claim.item.user_id,
        notification_type=NOTIFICATION_CLAIM_WITHDRAWN,
        title="Claim withdrawn",
        message=(
            f"A claim for your found item "
            f"\"{claim.item.title}\" has been withdrawn."
        ),
        entity_type="claim",
        entity_id=claim.id,
    )

    return updated_claim


# ============================================================================
# APPROVE
# ============================================================================


def approve_claim(
    db: Session,
    *,
    claim: Claim,
    reviewer_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Claim:
    """
    Approve a pending claim.

    Business rules:

    - Only pending claims can be approved.
    - A claimant cannot approve their own claim.
    - An item may have only one approved claim.
    - Once a claim is approved, the associated item becomes claimed.
    - The claimant receives a notification.
    - The caller is responsible for administrator authorization.

    Concurrency protection:

    - The claim row is locked first.
    - The claim status is re-checked after acquiring the lock.
    - The self-moderation rule is checked after acquiring the lock.
    - The associated item row is locked second.
    - This serializes concurrent approval attempts for the same claim
      and competing approval attempts for the same item.
    """

    locked_claim = get_claim_by_id_for_update(
        db,
        claim.id,
    )

    if locked_claim is None:
        raise ValueError(
            "The claim no longer exists."
        )

    claim = locked_claim

    if claim.status != CLAIM_STATUS_PENDING:
        raise ValueError(
            "Only pending claims can be approved."
        )

    if claim.claimant_id == reviewer_id:
        raise PermissionError(
            "You cannot moderate your own claim."
        )

    locked_item = get_item_by_id_for_update(
        db,
        claim.item_id,
    )

    if locked_item is None:
        raise ValueError(
            "The item associated with this claim no longer exists."
        )

    claim.item = locked_item

    # Prevent multiple approved claims for the same item.
    item_claims = get_claims_by_item(
        db,
        item_id=claim.item_id,
    )

    for existing_claim in item_claims:
        if (
            existing_claim.id != claim.id
            and existing_claim.status == CLAIM_STATUS_APPROVED
        ):
            raise ValueError(
                "This item already has an approved claim."
            )

    reviewed_at = datetime.now(timezone.utc)

    updated_claim = repository_update_claim(
        db,
        claim,
        status=CLAIM_STATUS_APPROVED,
        reviewed_by=reviewer_id,
        reviewed_at=reviewed_at,
    )

    # An approved claim means the item has been successfully claimed.
    repository_update_item_status(
        db,
        claim.item,
        status="claimed",
    )

    create_audit_log(
        db,
        event_type=AUDIT_CLAIM_UPDATED,
        success=True,
        description=(
            f"Claim {claim.id} approved and item "
            f"{claim.item_id} marked as claimed."
        ),
        user_id=reviewer_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    create_notification(
        db,
        user_id=claim.claimant_id,
        notification_type=NOTIFICATION_CLAIM_APPROVED,
        title="Claim approved",
        message=(
            f"Your claim for \"{claim.item.title}\" "
            f"has been approved."
        ),
        entity_type="claim",
        entity_id=claim.id,
    )

    return updated_claim


# ============================================================================
# REJECT
# ============================================================================


def reject_claim(
    db: Session,
    *,
    claim: Claim,
    reviewer_id: int,
    rejection_reason: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Claim:
    """
    Reject a pending claim.

    A rejection reason is mandatory for accountability.

    Moderators and administrators cannot reject their own claims.

    The claimant receives a notification containing the rejection
    reason.

    The caller is responsible for ensuring that reviewer_id
    belongs to an authorized administrator.
    """

    if claim.status != CLAIM_STATUS_PENDING:
        raise ValueError(
            "Only pending claims can be rejected."
        )

    if claim.claimant_id == reviewer_id:
        raise PermissionError(
            "You cannot moderate your own claim."
        )

    normalized_reason = rejection_reason.strip()

    if not normalized_reason:
        raise ValueError(
            "Rejection reason cannot be empty."
        )

    reviewed_at = datetime.now(timezone.utc)

    updated_claim = repository_update_claim(
        db,
        claim,
        status=CLAIM_STATUS_REJECTED,
        rejection_reason=normalized_reason,
        reviewed_by=reviewer_id,
        reviewed_at=reviewed_at,
    )

    create_audit_log(
        db,
        event_type=AUDIT_CLAIM_UPDATED,
        success=True,
        description=(
            f"Claim {claim.id} rejected."
        ),
        user_id=reviewer_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    create_notification(
        db,
        user_id=claim.claimant_id,
        notification_type=NOTIFICATION_CLAIM_REJECTED,
        title="Claim rejected",
        message=(
            f"Your claim for \"{claim.item.title}\" "
            f"was rejected. Reason: {normalized_reason}"
        ),
        entity_type="claim",
        entity_id=claim.id,
    )

    return updated_claim
