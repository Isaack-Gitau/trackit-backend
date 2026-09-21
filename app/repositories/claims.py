"""
TRACKIT Claim Repository.

Database access layer for claims against FOUND items.

Business rules, authorization, and claim lifecycle decisions
belong in the service layer.

This module is responsible only for querying and persisting
Claim records.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.claim import Claim


# ============================================================================
# CREATE
# ============================================================================


def create_claim(
    db: Session,
    *,
    item_id: int,
    claimant_id: int,
    reason: str,
) -> Claim:
    """
    Create and persist a new claim.

    The repository does not decide whether the claimant is
    allowed to claim the item. That belongs in the service layer.
    """

    claim = Claim(
        item_id=item_id,
        claimant_id=claimant_id,
        reason=reason,
        status="pending",
    )

    db.add(claim)
    db.flush()

    return claim


# ============================================================================
# READ — SINGLE CLAIM
# ============================================================================


def get_claim_by_id(
    db: Session,
    claim_id: int,
) -> Claim | None:
    """
    Retrieve a claim by its primary key with its related item loaded.
    """

    return db.scalar(
        select(Claim)
        .options(selectinload(Claim.item))
        .where(Claim.id == claim_id)
    )


def get_claim_by_id_for_update(
    db: Session,
    claim_id: int,
) -> Claim | None:
    """
    Retrieve a claim by primary key and lock its row for update.

    The lock is held until the current database transaction commits
    or rolls back. This is intended for claim lifecycle operations
    that must serialize concurrent state changes to the same claim.
    """

    return db.scalar(
        select(Claim)
        .where(Claim.id == claim_id)
        .with_for_update()
    )


# ============================================================================
# READ — CLAIMANT
# ============================================================================


def get_claims_by_user(
    db: Session,
    *,
    claimant_id: int,
) -> list[Claim]:
    """
    Retrieve all claims submitted by a specific user.

    Results are returned newest first.
    """

    statement = (
        select(Claim)
        .options(selectinload(Claim.item))
        .where(Claim.claimant_id == claimant_id)
        .order_by(Claim.created_at.desc())
    )

    return list(db.scalars(statement).all())


# ============================================================================
# READ — ITEM
# ============================================================================


def get_claims_by_item(
    db: Session,
    *,
    item_id: int,
) -> list[Claim]:
    """
    Retrieve all claims associated with an item.

    Results are returned newest first.
    """

    statement = (
        select(Claim)
        .where(Claim.item_id == item_id)
        .order_by(Claim.created_at.desc())
    )

    return list(db.scalars(statement).all())


# ============================================================================
# READ — ACTIVE CLAIM
# ============================================================================


def get_active_claim_by_user_and_item(
    db: Session,
    *,
    claimant_id: int,
    item_id: int,
) -> Claim | None:
    """
    Retrieve an existing active claim submitted by a user
    against an item.

    Active states are:

        pending
        approved

    Rejected and withdrawn claims are historical and therefore
    do not prevent a future claim unless the service layer
    imposes an additional business rule.
    """

    statement = (
        select(Claim)
        .where(
            Claim.claimant_id == claimant_id,
            Claim.item_id == item_id,
            Claim.status.in_(("pending", "approved")),
        )
        .order_by(Claim.created_at.desc())
        .limit(1)
    )

    return db.scalar(statement)


# ============================================================================
# READ — PENDING CLAIMS
# ============================================================================


def get_pending_claims(
    db: Session,
) -> list[Claim]:
    """
    Retrieve all pending claims.

    Intended primarily for administrative review.
    """

    statement = (
        select(Claim)
        .options(selectinload(Claim.item))
        .where(Claim.status == "pending")
        .order_by(Claim.created_at.asc())
    )

    return list(db.scalars(statement).all())


# ============================================================================
# UPDATE — CLAIM
# ============================================================================


def update_claim(
    db: Session,
    claim: Claim,
    *,
    status: str | None = None,
    rejection_reason: str | None = None,
    reviewed_by: int | None = None,
    reviewed_at=None,
) -> Claim:
    """
    Update supplied claim fields.

    Authorization and lifecycle validation must be performed
    by the service layer before this function is called.
    """

    if status is not None:
        claim.status = status

    if rejection_reason is not None:
        claim.rejection_reason = rejection_reason

    if reviewed_by is not None:
        claim.reviewed_by = reviewed_by

    if reviewed_at is not None:
        claim.reviewed_at = reviewed_at

    db.flush()

    return claim


# ============================================================================
# WITHDRAW
# ============================================================================


def withdraw_claim(
    db: Session,
    claim: Claim,
) -> Claim:
    """
    Mark a claim as withdrawn.

    Authorization and status validation must be performed
    by the service layer.
    """

    claim.status = "withdrawn"

    db.flush()

    return claim
