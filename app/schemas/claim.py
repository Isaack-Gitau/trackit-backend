"""
TRACKIT Claim Schemas.

Pydantic schemas used for validating claim creation,
administrative review, and API responses.

Security principles:

- claimant_id is never accepted from the client.
- reviewed_by is never accepted from the client.
- status is controlled by the service layer.
- Rejection reasons are validated before persistence.
- Response schemas use SQLAlchemy attributes directly.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# CLAIM STATUS
# ============================================================================

ClaimStatus = Literal[
    "pending",
    "approved",
    "rejected",
    "withdrawn",
]


# ============================================================================
# CREATE CLAIM
# ============================================================================


class ClaimCreate(BaseModel):
    """
    Data required for a user to submit a claim.

    The authenticated user's identity is obtained from
    the authentication context, never from this request.
    """

    reason: str = Field(
        ...,
        min_length=10,
        max_length=2000,
    )

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        """
        Remove unnecessary whitespace and reject empty values.
        """
        value = value.strip()

        if not value:
            raise ValueError("Claim reason cannot be empty.")

        return value


# ============================================================================
# REJECT CLAIM
# ============================================================================


class ClaimReject(BaseModel):
    """
    Data required for an administrator to reject a claim.
    """

    rejection_reason: str = Field(
        ...,
        min_length=5,
        max_length=1000,
    )

    @field_validator("rejection_reason")
    @classmethod
    def normalize_rejection_reason(cls, value: str) -> str:
        """
        Normalize and validate the rejection reason.
        """
        value = value.strip()

        if not value:
            raise ValueError("Rejection reason cannot be empty.")

        return value


# ============================================================================
# CLAIM ITEM SUMMARY
# ============================================================================


class ClaimItemSummary(BaseModel):
    """
    Safe summary of the item associated with a claim.

    Only fields required by claim interfaces are exposed.
    Sensitive owner and moderation information is intentionally omitted.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    title: str
    type: Literal["lost", "found"]
    category: str
    location: str
    image: str | None


# ============================================================================
# CLAIM RESPONSE
# ============================================================================


class ClaimResponse(BaseModel):
    """
    API representation of a claim.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    item_id: int
    claimant_id: int

    item: ClaimItemSummary

    reason: str

    status: ClaimStatus

    rejection_reason: str | None

    reviewed_by: int | None
    reviewed_at: datetime | None

    created_at: datetime
    updated_at: datetime