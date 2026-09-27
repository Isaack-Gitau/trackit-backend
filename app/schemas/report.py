"""
TRACKIT Report Schemas.

Pydantic schemas used for report creation,
moderator/admin review, resolution, and API responses.

Security principles:

- reporter_id is never accepted from the client.
- reviewed_by is never accepted from the client.
- status is controlled by the service layer.
- reviewed_at is controlled by the service layer.
- Resolution notes are controlled by the moderator/admin workflow.
- Normal report responses expose only reporter_id.
- Moderation report responses expose only reporter id + username.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# REPORT STATUS
# ============================================================================

ReportStatus = Literal[
    "pending",
    "reviewed",
    "resolved",
    "withdrawn",
]


# ============================================================================
# CREATE REPORT
# ============================================================================


class ReportCreate(BaseModel):
    """
    Data required for a user to submit a report.

    The authenticated user's identity is obtained from
    the authentication context, never from this request.
    """

    reason: str = Field(
        ...,
        min_length=3,
        max_length=100,
    )

    description: str = Field(
        ...,
        min_length=10,
        max_length=5000,
    )

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        """
        Normalize and validate the report reason.
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "Report reason cannot be empty."
            )

        return value

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        """
        Normalize and validate the report description.
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "Report description cannot be empty."
            )

        return value


# ============================================================================
# RESOLVE REPORT
# ============================================================================


class ReportResolve(BaseModel):
    """
    Data required for a moderator or administrator to resolve a report.
    """

    resolution_note: str = Field(
        ...,
        min_length=5,
        max_length=2000,
    )

    @field_validator("resolution_note")
    @classmethod
    def normalize_resolution_note(
        cls,
        value: str,
    ) -> str:
        """
        Normalize and validate the resolution note.
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "Resolution note cannot be empty."
            )

        return value


# ============================================================================
# MODERATION IDENTITY
# ============================================================================


class ReporterModerationIdentity(BaseModel):
    """
    Restricted reporter identity exposed only to
    moderator/admin report workflows.

    This intentionally excludes private profile information
    such as email, phone, address, social links, and preferences.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    username: str


# ============================================================================
# REPORT RESPONSE
# ============================================================================


class ReportResponse(BaseModel):
    """
    API representation of a report for normal user-facing endpoints.

    Only reporter_id is exposed. No reporter profile information
    is included in this response.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int

    item_id: int
    reporter_id: int

    reason: str
    description: str

    status: ReportStatus

    reviewed_by: int | None
    reviewed_at: datetime | None

    resolution_note: str | None

    created_at: datetime
    updated_at: datetime


# ============================================================================
# MODERATION REPORT RESPONSE
# ============================================================================


class ModerationReportResponse(BaseModel):
    """
    API representation of a report for moderator/admin workflows.

    Moderators/admins receive only the reporter's public moderation
    identity: id + username.

    Private profile information is intentionally excluded.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int

    item_id: int
    reporter_id: int
    reporter: ReporterModerationIdentity

    reason: str
    description: str

    status: ReportStatus

    reviewed_by: int | None
    reviewed_at: datetime | None

    resolution_note: str | None

    created_at: datetime
    updated_at: datetime
