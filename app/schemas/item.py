"""
TRACKIT Item Schemas.

Pydantic schemas used for validating item creation,
updates, filtering, moderation, and API responses.
"""

from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
)

from app.utils.images import image_storage_key_to_url


# ============================================================================
# SHARED ITEM FIELDS
# ============================================================================


class ItemBase(BaseModel):
    """
    Shared fields used by item creation and update schemas.
    """

    title: str = Field(
        ...,
        min_length=3,
        max_length=200,
    )

    description: str = Field(
        ...,
        min_length=10,
        max_length=5000,
    )

    type: Literal["lost", "found"]

    category: str = Field(
        ...,
        min_length=2,
        max_length=100,
    )

    location: str = Field(
        ...,
        min_length=2,
        max_length=255,
    )

    @field_validator(
        "title",
        "description",
        "category",
        "location",
    )
    @classmethod
    def strip_whitespace(cls, value: str) -> str:
        """
        Remove unnecessary leading/trailing whitespace
        and reject empty values.
        """
        value = value.strip()

        if not value:
            raise ValueError("Field cannot be empty.")

        return value


# ============================================================================
# CREATE ITEM
# ============================================================================


class ItemCreate(ItemBase):
    """
    Validated item data used after multipart/form-data fields
    have been parsed by the API layer.

    The actual uploaded image is handled separately through
    FastAPI's UploadFile mechanism.
    """

    image: str | None = Field(
        default=None,
        max_length=500,
    )


# ============================================================================
# UPDATE ITEM
# ============================================================================


class ItemUpdate(BaseModel):
    """
    Fields that may be changed by the item owner.

    All fields are optional because PATCH semantics are used.

    The image value represents the existing stored image key
    when applicable. Actual uploaded files are handled separately
    by the API layer.
    """

    title: str | None = Field(
        default=None,
        min_length=3,
        max_length=200,
    )

    description: str | None = Field(
        default=None,
        min_length=10,
        max_length=5000,
    )

    type: Literal["lost", "found"] | None = None

    category: str | None = Field(
        default=None,
        min_length=2,
        max_length=100,
    )

    location: str | None = Field(
        default=None,
        min_length=2,
        max_length=255,
    )

    image: str | None = Field(
        default=None,
        max_length=500,
    )

    @field_validator(
        "title",
        "description",
        "category",
        "location",
    )
    @classmethod
    def strip_optional_whitespace(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize optional string fields.
        """
        if value is None:
            return None

        value = value.strip()

        if not value:
            raise ValueError("Field cannot be empty.")

        return value


# ============================================================================
# ITEM MODERATION
# ============================================================================


class ItemReject(BaseModel):
    """
    Data required when an administrator rejects an item.

    A rejection reason is mandatory for accountability.
    """

    reason: str = Field(
        ...,
        min_length=3,
        max_length=1000,
    )

    @field_validator("reason")
    @classmethod
    def strip_reason(cls, value: str) -> str:
        """
        Normalize and validate the rejection reason.
        """
        value = value.strip()

        if not value:
            raise ValueError(
                "Rejection reason cannot be empty."
            )

        return value


# ============================================================================
# ITEM RESPONSE
# ============================================================================


class ItemResponse(BaseModel):
    """
    Public API representation of an item.

    The image field contains a public media URL when an image
    exists, not the internal filesystem path.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    user_id: int

    title: str
    description: str
    type: Literal["lost", "found"]
    category: str
    location: str

    image: str | None

    @field_serializer("image")
    def serialize_image(
        self,
        value: str | None,
    ) -> str | None:
        """Convert the internal storage key into a public media URL."""
        if value is None:
            return None

        return image_storage_key_to_url(value)

    status: str

    created_at: datetime
    updated_at: datetime


# ============================================================================
# ITEM LIST / FILTERS
# ============================================================================


class ItemListParams(BaseModel):
    """
    Validated parameters for item searching/filtering.
    """

    search: str | None = Field(
        default=None,
        max_length=100,
    )

    type: Literal["lost", "found"] | None = None

    category: str | None = Field(
        default=None,
        max_length=100,
    )

    location: str | None = Field(
        default=None,
        max_length=255,
    )

    status: Literal[
        "pending",
        "approved",
        "rejected",
        "claimed",
    ] | None = None

    page: int = Field(
        default=1,
        ge=1,
    )

    limit: int = Field(
        default=20,
        ge=1,
        le=100,
    )

    @field_validator(
        "search",
        "category",
        "location",
    )
    @classmethod
    def normalize_filters(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize optional search/filter values.
        """
        if value is None:
            return None

        value = value.strip()

        return value or None
