"""
TRACKIT Item Schemas.

Pydantic schemas used for validating item creation,
updates, filtering, and API responses.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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

    @field_validator("title", "description", "category", "location")
    @classmethod
    def strip_whitespace(cls, value: str) -> str:
        """
        Remove unnecessary leading/trailing whitespace.
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
    Data required to create a lost/found item.
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
    def strip_optional_whitespace(cls, value: str | None) -> str | None:
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
# ITEM RESPONSE
# ============================================================================


class ItemResponse(BaseModel):
    """
    Public API representation of an item.
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

    @field_validator("search", "category", "location")
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