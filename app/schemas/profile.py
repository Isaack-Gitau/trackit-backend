"""
TRACKIT Profile Schemas.

Defines request and response models for authenticated
user profile operations and authorized administrative
user-profile inspection.

Profile fields include:
- username
- first name
- last name
- email
- profile picture
- phone number
- bio
- address
- social links
- preferences

Authentication and authorization secrets are deliberately
excluded from all profile responses.

Administrative profile responses may contain additional
account-management information, but never expose:

- password hashes
- authentication tokens
- token versions
- password reset tokens
- email verification tokens
- other authentication secrets
"""

from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


# ============================================================================
# PROFILE RESPONSE
# ============================================================================


class ProfileResponse(BaseModel):
    """
    Safe representation of an authenticated user's profile.

    Sensitive authentication and authorization fields are
    deliberately excluded.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int

    username: str

    first_name: str

    last_name: str

    email: str

    profile_picture: str | None = None

    phone_number: str | None = None

    bio: str | None = None

    address: str | None = None

    social_links: dict[str, object] = Field(
        default_factory=dict,
    )

    preferences: dict[str, object] = Field(
        default_factory=dict,
    )

    is_verified: bool

    created_at: datetime

    updated_at: datetime


# ============================================================================
# ADMIN USER DETAIL RESPONSE
# ============================================================================


class AdminUserDetailResponse(BaseModel):
    """
    Detailed but security-safe representation of a user.

    This schema is exclusively intended for authorized
    administrative inspection.

    It intentionally excludes security-sensitive fields such as:

    - password_hash
    - token_version
    - authentication tokens
    - password reset tokens
    - email verification tokens
    - session credentials
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    # ========================================================================
    # ACCOUNT IDENTITY
    # ========================================================================

    id: int

    username: str

    first_name: str

    last_name: str

    email: str

    # ========================================================================
    # ACCOUNT STATUS
    # ========================================================================

    role: str

    is_active: bool

    is_verified: bool

    password_changed_at: datetime | None = None

    # ========================================================================
    # PROFILE INFORMATION
    # ========================================================================

    profile_picture: str | None = None

    phone_number: str | None = None

    bio: str | None = None

    address: str | None = None

    social_links: dict[str, object] = Field(
        default_factory=dict,
    )

    preferences: dict[str, object] = Field(
        default_factory=dict,
    )

    # ========================================================================
    # ACCOUNT TIMESTAMPS
    # ========================================================================

    created_at: datetime

    updated_at: datetime


# ============================================================================
# PROFILE UPDATE
# ============================================================================


class ProfileUpdate(BaseModel):
    """
    Fields that an authenticated user may update.

    All fields are optional because the profile endpoint
    uses PATCH semantics.
    """

    username: str | None = Field(
        default=None,
        min_length=3,
        max_length=50,
    )

    email: str | None = Field(
        default=None,
        max_length=320,
    )

    first_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    last_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    profile_picture: str | None = Field(
        default=None,
        max_length=500,
    )

    phone_number: str | None = Field(
        default=None,
        max_length=30,
    )

    bio: str | None = Field(
        default=None,
        max_length=500,
    )

    address: str | None = Field(
        default=None,
        max_length=255,
    )

    social_links: dict[str, object] | None = None

    preferences: dict[str, object] | None = None

    # ========================================================================
    # VALIDATORS
    # ========================================================================

    @field_validator("username")
    @classmethod
    def normalize_username(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize username to lowercase and remove
        surrounding whitespace.
        """

        if value is None:
            return None

        value = value.strip().lower()

        if not value:
            raise ValueError(
                "Username cannot be empty."
            )

        return value

    @field_validator("email")
    @classmethod
    def normalize_email(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize email to lowercase and remove
        surrounding whitespace.

        Email validation is intentionally kept at the
        application level rather than using Pydantic's
        EmailStr because the test and development environment
        legitimately uses reserved .test domains.
        """

        if value is None:
            return None

        value = value.strip().lower()

        if not value:
            return None

        # Basic structural validation.
        #
        # This intentionally does not reject reserved domains
        # such as .test, which are valid for development and
        # automated testing.
        if (
            "@" not in value
            or value.startswith("@")
            or value.endswith("@")
            or value.count("@") != 1
        ):
            raise ValueError(
                "Invalid email address."
            )

        local_part, domain = value.split("@", 1)

        if (
            not local_part
            or not domain
            or domain.startswith(".")
            or domain.endswith(".")
            or ".." in domain
        ):
            raise ValueError(
                "Invalid email address."
            )

        return value

    @field_validator(
        "first_name",
        "last_name",
        "phone_number",
        "bio",
        "address",
        "profile_picture",
    )
    @classmethod
    def normalize_optional_strings(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Trim optional string fields.

        Empty strings are converted to None.
        """

        if value is None:
            return None

        value = value.strip()

        if not value:
            return None

        return value