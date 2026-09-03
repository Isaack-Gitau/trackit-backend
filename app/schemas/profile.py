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

    Important PATCH semantics:

    - Omitted field = do not change the existing value.
    - Explicit null = clear the value when the database field
      is nullable.
    """

    username: str | None = Field(
        default=None,
        min_length=3,
        max_length=50,
    )

    email: str | None = Field(
        default=None,
        max_length=255,
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
    # REQUIRED STRING FIELDS
    # ========================================================================

    @field_validator("username")
    @classmethod
    def normalize_username(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize username.

        A missing username is allowed because this is PATCH.
        An explicitly supplied null username is rejected.
        """

        if value is None:
            raise ValueError(
                "Username cannot be null."
            )

        value = value.strip().lower()

        if not value:
            raise ValueError(
                "Username cannot be empty."
            )

        return value

    # ------------------------------------------------------------------------

    @field_validator("email")
    @classmethod
    def normalize_email(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize and validate email.

        A missing email is allowed because this is PATCH.
        An explicitly supplied null or empty email is rejected.

        Email validation intentionally remains application-level
        rather than using Pydantic EmailStr because the test and
        development environment legitimately uses reserved .test
        domains.
        """

        if value is None:
            raise ValueError(
                "Email cannot be null."
            )

        value = value.strip().lower()

        if not value:
            raise ValueError(
                "Email cannot be empty."
            )

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

    # ------------------------------------------------------------------------

    @field_validator("first_name")
    @classmethod
    def normalize_first_name(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize first name.

        Explicit null and empty values are rejected because
        first_name is non-nullable in the database.
        """

        if value is None:
            raise ValueError(
                "First name cannot be null."
            )

        value = value.strip()

        if not value:
            raise ValueError(
                "First name cannot be empty."
            )

        return value

    # ------------------------------------------------------------------------

    @field_validator("last_name")
    @classmethod
    def normalize_last_name(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize last name.

        Explicit null and empty values are rejected because
        last_name is non-nullable in the database.
        """

        if value is None:
            raise ValueError(
                "Last name cannot be null."
            )

        value = value.strip()

        if not value:
            raise ValueError(
                "Last name cannot be empty."
            )

        return value

    # ========================================================================
    # NULLABLE STRING FIELDS
    # ========================================================================

    @field_validator(
        "profile_picture",
        "phone_number",
        "bio",
        "address",
    )
    @classmethod
    def normalize_nullable_strings(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize nullable profile strings.

        Explicit null clears the database value.

        Empty strings are also treated as clear operations and
        therefore become None.
        """

        if value is None:
            return None

        value = value.strip()

        if not value:
            return None

        return value

    # ========================================================================
    # NON-NULL JSON FIELDS
    # ========================================================================

    @field_validator("social_links")
    @classmethod
    def validate_social_links(
        cls,
        value: dict[str, object] | None,
    ) -> dict[str, object] | None:
        """
        Validate social_links.

        The database column is non-nullable, so explicit null
        is rejected.
        """

        if value is None:
            raise ValueError(
                "Social links cannot be null."
            )

        return value

    # ------------------------------------------------------------------------

    @field_validator("preferences")
    @classmethod
    def validate_preferences(
        cls,
        value: dict[str, object] | None,
    ) -> dict[str, object] | None:
        """
        Validate preferences.

        The database column is non-nullable, so explicit null
        is rejected.
        """

        if value is None:
            raise ValueError(
                "Preferences cannot be null."
            )

        return value