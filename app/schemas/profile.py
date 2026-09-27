"""
TRACKIT Profile Schemas.

Defines request and response models for authenticated
user profile operations, public user profiles, privacy
settings, and authorized administrative user inspection.

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

Public profile fields are controlled by explicit privacy
settings and never expose arbitrary User model fields.

Administrative account-status fields include:
- role
- active/inactive status
- suspension timestamps
- suspension reason

Administrative email fields include:
- selected recipient user IDs
- email subject
- email message
- delivery results
"""

from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


# ============================================================================
# PROFILE PRIVACY
# ============================================================================


class ProfilePrivacyResponse(BaseModel):
    """
    Effective privacy settings for a user's public profile.

    These settings control which optional profile fields may
    be exposed to other authenticated TRACKIT users.

    Username is intentionally excluded because it is always
    public and is therefore not a user-controlled privacy field.
    """

    profile_picture: bool = True

    bio: bool = True

    first_name: bool = False

    last_name: bool = False

    email: bool = False

    phone_number: bool = False

    social_links: bool = False


# -----------------------------------------------------------------------------


class ProfilePrivacyUpdate(BaseModel):
    """
    Privacy settings that an authenticated user may update.

    PATCH semantics are used:

    - Omitted field = preserve the existing setting.
    - True = make the field public.
    - False = keep the field private.

    Username is intentionally excluded because usernames are
    always public on TRACKIT.
    """

    profile_picture: bool | None = Field(
        default=None,
        description=(
            "Whether the user's profile picture may be shown "
            "on their public profile."
        ),
    )

    bio: bool | None = Field(
        default=None,
        description=(
            "Whether the user's bio may be shown on their "
            "public profile."
        ),
    )

    first_name: bool | None = Field(
        default=None,
        description=(
            "Whether the user's first name may be shown on "
            "their public profile."
        ),
    )

    last_name: bool | None = Field(
        default=None,
        description=(
            "Whether the user's last name may be shown on "
            "their public profile."
        ),
    )

    email: bool | None = Field(
        default=None,
        description=(
            "Whether the user's email address may be shown "
            "on their public profile."
        ),
    )

    phone_number: bool | None = Field(
        default=None,
        description=(
            "Whether the user's phone number may be shown "
            "on their public profile."
        ),
    )

    social_links: bool | None = Field(
        default=None,
        description=(
            "Whether the user's social links may be shown "
            "on their public profile."
        ),
    )


# -----------------------------------------------------------------------------


class PublicProfileResponse(BaseModel):
    """
    Public profile information visible to other authenticated users.

    Username is always public. Optional profile fields are returned
    according to the user's privacy settings.

    Sensitive account, security, address, role, status, and preference
    information is intentionally excluded.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int

    username: str

    profile_picture: str | None = None

    bio: str | None = None

    first_name: str | None = None

    last_name: str | None = None

    email: str | None = None

    phone_number: str | None = None

    social_links: dict[str, object] = Field(
        default_factory=dict
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

    # ------------------------------------------------------------------------
    # SUSPENSION STATUS
    # ------------------------------------------------------------------------

    deactivated_at: datetime | None = None

    deactivated_until: datetime | None = None

    deactivation_reason: str | None = None

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
# MODERATION USER DETAIL RESPONSE
# ============================================================================


class ModerationUserDetailResponse(BaseModel):
    """
    Minimal user representation for moderation inspection.

    This schema is intended for moderator/admin visibility where
    identifying the account and understanding its moderation-relevant
    status are necessary.

    It deliberately excludes private profile and personal-contact
    information such as:

    - first_name
    - last_name
    - email
    - profile_picture
    - phone_number
    - bio
    - address
    - social_links
    - preferences

    It also excludes authentication and security fields such as:

    - password_changed_at
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
    # MODERATION IDENTITY
    # ========================================================================

    id: int

    username: str

    # ========================================================================
    # ACCOUNT STATUS
    # ========================================================================

    role: str

    is_active: bool

    is_verified: bool

    # ------------------------------------------------------------------------
    # DEACTIVATION STATUS
    # ------------------------------------------------------------------------

    deactivated_at: datetime | None = None

    deactivated_until: datetime | None = None

    deactivation_reason: str | None = None


# ============================================================================
# USER SUSPENSION REQUEST
# ============================================================================


class UserSuspensionRequest(BaseModel):
    """
    Request body used by administrators to temporarily
    suspend a user account.

    Duration is expressed in whole hours.

    Business-level duration limits are enforced by the
    user service. API-level validation also rejects values
    that are obviously outside the supported range.
    """

    duration_hours: int = Field(
        ...,
        ge=1,
        le=2160,
        description=(
            "Suspension duration in whole hours. "
            "Minimum: 1 hour. Maximum: 2160 hours (90 days)."
        ),
    )

    reason: str | None = Field(
        default=None,
        max_length=500,
        description=(
            "Optional reason for the suspension."
        ),
    )

    @field_validator("reason")
    @classmethod
    def normalize_reason(
        cls,
        value: str | None,
    ) -> str | None:
        """
        Normalize the optional suspension reason.

        Whitespace-only reasons are treated as no reason.
        """

        if value is None:
            return None

        value = value.strip()

        if not value:
            return None

        return value


# ============================================================================
# ADMIN CUSTOM EMAIL REQUEST
# ============================================================================


class AdminEmailRequest(BaseModel):
    """
    Request body used by administrators to send a custom
    email to selected TRACKIT users.

    Recipients are identified by user ID rather than by
    arbitrary email addresses. The service resolves the
    registered email address from the database.

    A maximum of 50 recipients is allowed per request.

    The admin may include their own account as a recipient.

    Inactive or suspended users are also valid recipients
    because administrative email is separate from account
    authentication and access.
    """

    user_ids: list[int] = Field(
        ...,
        min_length=1,
        max_length=50,
        description=(
            "IDs of the TRACKIT users who should receive the email. "
            "Maximum: 50 recipients."
        ),
    )

    subject: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Email subject.",
    )

    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Email message body.",
    )

    @field_validator("user_ids")
    @classmethod
    def validate_user_ids(
        cls,
        value: list[int],
    ) -> list[int]:
        """
        Validate recipient IDs.

        Recipient IDs must be positive integers and must not
        contain duplicates.
        """

        if any(user_id <= 0 for user_id in value):
            raise ValueError(
                "User IDs must be positive integers."
            )

        if len(value) != len(set(value)):
            raise ValueError(
                "Duplicate user IDs are not allowed."
            )

        return value

    # ------------------------------------------------------------------------

    @field_validator("subject")
    @classmethod
    def normalize_subject(
        cls,
        value: str,
    ) -> str:
        """
        Normalize the email subject.

        Leading and trailing whitespace is removed and an
        empty subject is rejected.
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "Email subject cannot be empty."
            )

        return value

    # ------------------------------------------------------------------------

    @field_validator("message")
    @classmethod
    def normalize_message(
        cls,
        value: str,
    ) -> str:
        """
        Normalize the email message.

        Leading and trailing whitespace is removed and an
        empty message is rejected.
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "Email message cannot be empty."
            )

        return value


# ============================================================================
# ADMIN CUSTOM EMAIL DELIVERY RESULT
# ============================================================================


class AdminEmailDeliveryResult(BaseModel):
    """
    Delivery result for one administrator-email recipient.

    The recipient's email address is deliberately excluded
    from the response because the user ID is sufficient for
    identifying the requested recipient and avoids returning
    unnecessary personal data.
    """

    user_id: int

    success: bool

    error: str | None = None


# ============================================================================
# ADMIN CUSTOM EMAIL RESPONSE
# ============================================================================


class AdminEmailResponse(BaseModel):
    """
    Summary of an administrator custom-email operation.

    A valid request may contain a mixture of successful and
    failed deliveries because each recipient is handled
    independently.
    """

    total: int

    sent: int

    failed: int

    results: list[AdminEmailDeliveryResult]


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
