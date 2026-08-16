"""
TRACKIT Authentication Schemas.

Pydantic schemas used for:

- User registration
- User login
- Admin login
- Email verification
- Verification-token resend
- Forgot-password requests
- Password reset
- JWT token responses
- Authenticated-user responses

Security principles:

- Strict input validation
- Normalized usernames and emails
- Sensitive authentication values are accepted through
  validated request bodies rather than URL query parameters
- Passwords are never returned
- Authentication responses do not expose sensitive information
"""

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
)

from app.core.security import validate_password_strength


# ============================================================================
# USER REGISTRATION
# ============================================================================


class UserRegisterRequest(BaseModel):
    """
    Request body for creating a TRACKIT user account.
    """

    username: str = Field(
        min_length=3,
        max_length=50,
    )

    first_name: str = Field(
        min_length=1,
        max_length=100,
    )

    last_name: str = Field(
        min_length=1,
        max_length=100,
    )

    email: EmailStr

    password: str = Field(
        min_length=8,
        max_length=128,
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        """
        Validate and normalize TRACKIT usernames.

        Rules:

        - 3-50 characters
        - must start with a letter
        - letters, numbers, underscores, and hyphens only
        - cannot be an email address
        - stored in lowercase
        """

        value = value.strip()

        if not value:
            raise ValueError("Username is required.")

        if "@" in value:
            raise ValueError(
                "Username cannot be an email address."
            )

        if not value[0].isalpha():
            raise ValueError(
                "Username must start with a letter."
            )

        if not all(
            character.isalnum() or character in "_-"
            for character in value
        ):
            raise ValueError(
                "Username may contain only letters, "
                "numbers, underscores, and hyphens."
            )

        return value.lower()

    @field_validator("first_name", "last_name")
    @classmethod
    def validate_names(cls, value: str) -> str:
        """
        Normalize personal names.
        """

        value = " ".join(
            value.strip().split()
        )

        if not value:
            raise ValueError(
                "Name is required."
            )

        return value

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """
        Normalize email addresses before Pydantic validation.
        """

        return str(value).strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        """
        Apply TRACKIT password-strength requirements.
        """

        validate_password_strength(value)

        return value


# ============================================================================
# USER LOGIN
# ============================================================================


class UserLoginRequest(BaseModel):
    """
    Request body for normal TRACKIT user login.

    Users may authenticate using either:

    - username
    - email
    """

    identifier: str = Field(
        min_length=3,
        max_length=255,
    )

    password: str = Field(
        min_length=1,
        max_length=128,
    )

    @field_validator("identifier")
    @classmethod
    def normalize_identifier(cls, value: str) -> str:
        """
        Normalize the login identifier.
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "Username or email is required."
            )

        return value.lower()


# ============================================================================
# ADMIN LOGIN
# ============================================================================


class AdminLoginRequest(BaseModel):
    """
    Request body for administrator authentication.

    Admin authentication is deliberately separated from
    normal user authentication at the API level.
    """

    identifier: str = Field(
        min_length=3,
        max_length=255,
    )

    password: str = Field(
        min_length=1,
        max_length=128,
    )

    @field_validator("identifier")
    @classmethod
    def normalize_identifier(cls, value: str) -> str:
        """
        Normalize the administrator login identifier.
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "Administrator username or email is required."
            )

        return value.lower()


# ============================================================================
# EMAIL VERIFICATION
# ============================================================================


class VerifyEmailRequest(BaseModel):
    """
    Request body for email verification.

    The verification token is deliberately placed in the
    request body rather than the URL query string.
    """

    token: str = Field(
        min_length=1,
        max_length=512,
    )

    @field_validator("token")
    @classmethod
    def normalize_token(cls, value: str) -> str:
        """
        Normalize the supplied verification token.
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "Verification token is required."
            )

        return value


# ============================================================================
# RESEND VERIFICATION
# ============================================================================


class ResendVerificationRequest(BaseModel):
    """
    Request body for requesting a new email-verification token.
    """

    email: EmailStr

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """
        Normalize the supplied email address.
        """

        return str(value).strip().lower()


# ============================================================================
# FORGOT PASSWORD
# ============================================================================


class ForgotPasswordRequest(BaseModel):
    """
    Request body for starting the password-reset process.

    The endpoint always returns a generic response regardless
    of whether the supplied email exists.
    """

    email: EmailStr

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """
        Normalize the supplied email address.
        """

        return str(value).strip().lower()


# ============================================================================
# RESET PASSWORD
# ============================================================================


class ResetPasswordRequest(BaseModel):
    """
    Request body for resetting a password.

    Both the reset token and new password remain in the
    request body and are therefore not exposed through
    URL query parameters.
    """

    token: str = Field(
        min_length=1,
        max_length=512,
    )

    new_password: str = Field(
        min_length=8,
        max_length=128,
    )

    @field_validator("token")
    @classmethod
    def normalize_token(cls, value: str) -> str:
        """
        Normalize the password-reset token.
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "Password reset token is required."
            )

        return value

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        """
        Apply TRACKIT password-strength requirements
        to the new password.
        """

        validate_password_strength(value)

        return value


# ============================================================================
# TOKEN RESPONSE
# ============================================================================


class TokenResponse(BaseModel):
    """
    JWT authentication response.
    """

    access_token: str

    token_type: str = "bearer"


# ============================================================================
# AUTHENTICATED USER RESPONSE
# ============================================================================


class AuthenticatedUserResponse(BaseModel):
    """
    Safe representation of the authenticated user.

    Password hashes, JWTs, reset tokens, verification tokens,
    and other sensitive security information are deliberately
    excluded.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    username: str
    first_name: str
    last_name: str
    email: EmailStr
    role: str
    is_active: bool
    is_verified: bool