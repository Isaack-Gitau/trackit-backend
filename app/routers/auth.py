
"""
TRACKIT Authentication Router.

Authentication endpoints for:

- User registration
- User login
- Current-user information
- Email verification
- Resending verification tokens
- Forgot-password requests
- Password reset

Security principles:

- Strict Pydantic validation is applied before service logic.
- Passwords are never returned.
- Authentication failures use safe responses.
- Verification/reset requests do not reveal account existence.
- Raw authentication tokens are never stored in PostgreSQL.
- Authentication tokens are short-lived and single-use.
- JWT authentication is handled through API dependencies.
- Authentication endpoints are rate limited by client IP.
- Rate-limit responses include Retry-After information.
"""

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.rate_limit import check_rate_limit
from app.db.dependencies import get_db
from app.models.user import User

from app.schemas.auth import (
    AuthenticatedUserResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    ResendVerificationRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    VerifyEmailRequest,
)

from app.services.auth import (
    login_user,
    register_user,
)

from app.services.email_verification import (
    create_verification_token,
    verify_email,
)

from app.services.password_reset import (
    create_password_reset_token,
    reset_user_password,
)

from app.services.user import (
    get_user_by_email_service,
)


# ============================================================================
# ROUTER
# ============================================================================

router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"],
)


# ============================================================================
# RATE LIMITING
# ============================================================================


def _get_client_ip(
    request: Request,
) -> str:
    """
    Return the client IP address used for rate limiting.

    For the current development/single-instance deployment,
    FastAPI's request.client address is used.

    IMPORTANT SECURITY NOTE:

    X-Forwarded-For and similar proxy headers are intentionally
    NOT trusted here.

    When TRACKIT is deployed behind a reverse proxy, trusted
    proxy configuration should be introduced explicitly.
    """

    if request.client is None:
        return "unknown"

    client_host = request.client.host.strip()

    if not client_host:
        return "unknown"

    return client_host


def _enforce_rate_limit(
    *,
    request: Request,
    bucket: str,
    max_attempts: int,
    window_seconds: int,
) -> None:
    """
    Enforce an IP-based rate limit.

    Each authentication operation receives its own bucket.

    Examples:

        register:127.0.0.1
        login:127.0.0.1
        verify-email:127.0.0.1
        resend-verification:127.0.0.1
        forgot-password:127.0.0.1
        reset-password:127.0.0.1

    Raises:
        HTTPException:
            HTTP 429 when the configured limit is exceeded.
    """

    client_ip = _get_client_ip(request)

    key = f"{bucket}:{client_ip}"

    result = check_rate_limit(
        key=key,
        max_attempts=max_attempts,
        window_seconds=window_seconds,
    )

    if result.allowed:
        return

    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=(
            "Too many requests. "
            "Please try again later."
        ),
        headers={
            "Retry-After": str(
                result.retry_after
            ),
        },
    )


# ============================================================================
# REGISTRATION
# ============================================================================


@router.post(
    "/register",
    response_model=AuthenticatedUserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
def register(
    data: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AuthenticatedUserResponse:
    """
    Register a new TRACKIT user account.

    Newly registered users:

    - are active
    - are unverified
    - cannot log in until email verification
    - receive a short-lived verification token

    Registration is rate limited by client IP.
    """

    # ------------------------------------------------------------------
    # Rate limit
    # ------------------------------------------------------------------

    _enforce_rate_limit(
        request=request,
        bucket="register",
        max_attempts=settings.REGISTER_RATE_LIMIT_ATTEMPTS,
        window_seconds=(
            settings.REGISTER_RATE_LIMIT_WINDOW_SECONDS
        ),
    )

    # ------------------------------------------------------------------
    # Create account
    # ------------------------------------------------------------------

    try:
        user = register_user(
            db,
            username=data.username,
            first_name=data.first_name,
            last_name=data.last_name,
            email=str(data.email),
            password=data.password,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Username or email is already registered."
            ),
        ) from None

    # ------------------------------------------------------------------
    # Create email verification token
    # ------------------------------------------------------------------

    create_verification_token(
        db,
        user,
    )

    # ------------------------------------------------------------------
    # Response
    # ------------------------------------------------------------------

    return AuthenticatedUserResponse.model_validate(
        user
    )


# ============================================================================
# USER LOGIN
# ============================================================================


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate a user",
)
def login(
    data: UserLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate a TRACKIT user.

    Login requires:

    - valid username or email
    - valid password
    - active account
    - verified email

    Login attempts are rate limited by client IP.

    Authentication failures intentionally use a generic
    response so the endpoint does not reveal sensitive
    account information.
    """

    # ------------------------------------------------------------------
    # Rate limit
    # ------------------------------------------------------------------

    _enforce_rate_limit(
        request=request,
        bucket="login",
        max_attempts=settings.LOGIN_RATE_LIMIT_ATTEMPTS,
        window_seconds=(
            settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS
        ),
    )

    # ------------------------------------------------------------------
    # Authenticate
    # ------------------------------------------------------------------

    result = login_user(
        db,
        login=data.identifier,
        password=data.password,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Invalid credentials or account "
                "not eligible for login."
            ),
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    access_token, _user = result

    # ------------------------------------------------------------------
    # Token response
    # ------------------------------------------------------------------

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
    )


# ============================================================================
# CURRENT USER
# ============================================================================


@router.get(
    "/me",
    response_model=AuthenticatedUserResponse,
    summary="Get the authenticated user",
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> AuthenticatedUserResponse:
    """
    Return the currently authenticated TRACKIT user.

    Requires:

    - valid Bearer JWT
    - active account
    - matching token_version
    """

    return AuthenticatedUserResponse.model_validate(
        current_user
    )


# ============================================================================
# EMAIL VERIFICATION
# ============================================================================


@router.post(
    "/verify-email",
    response_model=AuthenticatedUserResponse,
    summary="Verify an email address",
)
def verify_email_endpoint(
    data: VerifyEmailRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AuthenticatedUserResponse:
    """
    Verify a TRACKIT email address using a valid,
    single-use verification token.

    Verification attempts are rate limited by client IP.
    """

    # ------------------------------------------------------------------
    # Rate limit
    # ------------------------------------------------------------------

    _enforce_rate_limit(
        request=request,
        bucket="verify-email",
        max_attempts=(
            settings.VERIFICATION_RATE_LIMIT_ATTEMPTS
        ),
        window_seconds=(
            settings.VERIFICATION_RATE_LIMIT_WINDOW_SECONDS
        ),
    )

    # ------------------------------------------------------------------
    # Verify token
    # ------------------------------------------------------------------

    user = verify_email(
        db,
        data.token,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid or expired verification token."
            ),
        )

    # ------------------------------------------------------------------
    # Response
    # ------------------------------------------------------------------

    return AuthenticatedUserResponse.model_validate(
        user
    )


# ============================================================================
# RESEND VERIFICATION
# ============================================================================


@router.post(
    "/resend-verification",
    summary="Resend an email verification token",
)
def resend_verification(
    data: ResendVerificationRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """
    Request a new email verification token.

    The response is intentionally identical whether
    or not the account exists.

    This prevents account enumeration.

    Resend requests are rate limited by client IP.
    """

    # ------------------------------------------------------------------
    # Rate limit
    # ------------------------------------------------------------------

    _enforce_rate_limit(
        request=request,
        bucket="resend-verification",
        max_attempts=(
            settings.VERIFICATION_RATE_LIMIT_ATTEMPTS
        ),
        window_seconds=(
            settings.VERIFICATION_RATE_LIMIT_WINDOW_SECONDS
        ),
    )

    # ------------------------------------------------------------------
    # Generic response
    # ------------------------------------------------------------------

    generic_message = (
        "If an account exists for this email, "
        "a verification message has been sent."
    )

    # ------------------------------------------------------------------
    # Find account
    # ------------------------------------------------------------------

    user = get_user_by_email_service(
        db,
        data.email,
    )

    # ------------------------------------------------------------------
    # Do not reveal account existence
    # ------------------------------------------------------------------

    if user is None:
        return {
            "message": generic_message,
        }

    if user.is_verified:
        return {
            "message": generic_message,
        }

    if not user.is_active:
        return {
            "message": generic_message,
        }

    # ------------------------------------------------------------------
    # Create replacement verification token
    # ------------------------------------------------------------------

    create_verification_token(
        db,
        user,
    )

    return {
        "message": generic_message,
    }


# ============================================================================
# FORGOT PASSWORD
# ============================================================================


@router.post(
    "/forgot-password",
    summary="Request a password reset",
)
def forgot_password(
    data: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """
    Start the TRACKIT password-reset process.

    The response never reveals whether an account
    exists for the supplied email.

    Requests are rate limited by client IP.
    """

    # ------------------------------------------------------------------
    # Rate limit
    # ------------------------------------------------------------------

    _enforce_rate_limit(
        request=request,
        bucket="forgot-password",
        max_attempts=(
            settings.PASSWORD_RESET_RATE_LIMIT_ATTEMPTS
        ),
        window_seconds=(
            settings.PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS
        ),
    )

    # ------------------------------------------------------------------
    # Generic response
    # ------------------------------------------------------------------

    generic_message = (
        "If an account exists for this email, "
        "a password reset message has been sent."
    )

    # ------------------------------------------------------------------
    # Find account
    # ------------------------------------------------------------------

    user = get_user_by_email_service(
        db,
        data.email,
    )

    # ------------------------------------------------------------------
    # Do not reveal account existence
    # ------------------------------------------------------------------

    if user is None:
        return {
            "message": generic_message,
        }

    if not user.is_active:
        return {
            "message": generic_message,
        }

    # ------------------------------------------------------------------
    # Create password-reset token
    # ------------------------------------------------------------------

    create_password_reset_token(
        db,
        user,
    )

    return {
        "message": generic_message,
    }


# ============================================================================
# PASSWORD RESET
# ============================================================================


@router.post(
    "/reset-password",
    summary="Reset a user password",
)
def reset_password(
    data: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """
    Reset a user's password using a valid,
    single-use password-reset token.

    Successful reset:

    - changes the password
    - updates password_changed_at
    - increments token_version
    - invalidates existing JWT sessions
    - consumes the reset token
    - invalidates other unused reset tokens

    Reset attempts are rate limited by client IP.
    """

    # ------------------------------------------------------------------
    # Rate limit
    # ------------------------------------------------------------------

    _enforce_rate_limit(
        request=request,
        bucket="reset-password",
        max_attempts=(
            settings.PASSWORD_RESET_RATE_LIMIT_ATTEMPTS
        ),
        window_seconds=(
            settings.PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS
        ),
    )

    # ------------------------------------------------------------------
    # Reset password
    # ------------------------------------------------------------------

    try:
        user = reset_user_password(
            db,
            raw_token=data.token,
            new_password=data.new_password,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    # ------------------------------------------------------------------
    # Invalid or expired token
    # ------------------------------------------------------------------

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid or expired password reset token."
            ),
        )

    # ------------------------------------------------------------------
    # Success
    # ------------------------------------------------------------------

    return {
        "message": (
            "Password reset successfully. "
            "You may now log in with your new password."
        ),
    }
