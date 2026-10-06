"""
TRACKIT Application Configuration.

Centralized configuration for the TRACKIT backend.

Sensitive values must be supplied through environment
variables or the local .env file.

Never commit .env to version control.
"""

from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


class Settings(BaseSettings):
    """
    TRACKIT application settings.
    """

    # ========================================================================
    # Application
    # ========================================================================

    APP_NAME: str = "TRACKIT"

    ENVIRONMENT: str = "development"

    DEBUG: bool = True

    API_V1_PREFIX: str = "/api/v1"

    # ========================================================================
    # Database
    # ========================================================================

    # Supplied through DATABASE_URL environment variable or .env.
    # Empty default exists only to satisfy static type checking.
    DATABASE_URL: str = ""

    # ========================================================================
    # JWT Authentication
    # ========================================================================

    # Supplied through SECRET_KEY environment variable or .env.
    # Never use a real secret as a source-code default.
    SECRET_KEY: str = ""

    JWT_ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # ========================================================================
    # Authentication Rate Limiting
    # ========================================================================

    # ------------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------------

    LOGIN_RATE_LIMIT_ATTEMPTS: int = 5

    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 300

    # ------------------------------------------------------------------------
    # Password Reset
    # ------------------------------------------------------------------------

    PASSWORD_RESET_RATE_LIMIT_ATTEMPTS: int = 3

    PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS: int = 900

    # ------------------------------------------------------------------------
    # Email Verification
    # ------------------------------------------------------------------------

    VERIFICATION_RATE_LIMIT_ATTEMPTS: int = 3

    VERIFICATION_RATE_LIMIT_WINDOW_SECONDS: int = 900

    # ------------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------------

    REGISTER_RATE_LIMIT_ATTEMPTS: int = 5

    REGISTER_RATE_LIMIT_WINDOW_SECONDS: int = 900

    # ========================================================================
    # Administrator Bootstrap Rate Limiting
    # ========================================================================

    ADMIN_BOOTSTRAP_RATE_LIMIT_ATTEMPTS: int = 3
    ADMIN_BOOTSTRAP_RATE_LIMIT_WINDOW_SECONDS: int = 900

    # ========================================================================
    # Media / Image Uploads
    # ========================================================================

    """
    Configuration for user-uploaded media.

    Uploaded files are stored outside the application package
    under the configured MEDIA_ROOT.

    Development default:
        storage/media

    Production:
        MEDIA_ROOT should be configured through the environment
        or deployment configuration.
    """

    MEDIA_ROOT: str = "storage/media"

    """
    Public URL prefix used when serving approved media files.

    Example:

        /media/items/<generated-file-name>.jpg
    """

    MEDIA_URL: str = "/media"

    """
    Storage backend used for uploaded media.

    Development and tests use the local filesystem.
    Production can use an S3-compatible object store such as
    Cloudflare R2.
    """

    STORAGE_BACKEND: str = "local"

    """
    Cloudflare R2 / S3-compatible storage configuration.

    These values must be supplied through environment variables
    in production. Never commit credentials to source control.
    """

    R2_ACCOUNT_ID: str = ""

    R2_ACCESS_KEY_ID: str = ""

    R2_SECRET_ACCESS_KEY: str = ""

    R2_BUCKET_NAME: str = ""

    R2_PUBLIC_BASE_URL: str = ""

    CLOUDINARY_CLOUD_NAME: str = ""
    CLOUDINARY_API_KEY: str = ""
    CLOUDINARY_API_SECRET: str = ""

    """
    Maximum accepted image upload size.

    Default:
        5 MiB

    The upload implementation must enforce this limit while
    reading the request body rather than trusting Content-Length.
    """

    IMAGE_MAX_SIZE_BYTES: int = 5 * 1024 * 1024

    """
    Maximum decoded image dimensions.

    These limits protect the application from excessively large
    images and memory-intensive image processing.
    """

    IMAGE_MAX_WIDTH: int = 4096

    IMAGE_MAX_HEIGHT: int = 4096

    """
    Maximum total number of decoded pixels.

    Default:
        16 megapixels

    This is an additional protection against decompression-bomb
    style payloads.
    """

    IMAGE_MAX_PIXELS: int = 16 * 1024 * 1024

    """
    Formats accepted by the image-upload service.

    Only formats that can be safely decoded and re-encoded by
    Pillow should be accepted.

    SVG is intentionally excluded because it can contain active
    content and should not be treated as an ordinary image upload.
    """

    IMAGE_ALLOWED_FORMATS: str = "JPEG,PNG,WEBP"

    # ========================================================================
    # CORS
    # ========================================================================

    """
    Allowed browser origins.

    Development default:
        http://localhost:5500

    Production:
        Must be explicitly configured through the environment.

    Multiple origins may be supplied as a comma-separated value:

        CORS_ALLOWED_ORIGINS=https://trackit.example,https://www.trackit.example
    """

    CORS_ALLOWED_ORIGINS: str = (
        "http://localhost:5500"
    )

    CORS_ALLOW_CREDENTIALS: bool = True

    # ========================================================================
    # Trusted Hosts
    # ========================================================================

    """
    Allowed HTTP Host headers.

    Development/test defaults:

        localhost
        127.0.0.1
        testserver

    Production:
        Must be explicitly configured through the environment.

    Multiple hosts may be supplied as a comma-separated value:

        TRUSTED_HOSTS=api.trackit.example,trackit.example
    """

    TRUSTED_HOSTS: str = (
        "localhost,"
        "127.0.0.1,"
        "testserver"
    )

    # ========================================================================
    # Security Headers
    # ========================================================================

    SECURITY_HEADERS_ENABLED: bool = True

    """
    Enable HTTP Strict Transport Security.

    This should only be enabled when TRACKIT is served over HTTPS.

    Development:
        false

    Production:
        true
    """

    HSTS_ENABLED: bool = False

    HSTS_MAX_AGE: int = 31536000

    HSTS_INCLUDE_SUBDOMAINS: bool = True

    HSTS_PRELOAD: bool = False

    CONTENT_SECURITY_POLICY: str = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' data: https://fastapi.tiangolo.com https://res.cloudinary.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    REFERRER_POLICY: str = (
        "strict-origin-when-cross-origin"
    )

    PERMISSIONS_POLICY: str = (
        "camera=(), "
        "microphone=(), "
        "geolocation=()"
    )

    # ========================================================================
    # Initial Administrator Bootstrap
    # ========================================================================

    """
    One-time bootstrap configuration used to create the first
    administrator account.

    The bootstrap secret must be supplied through the deployment
    environment and must never be committed to source control.

    The bootstrap username is intentionally fixed server-side so
    the bootstrap endpoint cannot be used to elevate an arbitrary
    account.
    """

    ADMIN_BOOTSTRAP_SECRET: str = ""

    ADMIN_BOOTSTRAP_USERNAME: str = ""

    # ========================================================================
    # Email / Resend
    # ========================================================================

    # Supplied through RESEND_API_KEY environment variable or .env.
    # Never use a real API key as a source-code default.
    RESEND_API_KEY: str = ""

    # Resend's testing sender is used for the current portfolio deployment.
    # A verified custom domain can replace this later.
    RESEND_FROM_EMAIL: str = "onboarding@resend.dev"

    RESEND_FROM_NAME: str = "TRACKIT"

    # ------------------------------------------------------------------------
    # Frontend
    # ------------------------------------------------------------------------

    FRONTEND_URL: str = (
        "http://localhost:5500"
    )

    # ========================================================================
    # Rate-Limit Storage
    # ========================================================================

    """
    Rate-limit storage backend.

    Development:
        memory or redis

    Production:
        redis
    """

    RATE_LIMIT_BACKEND: str = "memory"

    """
    Redis connection URL.

    Development example:

        redis://localhost:6379/0

    Production:
        Set through the environment/secrets manager.
    """

    REDIS_URL: str = (
        "redis://localhost:6379/0"
    )

    """
    Fail closed when the configured production rate-limit
    backend is unavailable.

    When enabled, protected authentication requests must not
    silently bypass rate limiting if Redis becomes unavailable.
    """

    RATE_LIMIT_FAIL_CLOSED: bool = True

    # ========================================================================
    # Pydantic Settings Configuration
    # ========================================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# ============================================================================
# Global Settings Instance
# ============================================================================

settings = Settings()
