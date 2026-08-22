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

    DATABASE_URL: str

    # ========================================================================
    # JWT Authentication
    # ========================================================================

    SECRET_KEY: str

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
    # CORS
    # ========================================================================

    """
    Allowed frontend origins.

    Development default:
        http://localhost:5500

    In production, this should be explicitly configured
    through the environment.
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

    Development/test:
    -localhost
    -127.0.0.1
    -testserver

    Production deployments should explicitly configure
    the real API hostname through the environment.
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

    CONTENT_SECURITY_POLICY: str = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
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
    # Pydantic Settings Configuration
    # ========================================================================

        # ========================================================================
    # Email / SMTP
    # ========================================================================

    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587

    SMTP_USERNAME: str
    SMTP_PASSWORD: str

    SMTP_FROM_EMAIL: str
    SMTP_FROM_NAME: str = "TRACKIT"

    SMTP_USE_TLS: bool = True

    # Frontend URL used in verification/password-reset links.
    FRONTEND_URL: str = "http://localhost:5500"

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