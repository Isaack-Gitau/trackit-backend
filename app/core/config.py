"""
TRACKIT Application Configuration

Centralized configuration for the TRACKIT backend.

All sensitive values should be stored in the .env file.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    TRACKIT application settings.

    Values are loaded from environment variables and .env.
    """

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    APP_NAME: str = "TRACKIT"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    API_V1_PREFIX: str = "/api/v1"

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    DATABASE_URL: str

    # ------------------------------------------------------------------
    # JWT Authentication
    # ------------------------------------------------------------------

    SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # ------------------------------------------------------------------
    # Pydantic Settings Configuration
    # ------------------------------------------------------------------

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# ----------------------------------------------------------------------
# Global Settings Instance
# ----------------------------------------------------------------------

settings = Settings()