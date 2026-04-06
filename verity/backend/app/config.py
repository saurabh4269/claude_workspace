"""
Verity configuration module.
All settings can be overridden via environment variables or a .env file.
"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./verity.db"

    # Security - change SECRET_KEY in production via environment variable
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Feature flags
    AUTH_ENABLED: bool = False
    HISTORY_ENABLED: bool = True
    VULN_CHECK_ENABLED: bool = True

    # External APIs
    OSV_API_URL: str = "https://api.osv.dev/v1"
    # NVD enrichment is only enabled when NVD_API_KEY is set
    NVD_API_KEY: Optional[str] = None

    # Upload limits
    MAX_UPLOAD_SIZE_MB: int = 50

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)


# Singleton instance used throughout the application
settings = Settings()
