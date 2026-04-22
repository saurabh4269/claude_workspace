"""
Verity configuration module.
All settings can be overridden via environment variables or a .env file.
Runtime overrides (from the UI) are persisted to SITE_SETTINGS_PATH.
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

from pydantic_settings import BaseSettings, SettingsConfigDict

_OVERRIDE_KEYS = {"AUTH_ENABLED", "HISTORY_ENABLED", "VULN_CHECK_ENABLED"}


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
    NVD_API_KEY: Optional[str] = None
    # Set NVD_ENABLED=true plus NVD_API_KEY to enable CVSS enrichment from NVD
    nvd_enabled: bool = False

    # Upload limits
    MAX_UPLOAD_SIZE_MB: int = 50

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Path where UI-driven setting overrides are persisted
    SITE_SETTINGS_PATH: str = "/app/data/site_settings.json"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)


# Singleton instance used throughout the application
settings = Settings()


def _override_path() -> Path:
    return Path(settings.SITE_SETTINGS_PATH)


def load_overrides() -> None:
    """Apply persisted UI overrides on top of env-var settings."""
    p = _override_path()
    if not p.exists():
        return
    try:
        data: dict = json.loads(p.read_text())
        for key, value in data.items():
            if key in _OVERRIDE_KEYS and hasattr(settings, key):
                setattr(settings, key, value)
    except Exception as exc:
        logger.error("Failed to load site settings overrides from %s: %s", p, exc)


def save_overrides(updates: dict) -> None:
    """Persist a set of key→value overrides so they survive restarts."""
    p = _override_path()
    existing: dict = {}
    if p.exists():
        try:
            existing = json.loads(p.read_text())
        except Exception as exc:
            logger.warning("Could not read existing overrides from %s, overwriting: %s", p, exc)
    existing.update(updates)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps(existing))
    except Exception as exc:
        logger.error("Failed to persist site settings overrides to %s: %s", p, exc)
        raise
