"""
Site-wide settings endpoints.
GET  /api/v1/settings  — public, returns current effective settings
PATCH /api/v1/settings — open when auth disabled; admin-only when auth enabled
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_current_user
from app.api.schemas import SiteSettingsUpdate
from app.config import save_overrides, settings
from app.db.models import User

router = APIRouter(prefix="/settings", tags=["settings"])


def _site_settings_response() -> dict:
    return {
        "auth_enabled": settings.AUTH_ENABLED,
        "history_enabled": settings.HISTORY_ENABLED,
        "vuln_check_enabled": settings.VULN_CHECK_ENABLED,
    }


@router.get("")
async def get_site_settings() -> dict:
    """Return the current effective platform settings."""
    return _site_settings_response()


@router.patch("")
async def update_site_settings(
    body: SiteSettingsUpdate,
    current_user: Optional[User] = Depends(get_current_user),
) -> dict:
    """
    Update platform settings.
    When auth is disabled: open to anyone.
    When auth is enabled: admin-only.
    """
    if settings.AUTH_ENABLED:
        if current_user is None or not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required to change platform settings",
            )

    updates: dict = {}

    if body.auth_enabled is not None:
        settings.AUTH_ENABLED = body.auth_enabled
        updates["AUTH_ENABLED"] = body.auth_enabled

    if body.history_enabled is not None:
        settings.HISTORY_ENABLED = body.history_enabled
        updates["HISTORY_ENABLED"] = body.history_enabled

    if body.vuln_check_enabled is not None:
        settings.VULN_CHECK_ENABLED = body.vuln_check_enabled
        updates["VULN_CHECK_ENABLED"] = body.vuln_check_enabled

    if updates:
        save_overrides(updates)

    return _site_settings_response()
