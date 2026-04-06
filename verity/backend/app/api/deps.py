"""
FastAPI dependency functions for Verity.
Handles database sessions, authentication, and workspace validation.
"""

from typing import AsyncGenerator, Optional

from fastapi import Depends, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import verify_token
from app.config import settings
from app.db.models import User, Workspace, WorkspaceMember
from app.db.session import get_db


# Re-export get_db so callers can import from deps
__all__ = ["get_db", "get_current_user", "require_auth", "optional_workspace"]


async def get_current_user(
    authorization: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """
    Extract and validate the current user from the Authorization header.

    When AUTH_ENABLED=False, always returns None without checking the token.
    When AUTH_ENABLED=True, validates the Bearer JWT and loads the user from DB.

    Raises:
        HTTPException 401: If AUTH_ENABLED=True and the token is missing or invalid.
        HTTPException 401: If AUTH_ENABLED=True and the user does not exist or is inactive.
    """
    if not settings.AUTH_ENABLED:
        return None

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header with Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:]  # Strip "Bearer " prefix
    payload = verify_token(token)

    user_id: Optional[str] = payload.get("sub")
    token_type: Optional[str] = payload.get("type")

    if not user_id or token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type or missing subject claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def require_auth(
    current_user: Optional[User] = Depends(get_current_user),
) -> Optional[User]:
    """
    Raise HTTP 403 if AUTH_ENABLED=True and no authenticated user is present.
    Returns the user (or None if auth is disabled).
    """
    if settings.AUTH_ENABLED and current_user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication is required for this endpoint",
        )
    return current_user


async def optional_workspace(
    workspace_id: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> Optional[Workspace]:
    """
    If workspace_id is provided as a query parameter, validate it exists.

    When AUTH_ENABLED=True, also verifies the current user is a member.
    Returns the Workspace object or None if no workspace_id was given.

    Raises:
        HTTPException 404: If the workspace does not exist.
        HTTPException 403: If AUTH_ENABLED=True and the user is not a member.
    """
    if not workspace_id:
        return None

    result = await db.execute(
        select(Workspace).where(Workspace.id == workspace_id)
    )
    workspace = result.scalar_one_or_none()

    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace '{workspace_id}' not found",
        )

    if settings.AUTH_ENABLED and current_user is not None:
        member_result = await db.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == current_user.id,
            )
        )
        member = member_result.scalar_one_or_none()
        if member is None and workspace.owner_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not a member of this workspace",
            )

    return workspace
