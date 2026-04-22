"""
Authentication routes for Verity.
All endpoints return HTTP 501 when AUTH_ENABLED=False.
"""

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.api.schemas import (
    ChangePasswordRequest,
    InviteCreate,
    TokenOut,
    TokenRefresh,
    UserCreate,
    UserLogin,
    UserOut,
)
from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    verify_token,
)
from app.config import settings
from app.db.models import User, Workspace, WorkspaceInvite, WorkspaceMember

router = APIRouter(prefix="/auth", tags=["auth"])


def _require_auth_enabled() -> None:
    """Raise 501 if authentication is not enabled in configuration."""
    if not settings.AUTH_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "Authentication is not enabled. "
                "Set AUTH_ENABLED=true in your configuration to use this endpoint."
            ),
        )


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Register a new user account."""
    _require_auth_enabled()

    # Check for duplicate email
    result = await db.execute(select(User).where(User.email == body.email))
    existing = result.scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists",
        )

    user = User(
        id=str(uuid.uuid4()),
        email=body.email,
        hashed_password=get_password_hash(body.password),
        is_active=True,
        is_admin=False,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return UserOut.model_validate(user)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenOut)
async def login(
    body: UserLogin,
    db: AsyncSession = Depends(get_db),
) -> TokenOut:
    """Authenticate with email and password, returning access and refresh tokens."""
    _require_auth_enabled()

    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    # Use constant-time comparison to avoid timing attacks
    if user is None or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = {"sub": user.id}
    return TokenOut(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
    )


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

@router.post("/refresh", response_model=TokenOut)
async def refresh_token(
    body: TokenRefresh,
    db: AsyncSession = Depends(get_db),
) -> TokenOut:
    """Exchange a valid refresh token for a new token pair."""
    _require_auth_enabled()

    payload = verify_token(body.refresh_token, expected_type="refresh")
    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account is inactive",
        )

    token_data = {"sub": user.id}
    return TokenOut(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
    )


# ---------------------------------------------------------------------------
# Me
# ---------------------------------------------------------------------------

@router.get("/me", response_model=UserOut)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> UserOut:
    """Return the currently authenticated user's profile."""
    _require_auth_enabled()

    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    return UserOut.model_validate(current_user)


# ---------------------------------------------------------------------------
# Change password
# ---------------------------------------------------------------------------

@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """Change the current user's password."""
    _require_auth_enabled()

    if current_user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    current_user.hashed_password = get_password_hash(body.new_password)
    await db.flush()


# ---------------------------------------------------------------------------
# Invite
# ---------------------------------------------------------------------------

@router.post("/invite/{workspace_id}")
async def create_invite(
    workspace_id: str,
    body: InviteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Generate a workspace invite link for the given email address.
    Requires the calling user to be the workspace owner or admin.
    """
    _require_auth_enabled()

    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    # Verify workspace exists and caller has permission to invite
    result = await db.execute(
        select(Workspace).where(Workspace.id == workspace_id)
    )
    workspace = result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace not found",
        )

    # Only owner or admin can invite
    if workspace.owner_id != current_user.id:
        member_result = await db.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == current_user.id,
                WorkspaceMember.role.in_(["owner", "admin"]),
            )
        )
        member = member_result.scalar_one_or_none()
        if member is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only workspace owners and admins can invite members",
            )

    invite_token = secrets.token_urlsafe(32)
    invite = WorkspaceInvite(
        id=str(uuid.uuid4()),
        workspace_id=workspace_id,
        email=body.email,
        token=invite_token,
        created_by=current_user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        accepted=False,
    )
    db.add(invite)
    await db.flush()

    # In production, the base URL should come from configuration or the request
    invite_link = f"/auth/accept-invite/{invite_token}"
    return {"invite_link": invite_link}


# ---------------------------------------------------------------------------
# Accept invite
# ---------------------------------------------------------------------------

@router.post("/accept-invite/{token}", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def accept_invite(
    token: str,
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """
    Accept a workspace invite. Creates the user account and adds them as a member.
    """
    _require_auth_enabled()

    result = await db.execute(
        select(WorkspaceInvite).where(WorkspaceInvite.token == token)
    )
    invite = result.scalar_one_or_none()

    if invite is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invite not found or already used",
        )

    if invite.accepted:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This invite has already been accepted",
        )

    if datetime.now(timezone.utc) > invite.expires_at.replace(tzinfo=timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This invite link has expired",
        )

    # Email must match the invite
    if body.email.lower() != invite.email.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The email address does not match the invite",
        )

    # Create user account if one does not already exist
    user_result = await db.execute(select(User).where(User.email == body.email))
    user = user_result.scalar_one_or_none()

    if user is None:
        user = User(
            id=str(uuid.uuid4()),
            email=body.email,
            hashed_password=get_password_hash(body.password),
            is_active=True,
            is_admin=False,
        )
        db.add(user)
        await db.flush()

    # Add as workspace member (viewer role by default)
    existing_member_result = await db.execute(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == invite.workspace_id,
            WorkspaceMember.user_id == user.id,
        )
    )
    if existing_member_result.scalar_one_or_none() is None:
        member = WorkspaceMember(
            id=str(uuid.uuid4()),
            workspace_id=invite.workspace_id,
            user_id=user.id,
            role="viewer",
        )
        db.add(member)

    # Mark invite as accepted
    invite.accepted = True
    await db.flush()
    await db.refresh(user)

    return UserOut.model_validate(user)
