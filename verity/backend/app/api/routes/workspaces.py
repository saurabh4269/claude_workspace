"""
Workspace management routes for Verity.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_auth
from app.api.schemas import WorkspaceMemberOut, WorkspaceOut
from app.config import settings
from app.db.models import User, Workspace, WorkspaceMember

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


# ---------------------------------------------------------------------------
# Create workspace
# ---------------------------------------------------------------------------

@router.post("", response_model=WorkspaceOut, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> WorkspaceOut:
    """Create a new workspace. Requires authentication."""
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Workspace name is required",
        )

    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    workspace_id = str(uuid.uuid4())
    workspace = Workspace(
        id=workspace_id,
        name=name,
        owner_id=current_user.id,
    )
    db.add(workspace)

    # Add owner as a member with owner role
    owner_member = WorkspaceMember(
        id=str(uuid.uuid4()),
        workspace_id=workspace_id,
        user_id=current_user.id,
        role="owner",
    )
    db.add(owner_member)
    await db.flush()
    await db.refresh(workspace)

    return WorkspaceOut(
        id=workspace.id,
        name=workspace.name,
        owner_id=workspace.owner_id,
        created_at=workspace.created_at,
        member_count=1,
    )


# ---------------------------------------------------------------------------
# List workspaces
# ---------------------------------------------------------------------------

@router.get("", response_model=list[WorkspaceOut])
async def list_workspaces(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> list[WorkspaceOut]:
    """List all workspaces the current user belongs to."""
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    # Find workspaces where user is a member
    member_result = await db.execute(
        select(WorkspaceMember.workspace_id).where(
            WorkspaceMember.user_id == current_user.id
        )
    )
    workspace_ids = [row[0] for row in member_result.all()]

    if not workspace_ids:
        return []

    workspace_result = await db.execute(
        select(Workspace).where(Workspace.id.in_(workspace_ids))
    )
    workspaces = workspace_result.scalars().all()

    outs = []
    for ws in workspaces:
        count_result = await db.execute(
            select(func.count()).where(WorkspaceMember.workspace_id == ws.id)
        )
        member_count = count_result.scalar_one()
        outs.append(
            WorkspaceOut(
                id=ws.id,
                name=ws.name,
                owner_id=ws.owner_id,
                created_at=ws.created_at,
                member_count=member_count,
            )
        )
    return outs


# ---------------------------------------------------------------------------
# Get single workspace
# ---------------------------------------------------------------------------

@router.get("/{workspace_id}", response_model=WorkspaceOut)
async def get_workspace(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> WorkspaceOut:
    """Retrieve a workspace by ID."""
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()

    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace '{workspace_id}' not found",
        )

    # Verify membership
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

    count_result = await db.execute(
        select(func.count()).where(WorkspaceMember.workspace_id == workspace_id)
    )
    member_count = count_result.scalar_one()

    return WorkspaceOut(
        id=workspace.id,
        name=workspace.name,
        owner_id=workspace.owner_id,
        created_at=workspace.created_at,
        member_count=member_count,
    )


# ---------------------------------------------------------------------------
# Delete workspace
# ---------------------------------------------------------------------------

@router.delete("/{workspace_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workspace(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> None:
    """Delete a workspace. Only the workspace owner can delete it."""
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()

    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace '{workspace_id}' not found",
        )

    if workspace.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the workspace owner can delete this workspace",
        )

    await db.delete(workspace)


# ---------------------------------------------------------------------------
# List members
# ---------------------------------------------------------------------------

@router.get("/{workspace_id}/members", response_model=list[WorkspaceMemberOut])
async def list_members(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> list[WorkspaceMemberOut]:
    """List all members of a workspace."""
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()

    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace '{workspace_id}' not found",
        )

    # Verify the requester is a member
    member_check = await db.execute(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == current_user.id,
        )
    )
    if member_check.scalar_one_or_none() is None and workspace.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this workspace",
        )

    members_result = await db.execute(
        select(WorkspaceMember).where(WorkspaceMember.workspace_id == workspace_id)
    )
    members = members_result.scalars().all()

    outs = []
    for m in members:
        # Fetch the user email for context
        user_result = await db.execute(select(User).where(User.id == m.user_id))
        user = user_result.scalar_one_or_none()
        outs.append(
            WorkspaceMemberOut(
                user_id=m.user_id,
                workspace_id=m.workspace_id,
                role=m.role,
                joined_at=m.joined_at,
                email=user.email if user else None,
            )
        )
    return outs


# ---------------------------------------------------------------------------
# Remove member
# ---------------------------------------------------------------------------

@router.delete(
    "/{workspace_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_member(
    workspace_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> None:
    """Remove a member from a workspace. Owner or admin only."""
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()

    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace '{workspace_id}' not found",
        )

    # Only owner or admins can remove members (or self-removal)
    if current_user.id != user_id:
        caller_member_result = await db.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == current_user.id,
            )
        )
        caller_member = caller_member_result.scalar_one_or_none()
        is_owner = workspace.owner_id == current_user.id
        is_admin = caller_member is not None and caller_member.role in ("owner", "admin")
        if not is_owner and not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only workspace owners and admins can remove members",
            )

    member_result = await db.execute(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == user_id,
        )
    )
    member = member_result.scalar_one_or_none()

    if member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found in this workspace",
        )

    # Prevent removing the owner
    if member.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove the workspace owner",
        )

    await db.delete(member)
