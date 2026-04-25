"""
Workspace management routes for Verity.
"""

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_auth
from app.api.schemas import (
    InviteCreate,
    PolicyOut,
    PolicyUpsert,
    WorkspaceAnalyticsOut,
    WorkspaceCreate,
    WorkspaceMemberOut,
    WorkspaceOut,
)
from app.config import settings
from app.db.models import Scan, User, Workspace, WorkspaceMember, WorkspaceInvite, WorkspacePolicy

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


# ---------------------------------------------------------------------------
# Create workspace
# ---------------------------------------------------------------------------

@router.post("", response_model=WorkspaceOut, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    body: WorkspaceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> WorkspaceOut:
    """Create a new workspace. Requires authentication."""
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication is required to create a workspace",
        )

    workspace_id = str(uuid.uuid4())
    workspace = Workspace(
        id=workspace_id,
        name=body.name,
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
        return []

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
            status_code=status.HTTP_403_FORBIDDEN,
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
            status_code=status.HTTP_403_FORBIDDEN,
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
            status_code=status.HTTP_403_FORBIDDEN,
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
            status_code=status.HTTP_403_FORBIDDEN,
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


# ---------------------------------------------------------------------------
# Invite member
# ---------------------------------------------------------------------------

@router.post("/{workspace_id}/invite")
async def invite_member(
    workspace_id: str,
    body: InviteCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> dict:
    """Generate an invite link for a workspace. Owner/admin only."""
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authentication required")

    ws_result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = ws_result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Workspace '{workspace_id}' not found")

    # Verify caller is owner or admin
    if workspace.owner_id != current_user.id:
        mem_result = await db.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == current_user.id,
            )
        )
        member = mem_result.scalar_one_or_none()
        if member is None or member.role not in ("owner", "admin"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner or admin required to invite members")

    email = str(body.email).strip()

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    invite = WorkspaceInvite(
        id=str(uuid.uuid4()),
        workspace_id=workspace_id,
        email=email,
        token=token,
        created_by=current_user.id,
        expires_at=expires_at,
        accepted=False,
    )
    db.add(invite)
    await db.flush()

    base_url = str(request.base_url).rstrip("/")
    invite_link = f"{base_url}/invite?token={token}"

    return {"invite_link": invite_link}


# ---------------------------------------------------------------------------
# Workspace analytics
# ---------------------------------------------------------------------------

@router.get("/{workspace_id}/analytics", response_model=WorkspaceAnalyticsOut)
async def get_workspace_analytics(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> WorkspaceAnalyticsOut:
    """Return aggregate statistics for all scans in a workspace."""
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authentication required")

    ws_result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = ws_result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Workspace '{workspace_id}' not found")

    # Verify membership
    mem_result = await db.execute(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == current_user.id,
        )
    )
    if mem_result.scalar_one_or_none() is None and workspace.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a workspace member")

    scans_result = await db.execute(
        select(Scan).where(Scan.workspace_id == workspace_id).order_by(Scan.created_at.desc())
    )
    scans = scans_result.scalars().all()

    total_scans = len(scans)
    if total_scans == 0:
        return WorkspaceAnalyticsOut(
            workspace_id=workspace_id,
            total_scans=0,
            avg_quality_score=None,
            avg_risk_score=0.0,
            ntia_pass_rate=0.0,
            risk_distribution={},
            score_trend=[],
            top_vulnerabilities=[],
        )

    risk_scores = [s.risk_score for s in scans]
    avg_risk = sum(risk_scores) / len(risk_scores)

    quality_scores = [s.quality_score for s in scans if s.quality_score is not None]
    avg_quality = sum(quality_scores) / len(quality_scores) if quality_scores else None

    ntia_pass = sum(1 for s in scans if s.ntia_compliant)
    ntia_rate = ntia_pass / total_scans if total_scans else 0.0

    risk_dist: dict[str, int] = {}
    for s in scans:
        risk_dist[s.risk_level] = risk_dist.get(s.risk_level, 0) + 1

    trend = [
        {
            "date": s.created_at.isoformat(),
            "risk_score": s.risk_score,
            "quality_score": s.quality_score,
        }
        for s in reversed(scans[-30:])  # last 30 scans, oldest first
    ]

    # Aggregate top vulns across all components in workspace scans
    vuln_counts: dict[str, int] = {}
    from app.db.models import ScanComponent
    scan_ids = [s.id for s in scans]
    if scan_ids:
        comp_result = await db.execute(
            select(ScanComponent).where(ScanComponent.scan_id.in_(scan_ids))
        )
        for comp in comp_result.scalars().all():
            for v in (comp.vulnerabilities or []):
                if isinstance(v, dict):
                    vid = v.get("id", "")
                    if vid:
                        vuln_counts[vid] = vuln_counts.get(vid, 0) + 1

    top_vulns = sorted(
        [{"id": vid, "count": cnt} for vid, cnt in vuln_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    return WorkspaceAnalyticsOut(
        workspace_id=workspace_id,
        total_scans=total_scans,
        avg_quality_score=avg_quality,
        avg_risk_score=avg_risk,
        ntia_pass_rate=ntia_rate,
        risk_distribution=risk_dist,
        score_trend=trend,
        top_vulnerabilities=top_vulns,
    )


# ---------------------------------------------------------------------------
# Workspace policy CRUD
# ---------------------------------------------------------------------------

@router.get("/{workspace_id}/policy", response_model=PolicyOut)
async def get_workspace_policy(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> PolicyOut:
    """Get the YAML policy for a workspace."""
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authentication required")

    ws_result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = ws_result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Workspace '{workspace_id}' not found")

    pol_result = await db.execute(
        select(WorkspacePolicy).where(WorkspacePolicy.workspace_id == workspace_id)
    )
    policy = pol_result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No policy configured for this workspace")

    return PolicyOut(
        id=policy.id,
        workspace_id=policy.workspace_id,
        name=policy.name,
        policy_yaml=policy.policy_yaml,
        updated_at=policy.updated_at,
    )


@router.put("/{workspace_id}/policy", response_model=PolicyOut)
async def upsert_workspace_policy(
    workspace_id: str,
    body: PolicyUpsert,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> PolicyOut:
    """Create or replace the YAML policy for a workspace. Owner/admin only."""
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authentication required")

    ws_result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = ws_result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Workspace '{workspace_id}' not found")

    # Only owner or workspace admin may manage policy
    if workspace.owner_id != current_user.id and not current_user.is_admin:
        mem_result = await db.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == current_user.id,
            )
        )
        member = mem_result.scalar_one_or_none()
        if member is None or member.role not in ("owner", "admin"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner or admin required")

    pol_result = await db.execute(
        select(WorkspacePolicy).where(WorkspacePolicy.workspace_id == workspace_id)
    )
    policy = pol_result.scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if policy is None:
        policy = WorkspacePolicy(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            name=body.name,
            policy_yaml=body.policy_yaml,
            updated_at=now,
        )
        db.add(policy)
    else:
        policy.name = body.name
        policy.policy_yaml = body.policy_yaml
        policy.updated_at = now

    await db.flush()
    await db.refresh(policy)

    return PolicyOut(
        id=policy.id,
        workspace_id=policy.workspace_id,
        name=policy.name,
        policy_yaml=policy.policy_yaml,
        updated_at=policy.updated_at,
    )


@router.delete("/{workspace_id}/policy", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workspace_policy(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> None:
    """Delete the policy for a workspace. Owner only."""
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authentication required")

    ws_result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = ws_result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Workspace '{workspace_id}' not found")

    if workspace.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner required")

    pol_result = await db.execute(
        select(WorkspacePolicy).where(WorkspacePolicy.workspace_id == workspace_id)
    )
    policy = pol_result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No policy to delete")

    await db.delete(policy)
