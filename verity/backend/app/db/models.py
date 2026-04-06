"""
SQLAlchemy ORM models for Verity.
UUIDs are stored as strings for SQLite compatibility.
JSON fields are stored as Text with helper properties for serialization.
"""

import json
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _default_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # Relationships
    workspaces: Mapped[list["Workspace"]] = relationship(
        "Workspace", back_populates="owner", foreign_keys="Workspace.owner_id"
    )
    workspace_memberships: Mapped[list["WorkspaceMember"]] = relationship(
        "WorkspaceMember", back_populates="user"
    )
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="user")


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # Relationships
    owner: Mapped["User"] = relationship(
        "User", back_populates="workspaces", foreign_keys=[owner_id]
    )
    members: Mapped[list["WorkspaceMember"]] = relationship(
        "WorkspaceMember", back_populates="workspace"
    )
    invites: Mapped[list["WorkspaceInvite"]] = relationship(
        "WorkspaceInvite", back_populates="workspace"
    )
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="workspace")


class WorkspaceMember(Base):
    __tablename__ = "workspace_members"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    # role is one of: owner, admin, viewer
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="viewer")
    joined_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship(
        "Workspace", back_populates="members"
    )
    user: Mapped["User"] = relationship("User", back_populates="workspace_memberships")


class WorkspaceInvite(Base):
    __tablename__ = "workspace_invites"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    # Unique token used in the invite link URL
    token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    created_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    accepted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    workspace: Mapped["Workspace"] = relationship(
        "Workspace", back_populates="invites"
    )
    creator: Mapped["User"] = relationship("User", foreign_keys=[created_by])


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    # sbom_format is one of: cyclonedx, spdx
    sbom_format: Mapped[str] = mapped_column(String(50), nullable=False)
    format_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    # user_id is null when AUTH_ENABLED=False
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    workspace_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("workspaces.id"), nullable=True
    )
    # risk_level is one of: LOW, MEDIUM, HIGH, CRITICAL
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    total_components: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vulnerable_components: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    invalid_components: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ntia_compliant: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    vuln_check_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    save_to_history: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # summary stored as JSON text
    _summary: Mapped[str | None] = mapped_column("summary", Text, nullable=True)

    # Relationships
    user: Mapped["User | None"] = relationship("User", back_populates="scans")
    workspace: Mapped["Workspace | None"] = relationship(
        "Workspace", back_populates="scans"
    )
    components: Mapped[list["ScanComponent"]] = relationship(
        "ScanComponent",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    @property
    def summary(self) -> dict:
        if self._summary is None:
            return {}
        try:
            return json.loads(self._summary)
        except (json.JSONDecodeError, TypeError):
            return {}

    @summary.setter
    def summary(self, value: dict) -> None:
        self._summary = json.dumps(value) if value is not None else None


class ScanComponent(Base):
    __tablename__ = "scan_components"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    purl: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpe: Mapped[str | None] = mapped_column(Text, nullable=True)
    supplier: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # licenses stored as JSON array text
    _licenses: Mapped[str | None] = mapped_column("licenses", Text, nullable=True)
    component_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # risk_level is one of: LOW, MEDIUM, HIGH, CRITICAL
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    # missing_fields stored as JSON array text
    _missing_fields: Mapped[str | None] = mapped_column(
        "missing_fields", Text, nullable=True
    )
    # vulnerabilities stored as JSON array text
    _vulnerabilities: Mapped[str | None] = mapped_column(
        "vulnerabilities", Text, nullable=True
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="components")

    @property
    def licenses(self) -> list:
        if self._licenses is None:
            return []
        try:
            return json.loads(self._licenses)
        except (json.JSONDecodeError, TypeError):
            return []

    @licenses.setter
    def licenses(self, value: list) -> None:
        self._licenses = json.dumps(value) if value is not None else None

    @property
    def missing_fields(self) -> list:
        if self._missing_fields is None:
            return []
        try:
            return json.loads(self._missing_fields)
        except (json.JSONDecodeError, TypeError):
            return []

    @missing_fields.setter
    def missing_fields(self, value: list) -> None:
        self._missing_fields = json.dumps(value) if value is not None else None

    @property
    def vulnerabilities(self) -> list:
        if self._vulnerabilities is None:
            return []
        try:
            return json.loads(self._vulnerabilities)
        except (json.JSONDecodeError, TypeError):
            return []

    @vulnerabilities.setter
    def vulnerabilities(self, value: list) -> None:
        self._vulnerabilities = json.dumps(value) if value is not None else None
