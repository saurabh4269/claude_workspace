"""
SQLAlchemy ORM models for Verity.
UUIDs are stored as strings for SQLite compatibility.
JSON fields are stored as Text with helper properties for serialization.
"""

import json
import logging
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

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
    # Quality scoring (new)
    quality_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    quality_grade: Mapped[str | None] = mapped_column(String(2), nullable=True)
    _category_scores: Mapped[str | None] = mapped_column("category_scores", Text, nullable=True)
    _dependency_graph: Mapped[str | None] = mapped_column("dependency_graph", Text, nullable=True)
    # Compliance results (new)
    _ntia_result: Mapped[str | None] = mapped_column("ntia_result", Text, nullable=True)
    _bsi_result: Mapped[str | None] = mapped_column("bsi_result", Text, nullable=True)
    _fsct_result: Mapped[str | None] = mapped_column("fsct_result", Text, nullable=True)
    _oct_result: Mapped[str | None] = mapped_column("oct_result", Text, nullable=True)
    _policy_result: Mapped[str | None] = mapped_column("policy_result", Text, nullable=True)
    _profile_result: Mapped[str | None] = mapped_column("profile_result", Text, nullable=True)

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
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("Corrupt JSON in scan.summary (id=%s): %s", self.id, exc)
            return {}

    @summary.setter
    def summary(self, value: dict) -> None:
        self._summary = json.dumps(value) if value is not None else None

    def _get_json(self, attr: str) -> dict | list | None:
        val = getattr(self, attr)
        if val is None:
            return None
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("Corrupt JSON in scan.%s (id=%s): %s", attr, self.id, exc)
            return None

    def _set_json(self, attr: str, value) -> None:
        setattr(self, attr, json.dumps(value) if value is not None else None)

    @property
    def category_scores(self) -> dict | None:
        return self._get_json("_category_scores")

    @category_scores.setter
    def category_scores(self, value) -> None:
        self._set_json("_category_scores", value)

    @property
    def dependency_graph(self) -> dict | None:
        return self._get_json("_dependency_graph")

    @dependency_graph.setter
    def dependency_graph(self, value) -> None:
        self._set_json("_dependency_graph", value)

    @property
    def ntia_result(self) -> dict | None:
        return self._get_json("_ntia_result")

    @ntia_result.setter
    def ntia_result(self, value) -> None:
        self._set_json("_ntia_result", value)

    @property
    def bsi_result(self) -> dict | None:
        return self._get_json("_bsi_result")

    @bsi_result.setter
    def bsi_result(self, value) -> None:
        self._set_json("_bsi_result", value)

    @property
    def fsct_result(self) -> dict | None:
        return self._get_json("_fsct_result")

    @fsct_result.setter
    def fsct_result(self, value) -> None:
        self._set_json("_fsct_result", value)

    @property
    def oct_result(self) -> dict | None:
        return self._get_json("_oct_result")

    @oct_result.setter
    def oct_result(self, value) -> None:
        self._set_json("_oct_result", value)

    @property
    def policy_result(self) -> dict | None:
        return self._get_json("_policy_result")

    @policy_result.setter
    def policy_result(self, value) -> None:
        self._set_json("_policy_result", value)

    @property
    def profile_result(self) -> dict | None:
        return self._get_json("_profile_result")

    @profile_result.setter
    def profile_result(self, value) -> None:
        self._set_json("_profile_result", value)


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
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("Corrupt JSON in component.licenses (id=%s): %s", self.id, exc)
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
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("Corrupt JSON in component.missing_fields (id=%s): %s", self.id, exc)
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
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("Corrupt JSON in component.vulnerabilities (id=%s): %s", self.id, exc)
            return []

    @vulnerabilities.setter
    def vulnerabilities(self, value: list) -> None:
        self._vulnerabilities = json.dumps(value) if value is not None else None


class KevCache(Base):
    __tablename__ = "kev_cache"

    cve_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    vendor_project: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vulnerability_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    due_date: Mapped[str | None] = mapped_column(String(50), nullable=True)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class WorkspacePolicy(Base):
    __tablename__ = "workspace_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False, unique=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="Default Policy")
    policy_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    workspace: Mapped["Workspace"] = relationship("Workspace")
