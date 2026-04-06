"""
Pydantic v2 request and response schemas for the Verity API.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    vuln_check: bool = True
    save_to_history: bool = True
    workspace_id: Optional[str] = None


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class WorkspaceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class InviteCreate(BaseModel):
    email: EmailStr
    workspace_id: str


class TokenRefresh(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class UserOut(BaseModel):
    id: str
    email: str
    is_admin: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class WorkspaceOut(BaseModel):
    id: str
    name: str
    owner_id: str
    created_at: datetime
    member_count: int = 0

    model_config = {"from_attributes": True}


class VulnOut(BaseModel):
    id: str
    summary: str
    severity: str
    cvss_score: float
    fixed_version: Optional[str] = None
    published: Optional[str] = None

    model_config = {"from_attributes": True}


class ComponentOut(BaseModel):
    id: str
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    supplier: Optional[str] = None
    licenses: list[str] = Field(default_factory=list)
    component_type: Optional[str] = None
    risk_level: str
    risk_score: float
    missing_fields: list[str] = Field(default_factory=list)
    vulnerabilities: list[VulnOut] = Field(default_factory=list)

    model_config = {"from_attributes": True}

    @field_validator("vulnerabilities", mode="before")
    @classmethod
    def parse_vulnerabilities(cls, v):
        """
        Convert raw vulnerability dicts (from DB JSON) to VulnOut objects.
        """
        if not v:
            return []
        result = []
        for item in v:
            if isinstance(item, dict):
                result.append(VulnOut(**item))
            elif isinstance(item, VulnOut):
                result.append(item)
        return result


class ValidationIssueOut(BaseModel):
    severity: str
    code: str
    message: str
    component_name: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: str
    filename: str
    sbom_format: str
    format_version: Optional[str] = None
    created_at: datetime
    risk_level: str
    risk_score: float
    total_components: int
    vulnerable_components: int
    invalid_components: int
    ntia_compliant: bool
    vuln_check_enabled: bool
    summary: dict = Field(default_factory=dict)

    model_config = {"from_attributes": True}


class ScanDetailOut(ScanOut):
    components: list[ComponentOut] = Field(default_factory=list)
    validation_issues: list[ValidationIssueOut] = Field(default_factory=list)


class ScanListOut(BaseModel):
    items: list[ScanOut]
    total: int
    page: int
    per_page: int


class WorkspaceMemberOut(BaseModel):
    user_id: str
    workspace_id: str
    role: str
    joined_at: datetime
    email: Optional[str] = None

    model_config = {"from_attributes": True}
