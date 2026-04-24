"""
Pydantic v2 request and response schemas for the Verity API.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    vuln_check: bool = True
    save_to_history: bool = True
    workspace_id: Optional[str] = None
    run_compliance: bool = True   # run NTIA + BSI + FSCT + OCT on every upload


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


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


class SiteSettingsUpdate(BaseModel):
    auth_enabled: Optional[bool] = None
    history_enabled: Optional[bool] = None
    vuln_check_enabled: Optional[bool] = None


class PolicyUpsert(BaseModel):
    name: str = Field(default="Default Policy", min_length=1, max_length=255)
    policy_yaml: str


class ScanDiffRequest(BaseModel):
    scan_id_a: str
    scan_id_b: str


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
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_kev: bool = False

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
        if not v:
            return []
        result = []
        for item in v:
            if isinstance(item, dict):
                try:
                    result.append(VulnOut(**item))
                except Exception:
                    pass
            elif isinstance(item, VulnOut):
                result.append(item)
        return result


class ValidationIssueOut(BaseModel):
    severity: str
    code: str
    message: str
    component_name: Optional[str] = None

    model_config = {"from_attributes": True}


class FeatureResultOut(BaseModel):
    key: str
    score: float
    applicable: bool
    weight: float
    detail: str


class CategoryResultOut(BaseModel):
    name: str
    weight: int
    score: float
    weighted_score: float
    features: list[FeatureResultOut] = Field(default_factory=list)


class QualityScoreOut(BaseModel):
    overall_score: float
    grade: str
    categories: list[CategoryResultOut] = Field(default_factory=list)


class NTIAElementOut(BaseModel):
    element_name: str
    compliant: bool
    score: float
    failing_components: list[str] = Field(default_factory=list)
    detail: str


class NTIAResultOut(BaseModel):
    standard: str = "NTIA Minimum Elements"
    overall_compliant: bool
    overall_score: float
    elements: list[NTIAElementOut] = Field(default_factory=list)


class ComplianceRecordOut(BaseModel):
    check_key: str
    tier: str
    score: float
    applicable: bool
    subject_id: str
    found_value: str
    expected: str
    detail: str


class BSIResultOut(BaseModel):
    standard: str
    overall_score: float
    compliant: bool
    required_passed: int
    required_total: int
    additional_passed: int
    additional_total: int
    records: list[ComplianceRecordOut] = Field(default_factory=list)


class FSCTResultOut(BaseModel):
    standard: str = "FSCT v3"
    overall_score: float
    raw_score: Optional[float] = None
    records: list[ComplianceRecordOut] = Field(default_factory=list)


class OCTResultOut(BaseModel):
    standard: str = "OpenChain Telco v1.1"
    overall_score: float
    spdx_only_fail: bool = False
    records: list[ComplianceRecordOut] = Field(default_factory=list)


class ComplianceSummaryOut(BaseModel):
    ntia: Optional[NTIAResultOut] = None
    bsi_v21: Optional[BSIResultOut] = None
    fsct: Optional[FSCTResultOut] = None
    oct: Optional[OCTResultOut] = None


class PolicyRuleOutcome(BaseModel):
    rule_id: str
    description: str
    action: str
    triggered: bool
    detail: str


class PolicyResultOut(BaseModel):
    overall: str
    outcomes: list[PolicyRuleOutcome] = Field(default_factory=list)


class DependencyGraphOut(BaseModel):
    nodes: list[str] = Field(default_factory=list)
    edges: list[list] = Field(default_factory=list)
    primary_component_ref: Optional[str] = None
    orphans: list[str] = Field(default_factory=list)
    is_complete: bool = False
    max_depth: int = 0


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
    quality_score: Optional[float] = None
    quality_grade: Optional[str] = None

    model_config = {"from_attributes": True}


class ProfileFeatureOut(BaseModel):
    key: str
    score: Optional[float] = None
    applicable: bool
    weight: float
    detail: str


class ProfileScoreOut(BaseModel):
    profile_name: str
    profile_score: float
    grade: str
    features: list[ProfileFeatureOut] = Field(default_factory=list)


class ScanDetailOut(ScanOut):
    components: list[ComponentOut] = Field(default_factory=list)
    validation_issues: list[ValidationIssueOut] = Field(default_factory=list)
    quality: Optional[QualityScoreOut] = None
    compliance: Optional[ComplianceSummaryOut] = None
    dependency_graph: Optional[DependencyGraphOut] = None
    policy_result: Optional[PolicyResultOut] = None
    profile_score: Optional[ProfileScoreOut] = None


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


class ComponentSearchResult(BaseModel):
    component_id: str
    scan_id: str
    scan_filename: str
    scan_date: datetime
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    risk_level: str
    risk_score: float
    vuln_count: int = 0


class ComponentSearchOut(BaseModel):
    query: str
    results: list[ComponentSearchResult]
    total: int


class ScanDiffOut(BaseModel):
    scan_id_a: str
    scan_id_b: str
    filename_a: str
    filename_b: str
    score_delta: float
    added: list[dict] = Field(default_factory=list)
    removed: list[dict] = Field(default_factory=list)
    version_changed: list[dict] = Field(default_factory=list)
    new_vulnerabilities: list[dict] = Field(default_factory=list)
    resolved_vulnerabilities: list[dict] = Field(default_factory=list)


class WorkspaceAnalyticsOut(BaseModel):
    workspace_id: str
    total_scans: int
    avg_quality_score: Optional[float] = None
    avg_risk_score: float
    ntia_pass_rate: float
    risk_distribution: dict = Field(default_factory=dict)
    score_trend: list[dict] = Field(default_factory=list)
    top_vulnerabilities: list[dict] = Field(default_factory=list)


class PolicyOut(BaseModel):
    id: str
    workspace_id: str
    name: str
    policy_yaml: str
    updated_at: datetime

    model_config = {"from_attributes": True}


class CIScanOut(BaseModel):
    scan_id: Optional[str] = None
    filename: str
    overall_score: Optional[float] = None
    grade: Optional[str] = None
    risk_level: str
    ntia_compliant: bool
    policy_result: Optional[str] = None
    policy_failures: list[str] = Field(default_factory=list)
    passed: bool
