"""
Scan routes for Verity.
Handles SBOM file upload, processing, retrieval, deletion, diff, and compliance.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, get_db
from app.api.schemas import (
    BSIResultOut,
    CategoryResultOut,
    ComplianceRecordOut,
    ComplianceSummaryOut,
    ComponentOut,
    DependencyGraphOut,
    FeatureResultOut,
    FSCTResultOut,
    NTIAElementOut,
    NTIAResultOut,
    OCTResultOut,
    PolicyResultOut,
    PolicyRuleOutcome,
    QualityScoreOut,
    ScanDetailOut,
    ScanDiffOut,
    ScanDiffRequest,
    ScanListOut,
    ScanOut,
    ValidationIssueOut,
    VulnOut,
)
from app.config import settings
from app.core.compliance import check_bsi, check_fsct, check_ntia, check_oct
from app.core.parser import ParseError, parse
from app.core.policy import evaluate_policy, parse_policy
from app.core.risk_analyzer import analyze
from app.core.scorer import QualityScore, score, quality_score_to_dict
from app.core.validator import validate
from app.core.vuln_checker import check_vulnerabilities
from app.db.models import Scan, ScanComponent, User, WorkspacePolicy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

_ALLOWED_EXTENSIONS = {".json", ".xml", ".spdx", ".tv", ".yaml", ".yml"}


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

@router.post("/upload", response_model=ScanDetailOut, status_code=status.HTTP_201_CREATED)
async def upload_scan(
    file: UploadFile = File(...),
    vuln_check: bool = Form(default=True),
    save_to_history: bool = Form(default=True),
    workspace_id: Optional[str] = Form(default=None),
    run_compliance: bool = Form(default=True),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> ScanDetailOut:
    """Upload an SBOM file for validation, quality scoring, compliance, and risk assessment."""
    filename = file.filename or "unknown"

    lower_name = filename.lower()
    if not any(lower_name.endswith(ext) for ext in _ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported file type. Allowed: {', '.join(sorted(_ALLOWED_EXTENSIONS))}",
        )

    content_bytes = await file.read()
    if len(content_bytes) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {settings.MAX_UPLOAD_SIZE_MB} MB limit",
        )

    try:
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Could not decode file as UTF-8: {exc}",
        ) from exc

    try:
        doc = parse(content, filename=filename)
    except ParseError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    validation_result = validate(doc)

    effective_vuln_check = vuln_check and settings.VULN_CHECK_ENABLED
    vuln_results: dict = {}
    if effective_vuln_check:
        vuln_results = await check_vulnerabilities(doc.components, enabled=True)

    risk_report = analyze(doc, vuln_results=vuln_results)

    # Quality scoring (pass vuln_results for Category 8 security health metrics)
    qs: Optional[QualityScore] = None
    qs_dict: Optional[dict] = None
    try:
        qs = score(doc, vuln_results=vuln_results if effective_vuln_check else None)
        qs_dict = quality_score_to_dict(qs)
    except Exception as exc:
        logger.warning("Quality scoring failed: %s", exc)

    # Compliance checks
    ntia_res_dict: Optional[dict] = None
    bsi_res_dict: Optional[dict] = None
    fsct_res_dict: Optional[dict] = None
    oct_res_dict: Optional[dict] = None
    if run_compliance:
        try:
            ntia_res_dict = check_ntia(doc).to_dict()
        except Exception as exc:
            logger.warning("NTIA check failed: %s", exc)
        try:
            bsi_res_dict = check_bsi(doc).to_dict()
        except Exception as exc:
            logger.warning("BSI check failed: %s", exc)
        try:
            fsct_res_dict = check_fsct(doc).to_dict()
        except Exception as exc:
            logger.warning("FSCT check failed: %s", exc)
        try:
            oct_res_dict = check_oct(doc).to_dict()
        except Exception as exc:
            logger.warning("OCT check failed: %s", exc)

    # Dependency graph
    dep_graph_dict: Optional[dict] = None
    if doc.dependency_graph is not None:
        # dependency_graph is already a dict (serialized by the parser)
        dep_graph_dict = doc.dependency_graph if isinstance(doc.dependency_graph, dict) else None

    # Policy evaluation
    policy_result_dict: Optional[dict] = None
    if workspace_id:
        try:
            pol_result = await db.execute(
                select(WorkspacePolicy).where(WorkspacePolicy.workspace_id == workspace_id)
            )
            pol_row = pol_result.scalar_one_or_none()
            if pol_row:
                rules = parse_policy(pol_row.policy_yaml)
                if rules:
                    comp_dicts = _components_to_dicts(doc.components, vuln_results)
                    scan_data = {
                        "quality_score": qs.overall_score if qs else 0.0,
                        "risk_score": risk_report.overall_risk_score,
                        "risk_level": risk_report.overall_risk_level,
                        "components": comp_dicts,
                        "category_scores": qs_dict,
                    }
                    policy_result_dict = evaluate_policy(rules, scan_data).to_dict()
        except Exception as exc:
            logger.warning("Policy evaluation failed: %s", exc)

    # Counts
    vulnerable_count = sum(1 for comp in doc.components if _get_comp_vulns(comp, vuln_results))
    invalid_count = sum(
        1 for cv in validation_result.component_results
        if any(i.severity == "ERROR" for i in cv.issues)
    )

    summary = {
        "risk_distribution": risk_report.summary,
        "ntia_issue_count": sum(1 for i in validation_result.issues if i.severity == "ERROR"),
        "format": doc.format,
        "spec_version": doc.spec_version,
        "validation_issues": [
            {"severity": i.severity, "code": i.code, "message": i.message,
             "component_name": i.component_name}
            for i in validation_result.issues
        ],
    }

    scan_id = str(uuid.uuid4())
    should_save = save_to_history and settings.HISTORY_ENABLED

    if should_save:
        scan = Scan(
            id=scan_id,
            filename=filename,
            sbom_format=doc.format,
            format_version=doc.spec_version,
            user_id=current_user.id if current_user else None,
            workspace_id=workspace_id,
            risk_level=risk_report.overall_risk_level,
            risk_score=risk_report.overall_risk_score,
            total_components=len(doc.components),
            vulnerable_components=vulnerable_count,
            invalid_components=invalid_count,
            ntia_compliant=validation_result.ntia_compliant,
            vuln_check_enabled=effective_vuln_check,
            save_to_history=True,
            quality_score=qs.overall_score if qs else None,
            quality_grade=qs.grade if qs else None,
        )
        scan.summary = summary
        if qs_dict:
            scan.category_scores = qs_dict
        if dep_graph_dict:
            scan.dependency_graph = dep_graph_dict
        if ntia_res_dict:
            scan.ntia_result = ntia_res_dict
        if bsi_res_dict:
            scan.bsi_result = bsi_res_dict
        if fsct_res_dict:
            scan.fsct_result = fsct_res_dict
        if oct_res_dict:
            scan.oct_result = oct_res_dict
        if policy_result_dict:
            scan.policy_result = policy_result_dict
        db.add(scan)
        await db.flush()

        for comp, comp_risk in zip(doc.components, risk_report.component_risks):
            comp_validation = next(
                (cv for cv in validation_result.component_results if cv.component_name == comp.name),
                None,
            )
            missing_fields = comp_validation.missing_fields if comp_validation else []
            vulns = _get_comp_vulns(comp, vuln_results)
            db_comp = ScanComponent(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                name=comp.name,
                version=comp.version,
                purl=comp.purl,
                cpe=comp.cpe,
                supplier=comp.supplier,
                component_type=comp.component_type,
                risk_level=comp_risk.risk_level,
                risk_score=comp_risk.risk_score,
            )
            db_comp.licenses = comp.licenses
            db_comp.missing_fields = missing_fields
            db_comp.vulnerabilities = vulns
            db.add(db_comp)

        await db.flush()

    component_outs = _build_component_outs(
        doc.components, risk_report.component_risks,
        validation_result.component_results, vuln_results,
        scan_id if should_save else str(uuid.uuid4()),
    )
    validation_issue_outs = [
        ValidationIssueOut(severity=i.severity, code=i.code, message=i.message,
                           component_name=i.component_name)
        for i in validation_result.issues
    ]

    return ScanDetailOut(
        id=scan_id,
        filename=filename,
        sbom_format=doc.format,
        format_version=doc.spec_version,
        created_at=datetime.now(timezone.utc),
        risk_level=risk_report.overall_risk_level,
        risk_score=risk_report.overall_risk_score,
        total_components=len(doc.components),
        vulnerable_components=vulnerable_count,
        invalid_components=invalid_count,
        ntia_compliant=validation_result.ntia_compliant,
        vuln_check_enabled=effective_vuln_check,
        summary=summary,
        quality_score=qs.overall_score if qs else None,
        quality_grade=qs.grade if qs else None,
        components=component_outs,
        validation_issues=validation_issue_outs,
        quality=_qs_to_out(qs) if qs else None,
        compliance=_build_compliance_out(ntia_res_dict, bsi_res_dict, fsct_res_dict, oct_res_dict),
        dependency_graph=_dep_graph_to_out(dep_graph_dict),
        policy_result=_policy_result_to_out(policy_result_dict),
    )


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

@router.get("", response_model=ScanListOut)
async def list_scans(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    workspace_id: Optional[str] = Query(default=None),
    risk_level: Optional[str] = Query(default=None),
    date_from: Optional[datetime] = Query(default=None),
    date_to: Optional[datetime] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> ScanListOut:
    """List scans with optional filters and pagination."""
    query = select(Scan)

    if settings.AUTH_ENABLED and current_user is not None:
        query = query.where(Scan.user_id == current_user.id)
    if workspace_id:
        query = query.where(Scan.workspace_id == workspace_id)
    if risk_level:
        query = query.where(Scan.risk_level == risk_level.upper())
    if date_from:
        query = query.where(Scan.created_at >= date_from)
    if date_to:
        query = query.where(Scan.created_at <= date_to)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    offset = (page - 1) * per_page
    query = query.order_by(Scan.created_at.desc()).offset(offset).limit(per_page)
    result = await db.execute(query)
    scans = result.scalars().all()

    items = [
        ScanOut(
            id=s.id, filename=s.filename, sbom_format=s.sbom_format,
            format_version=s.format_version, created_at=s.created_at,
            risk_level=s.risk_level, risk_score=s.risk_score,
            total_components=s.total_components, vulnerable_components=s.vulnerable_components,
            invalid_components=s.invalid_components, ntia_compliant=s.ntia_compliant,
            vuln_check_enabled=s.vuln_check_enabled, summary=s.summary,
            quality_score=s.quality_score, quality_grade=s.quality_grade,
        )
        for s in scans
    ]
    return ScanListOut(items=items, total=total, page=page, per_page=per_page)


# ---------------------------------------------------------------------------
# Get single scan
# ---------------------------------------------------------------------------

@router.get("/{scan_id}", response_model=ScanDetailOut)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> ScanDetailOut:
    """Retrieve a scan by ID including all components, quality, and compliance."""
    result = await db.execute(
        select(Scan).options(selectinload(Scan.components)).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")

    if settings.AUTH_ENABLED and current_user is not None:
        if scan.user_id and scan.user_id != current_user.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    component_outs = _build_component_outs_from_db(scan.components)
    issues_raw = scan.summary.get("validation_issues") or []
    validation_issue_outs = [
        ValidationIssueOut(**issue) for issue in issues_raw if isinstance(issue, dict)
    ]

    return ScanDetailOut(
        id=scan.id, filename=scan.filename, sbom_format=scan.sbom_format,
        format_version=scan.format_version, created_at=scan.created_at,
        risk_level=scan.risk_level, risk_score=scan.risk_score,
        total_components=scan.total_components, vulnerable_components=scan.vulnerable_components,
        invalid_components=scan.invalid_components, ntia_compliant=scan.ntia_compliant,
        vuln_check_enabled=scan.vuln_check_enabled, summary=scan.summary,
        quality_score=scan.quality_score, quality_grade=scan.quality_grade,
        components=component_outs, validation_issues=validation_issue_outs,
        quality=_qs_dict_to_out(scan.category_scores, scan.quality_score, scan.quality_grade),
        compliance=_build_compliance_out(
            scan.ntia_result, scan.bsi_result, scan.fsct_result, scan.oct_result
        ),
        dependency_graph=_dep_graph_to_out(scan.dependency_graph),
        policy_result=_policy_result_to_out(scan.policy_result),
    )


# ---------------------------------------------------------------------------
# Compliance detail
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/compliance", response_model=ComplianceSummaryOut)
async def get_scan_compliance(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> ComplianceSummaryOut:
    """Return detailed compliance results for a scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")
    if settings.AUTH_ENABLED and current_user is not None:
        if scan.user_id and scan.user_id != current_user.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    compliance = _build_compliance_out(scan.ntia_result, scan.bsi_result, scan.fsct_result, scan.oct_result)
    return compliance or ComplianceSummaryOut()


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

@router.post("/diff", response_model=ScanDiffOut)
async def diff_scans(
    body: ScanDiffRequest,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> ScanDiffOut:
    """Compare two scans and return component-level diffs."""
    result_a = await db.execute(
        select(Scan).options(selectinload(Scan.components)).where(Scan.id == body.scan_id_a)
    )
    scan_a = result_a.scalar_one_or_none()
    result_b = await db.execute(
        select(Scan).options(selectinload(Scan.components)).where(Scan.id == body.scan_id_b)
    )
    scan_b = result_b.scalar_one_or_none()

    if scan_a is None:
        raise HTTPException(status_code=404, detail=f"Scan '{body.scan_id_a}' not found")
    if scan_b is None:
        raise HTTPException(status_code=404, detail=f"Scan '{body.scan_id_b}' not found")

    def _comp_key(c: ScanComponent) -> str:
        return (c.purl or c.name).lower()

    map_a = {_comp_key(c): c for c in scan_a.components}
    map_b = {_comp_key(c): c for c in scan_b.components}
    keys_a, keys_b = set(map_a), set(map_b)

    added = [{"name": map_b[k].name, "version": map_b[k].version, "purl": map_b[k].purl} for k in keys_b - keys_a]
    removed = [{"name": map_a[k].name, "version": map_a[k].version, "purl": map_a[k].purl} for k in keys_a - keys_b]

    version_changed = []
    new_vulns = []
    resolved_vulns = []
    for k in keys_a & keys_b:
        ca, cb = map_a[k], map_b[k]
        if ca.version != cb.version:
            version_changed.append({"name": ca.name, "old": ca.version, "new": cb.version})
        vuln_ids_a = {v.get("id") for v in (ca.vulnerabilities or []) if isinstance(v, dict)}
        vuln_ids_b = {v.get("id") for v in (cb.vulnerabilities or []) if isinstance(v, dict)}
        for v in (cb.vulnerabilities or []):
            if isinstance(v, dict) and v.get("id") not in vuln_ids_a:
                new_vulns.append({"component": cb.name, **v})
        for v in (ca.vulnerabilities or []):
            if isinstance(v, dict) and v.get("id") not in vuln_ids_b:
                resolved_vulns.append({"component": ca.name, **v})

    score_delta = (scan_b.risk_score or 0.0) - (scan_a.risk_score or 0.0)

    return ScanDiffOut(
        scan_id_a=scan_a.id, scan_id_b=scan_b.id,
        filename_a=scan_a.filename, filename_b=scan_b.filename,
        score_delta=score_delta,
        added=added, removed=removed, version_changed=version_changed,
        new_vulnerabilities=new_vulns, resolved_vulnerabilities=resolved_vulns,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/export/json")
async def export_scan_json(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> Response:
    """Export a scan result as a JSON file download."""
    scan_detail = await _fetch_scan_detail(scan_id, db, current_user)
    from app.exporters.json_exp import export_json
    content = export_json(scan_detail.model_dump())
    return Response(
        content=content, media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="verity-{scan_id}.json"'},
    )


@router.get("/{scan_id}/export/pdf")
async def export_scan_pdf(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> Response:
    """Export a scan result as a branded PDF report."""
    scan_detail = await _fetch_scan_detail(scan_id, db, current_user)
    from app.exporters.pdf import export_pdf
    content = export_pdf(scan_detail.model_dump())
    return Response(
        content=content, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="verity-{scan_id}.pdf"'},
    )


async def _fetch_scan_detail(
    scan_id: str, db: AsyncSession, current_user: Optional[User]
) -> ScanDetailOut:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")
    if settings.AUTH_ENABLED and current_user is not None:
        if scan.user_id and scan.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    comp_result = await db.execute(select(ScanComponent).where(ScanComponent.scan_id == scan_id))
    db_components = comp_result.scalars().all()
    component_outs = _build_component_outs_from_db(db_components)
    summary = scan.summary or {}
    validation_issues = [
        ValidationIssueOut(**issue) for issue in summary.get("validation_issues", [])
        if isinstance(issue, dict)
    ]
    return ScanDetailOut(
        id=scan.id, filename=scan.filename, sbom_format=scan.sbom_format,
        format_version=scan.format_version, created_at=scan.created_at,
        risk_level=scan.risk_level, risk_score=scan.risk_score,
        total_components=scan.total_components, vulnerable_components=scan.vulnerable_components,
        invalid_components=scan.invalid_components, ntia_compliant=scan.ntia_compliant,
        vuln_check_enabled=scan.vuln_check_enabled, summary=summary,
        quality_score=scan.quality_score, quality_grade=scan.quality_grade,
        components=component_outs, validation_issues=validation_issues,
        quality=_qs_dict_to_out(scan.category_scores, scan.quality_score, scan.quality_grade),
        compliance=_build_compliance_out(
            scan.ntia_result, scan.bsi_result, scan.fsct_result, scan.oct_result
        ),
        dependency_graph=_dep_graph_to_out(scan.dependency_graph),
        policy_result=_policy_result_to_out(scan.policy_result),
    )


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> None:
    """Delete a scan and all its associated components."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")
    if settings.AUTH_ENABLED and current_user is not None:
        if scan.user_id and scan.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    await db.delete(scan)


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------

def _get_comp_vulns(comp, vuln_results: dict) -> list:
    from app.core.vuln_checker import _component_key
    return vuln_results.get(_component_key(comp)) or []


def _components_to_dicts(components, vuln_results: dict) -> list[dict]:
    result = []
    for comp in components:
        vulns = _get_comp_vulns(comp, vuln_results)
        result.append({
            "name": comp.name,
            "version": comp.version,
            "purl": comp.purl,
            "licenses": comp.licenses,
            "supplier": comp.supplier,
            "vulnerabilities": vulns,
        })
    return result


def _build_component_outs(
    components, component_risks, component_validations, vuln_results: dict, scan_id: str
) -> list[ComponentOut]:
    risk_map = {cr.component_name: cr for cr in component_risks}
    validation_map = {cv.component_name: cv for cv in component_validations}
    outs = []
    for comp in components:
        cr = risk_map.get(comp.name)
        cv = validation_map.get(comp.name)
        vulns_raw = _get_comp_vulns(comp, vuln_results)
        vuln_outs = [_vuln_dict_to_out(v) for v in vulns_raw if isinstance(v, dict)]
        outs.append(ComponentOut(
            id=str(uuid.uuid4()), name=comp.name, version=comp.version,
            purl=comp.purl, cpe=comp.cpe, supplier=comp.supplier,
            licenses=comp.licenses, component_type=comp.component_type,
            risk_level=cr.risk_level if cr else "LOW",
            risk_score=cr.risk_score if cr else 0.0,
            missing_fields=cv.missing_fields if cv else [],
            vulnerabilities=vuln_outs,
        ))
    return outs


def _build_component_outs_from_db(db_components) -> list[ComponentOut]:
    outs = []
    for db_comp in db_components:
        vuln_outs = [
            _vuln_dict_to_out(v) for v in (db_comp.vulnerabilities or [])
            if isinstance(v, dict)
        ]
        outs.append(ComponentOut(
            id=db_comp.id, name=db_comp.name, version=db_comp.version,
            purl=db_comp.purl, cpe=db_comp.cpe, supplier=db_comp.supplier,
            licenses=db_comp.licenses, component_type=db_comp.component_type,
            risk_level=db_comp.risk_level, risk_score=db_comp.risk_score,
            missing_fields=db_comp.missing_fields, vulnerabilities=vuln_outs,
        ))
    return outs


def _vuln_dict_to_out(v: dict) -> VulnOut:
    return VulnOut(
        id=v.get("id", ""),
        summary=v.get("summary", ""),
        severity=v.get("severity", "UNKNOWN"),
        cvss_score=float(v.get("cvss_score") or 0.0),
        fixed_version=v.get("fixed_version"),
        published=v.get("published"),
        epss_score=v.get("epss_score"),
        epss_percentile=v.get("epss_percentile"),
        in_kev=bool(v.get("in_kev", False)),
    )


def _qs_to_out(qs: QualityScore) -> QualityScoreOut:
    cat_outs = []
    for cat in qs.categories:
        feat_outs = [
            FeatureResultOut(
                key=f.key, score=f.score, applicable=f.applicable,
                weight=f.weight, detail=f.detail,
            )
            for f in cat.features
        ]
        cat_outs.append(CategoryResultOut(
            name=cat.name, weight=cat.weight, score=cat.score,
            weighted_score=cat.weighted_score, features=feat_outs,
        ))
    return QualityScoreOut(overall_score=qs.overall_score, grade=qs.grade, categories=cat_outs)


def _qs_dict_to_out(
    qs_dict: Optional[dict], quality_score: Optional[float], quality_grade: Optional[str]
) -> Optional[QualityScoreOut]:
    if quality_score is None:
        return None
    if not qs_dict:
        return QualityScoreOut(overall_score=quality_score or 0.0, grade=quality_grade or "F")
    cats_raw = qs_dict.get("categories") or []
    cat_outs = []
    for cat in cats_raw:
        feats = [
            FeatureResultOut(
                key=f.get("key", ""), score=f.get("score", 0.0), applicable=f.get("applicable", True),
                weight=f.get("weight", 1.0), detail=f.get("detail", ""),
            )
            for f in (cat.get("features") or [])
        ]
        cat_outs.append(CategoryResultOut(
            name=cat.get("name", ""), weight=cat.get("weight", 0),
            score=cat.get("score", 0.0), weighted_score=cat.get("weighted_score", 0.0),
            features=feats,
        ))
    return QualityScoreOut(
        overall_score=qs_dict.get("overall_score", quality_score or 0.0),
        grade=qs_dict.get("grade", quality_grade or "F"),
        categories=cat_outs,
    )


def _build_compliance_out(
    ntia_dict: Optional[dict],
    bsi_dict: Optional[dict],
    fsct_dict: Optional[dict],
    oct_dict: Optional[dict],
) -> Optional[ComplianceSummaryOut]:
    if not any([ntia_dict, bsi_dict, fsct_dict, oct_dict]):
        return None
    return ComplianceSummaryOut(
        ntia=_ntia_dict_to_out(ntia_dict),
        bsi_v21=_bsi_dict_to_out(bsi_dict),
        fsct=_fsct_dict_to_out(fsct_dict),
        oct=_oct_dict_to_out(oct_dict),
    )


def _record_dicts_to_out(records_raw: list) -> list[ComplianceRecordOut]:
    outs = []
    for r in records_raw:
        if not isinstance(r, dict):
            continue
        outs.append(ComplianceRecordOut(
            check_key=r.get("check_key", ""),
            tier=r.get("tier", "required"),
            score=float(r.get("score", 0.0)),
            applicable=bool(r.get("applicable", True)),
            subject_id=r.get("subject_id", ""),
            found_value=r.get("found_value", ""),
            expected=r.get("expected", ""),
            detail=r.get("detail", ""),
        ))
    return outs


def _ntia_dict_to_out(d: Optional[dict]) -> Optional[NTIAResultOut]:
    if not d:
        return None
    elements_raw = d.get("elements") or []
    elements = [
        NTIAElementOut(
            element_name=e.get("element_name", ""),
            compliant=bool(e.get("compliant", False)),
            score=float(e.get("score", 0.0)),
            failing_components=e.get("failing_components") or [],
            detail=e.get("detail", ""),
        )
        for e in elements_raw
        if isinstance(e, dict)
    ]
    return NTIAResultOut(
        overall_compliant=bool(d.get("overall_compliant", False)),
        overall_score=float(d.get("overall_score", 0.0)),
        elements=elements,
    )


def _bsi_dict_to_out(d: Optional[dict]) -> Optional[BSIResultOut]:
    if not d:
        return None
    return BSIResultOut(
        standard=d.get("standard", "BSI TR-03183-2"),
        overall_score=float(d.get("overall_score", 0.0)),
        compliant=bool(d.get("compliant", False)),
        required_passed=int(d.get("required_passed", 0)),
        required_total=int(d.get("required_total", 0)),
        additional_passed=int(d.get("additional_passed", 0)),
        additional_total=int(d.get("additional_total", 0)),
        records=_record_dicts_to_out(d.get("records") or []),
    )


def _fsct_dict_to_out(d: Optional[dict]) -> Optional[FSCTResultOut]:
    if not d:
        return None
    return FSCTResultOut(
        standard=d.get("standard", "FSCT v3"),
        overall_score=float(d.get("overall_score", 0.0)),
        records=_record_dicts_to_out(d.get("records") or []),
    )


def _oct_dict_to_out(d: Optional[dict]) -> Optional[OCTResultOut]:
    if not d:
        return None
    return OCTResultOut(
        standard=d.get("standard", "OpenChain Telco v1.1"),
        overall_score=float(d.get("overall_score", 0.0)),
        spdx_only_fail=bool(d.get("spdx_only_fail", False)),
        records=_record_dicts_to_out(d.get("records") or []),
    )


def _dep_graph_to_out(d: Optional[dict]) -> Optional[DependencyGraphOut]:
    if not d:
        return None
    return DependencyGraphOut(
        nodes=d.get("nodes") or [],
        edges=d.get("edges") or [],
        primary_component_ref=d.get("primary_component_ref"),
        orphans=d.get("orphans") or [],
        is_complete=bool(d.get("is_complete", False)),
        max_depth=int(d.get("max_depth", 0)),
    )


def _policy_result_to_out(d: Optional[dict]) -> Optional[PolicyResultOut]:
    if not d:
        return None
    outcomes = [
        PolicyRuleOutcome(
            rule_id=o.get("rule_id", ""),
            description=o.get("description", ""),
            action=o.get("action", "warn"),
            triggered=bool(o.get("triggered", False)),
            detail=o.get("detail", ""),
        )
        for o in (d.get("outcomes") or [])
        if isinstance(o, dict)
    ]
    return PolicyResultOut(overall=d.get("overall", "pass"), outcomes=outcomes)
