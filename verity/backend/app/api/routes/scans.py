"""
Scan routes for Verity.
Handles SBOM file upload, processing, retrieval, and deletion.
"""

import json
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
    ComponentOut,
    ScanDetailOut,
    ScanListOut,
    ScanOut,
    ValidationIssueOut,
    VulnOut,
)
from app.config import settings
from app.core.parser import ParseError, parse
from app.core.risk_analyzer import analyze
from app.core.validator import validate
from app.core.vuln_checker import check_vulnerabilities
from app.db.models import Scan, ScanComponent, User

router = APIRouter(prefix="/scans", tags=["scans"])

# Allowed file extensions for SBOM uploads
_ALLOWED_EXTENSIONS = {".json", ".xml", ".spdx", ".tv"}


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

@router.post("/upload", response_model=ScanDetailOut, status_code=status.HTTP_201_CREATED)
async def upload_scan(
    file: UploadFile = File(...),
    vuln_check: bool = Form(default=True),
    save_to_history: bool = Form(default=True),
    workspace_id: Optional[str] = Form(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> ScanDetailOut:
    """
    Upload an SBOM file for validation and risk assessment.

    Supports CycloneDX JSON/XML and SPDX JSON/tag-value formats.
    Performs NTIA compliance checking, risk scoring, and optional
    vulnerability lookup against OSV.dev.
    """
    filename = file.filename or "unknown"

    # Validate file extension
    lower_name = filename.lower()
    if not any(lower_name.endswith(ext) for ext in _ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Unsupported file type. Allowed extensions: "
                f"{', '.join(sorted(_ALLOWED_EXTENSIONS))}"
            ),
        )

    # Read and validate file size
    content_bytes = await file.read()
    if len(content_bytes) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB} MB"
            ),
        )

    try:
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Could not decode file content as UTF-8: {exc}",
        ) from exc

    # Parse the SBOM
    try:
        doc = parse(content, filename=filename)
    except ParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    # Validate against NTIA and format spec
    validation_result = validate(doc)

    # Check vulnerabilities
    effective_vuln_check = vuln_check and settings.VULN_CHECK_ENABLED
    vuln_results: dict = {}
    if effective_vuln_check:
        vuln_results = await check_vulnerabilities(doc.components, enabled=True)

    # Analyze risk
    risk_report = analyze(doc, vuln_results=vuln_results)

    # Count vulnerable components
    vulnerable_count = sum(
        1
        for comp in doc.components
        if _get_comp_vulns(comp, vuln_results)
    )

    # Count invalid components (at least one NTIA ERROR)
    invalid_count = sum(
        1
        for cv in validation_result.component_results
        if any(i.severity == "ERROR" for i in cv.issues)
    )

    # Build summary dict
    summary = {
        "risk_distribution": risk_report.summary,
        "ntia_issue_count": sum(
            1 for i in validation_result.issues if i.severity == "ERROR"
        ),
        "format": doc.format,
        "spec_version": doc.spec_version,
    }

    # Persist to DB if requested
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
        )
        scan.summary = summary
        db.add(scan)
        await db.flush()

        # Persist components
        for i, (comp, comp_risk) in enumerate(
            zip(doc.components, risk_report.component_risks)
        ):
            comp_id = str(uuid.uuid4())
            # Find validation result for this component
            comp_validation = next(
                (cv for cv in validation_result.component_results
                 if cv.component_name == comp.name),
                None,
            )
            missing_fields = comp_validation.missing_fields if comp_validation else []
            vulns = _get_comp_vulns(comp, vuln_results)

            db_comp = ScanComponent(
                id=comp_id,
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

    # Build response without hitting DB again
    component_outs = _build_component_outs(
        doc.components,
        risk_report.component_risks,
        validation_result.component_results,
        vuln_results,
        scan_id if should_save else str(uuid.uuid4()),
    )

    validation_issue_outs = [
        ValidationIssueOut(
            severity=issue.severity,
            code=issue.code,
            message=issue.message,
            component_name=issue.component_name,
        )
        for issue in validation_result.issues
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
        components=component_outs,
        validation_issues=validation_issue_outs,
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

    # Count total
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar_one()

    # Paginate
    offset = (page - 1) * per_page
    query = query.order_by(Scan.created_at.desc()).offset(offset).limit(per_page)
    result = await db.execute(query)
    scans = result.scalars().all()

    items = [
        ScanOut(
            id=s.id,
            filename=s.filename,
            sbom_format=s.sbom_format,
            format_version=s.format_version,
            created_at=s.created_at,
            risk_level=s.risk_level,
            risk_score=s.risk_score,
            total_components=s.total_components,
            vulnerable_components=s.vulnerable_components,
            invalid_components=s.invalid_components,
            ntia_compliant=s.ntia_compliant,
            vuln_check_enabled=s.vuln_check_enabled,
            summary=s.summary,
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
    """Retrieve a scan by ID, including all components and validation issues."""
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.components))
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )

    if settings.AUTH_ENABLED and current_user is not None:
        if scan.user_id and scan.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to view this scan",
            )

    component_outs = _build_component_outs_from_db(scan.components)

    # Validation issues are stored in the summary dict
    issues_raw = scan.summary.get("validation_issues") or []
    validation_issue_outs = [
        ValidationIssueOut(**issue) for issue in issues_raw if isinstance(issue, dict)
    ]

    return ScanDetailOut(
        id=scan.id,
        filename=scan.filename,
        sbom_format=scan.sbom_format,
        format_version=scan.format_version,
        created_at=scan.created_at,
        risk_level=scan.risk_level,
        risk_score=scan.risk_score,
        total_components=scan.total_components,
        vulnerable_components=scan.vulnerable_components,
        invalid_components=scan.invalid_components,
        ntia_compliant=scan.ntia_compliant,
        vuln_check_enabled=scan.vuln_check_enabled,
        summary=scan.summary,
        components=component_outs,
        validation_issues=validation_issue_outs,
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
        content=content,
        media_type="application/json",
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
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="verity-{scan_id}.pdf"'},
    )


async def _fetch_scan_detail(
    scan_id: str,
    db: AsyncSession,
    current_user: Optional[User],
) -> ScanDetailOut:
    """Shared helper: fetch a scan + components and return ScanDetailOut."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")

    if settings.AUTH_ENABLED and current_user is not None:
        if scan.user_id and scan.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    comp_result = await db.execute(
        select(ScanComponent).where(ScanComponent.scan_id == scan_id)
    )
    db_components = comp_result.scalars().all()
    component_outs = _build_component_outs_from_db(db_components)
    summary = scan.summary or {}
    validation_issues = [
        ValidationIssueOut(**issue) for issue in summary.get("validation_issues", [])
        if isinstance(issue, dict)
    ]
    return ScanDetailOut(
        id=scan.id,
        filename=scan.filename,
        sbom_format=scan.sbom_format,
        format_version=scan.format_version,
        created_at=scan.created_at,
        risk_level=scan.risk_level,
        risk_score=scan.risk_score,
        total_components=scan.total_components,
        vulnerable_components=scan.vulnerable_components,
        invalid_components=scan.invalid_components,
        ntia_compliant=scan.ntia_compliant,
        vuln_check_enabled=scan.vuln_check_enabled,
        summary=summary,
        components=component_outs,
        validation_issues=validation_issues,
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )

    if settings.AUTH_ENABLED and current_user is not None:
        if scan.user_id and scan.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to delete this scan",
            )

    await db.delete(scan)


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def _get_comp_vulns(comp, vuln_results: dict) -> list:
    """Return vulnerability list for a component from vuln_results."""
    from app.core.vuln_checker import _component_key
    key = _component_key(comp)
    return vuln_results.get(key) or []


def _build_component_outs(
    components,
    component_risks,
    component_validations,
    vuln_results: dict,
    scan_id: str,
) -> list[ComponentOut]:
    """Build ComponentOut list from parsed data (before DB persistence)."""
    outs = []
    risk_map = {cr.component_name: cr for cr in component_risks}
    validation_map = {cv.component_name: cv for cv in component_validations}

    for comp in components:
        cr = risk_map.get(comp.name)
        cv = validation_map.get(comp.name)
        vulns_raw = _get_comp_vulns(comp, vuln_results)
        vuln_outs = [
            VulnOut(
                id=v.get("id", ""),
                summary=v.get("summary", ""),
                severity=v.get("severity", "UNKNOWN"),
                cvss_score=float(v.get("cvss_score") or 0.0),
                fixed_version=v.get("fixed_version"),
                published=v.get("published"),
            )
            for v in vulns_raw
        ]
        outs.append(
            ComponentOut(
                id=str(uuid.uuid4()),
                name=comp.name,
                version=comp.version,
                purl=comp.purl,
                cpe=comp.cpe,
                supplier=comp.supplier,
                licenses=comp.licenses,
                component_type=comp.component_type,
                risk_level=cr.risk_level if cr else "LOW",
                risk_score=cr.risk_score if cr else 0.0,
                missing_fields=cv.missing_fields if cv else [],
                vulnerabilities=vuln_outs,
            )
        )
    return outs


def _build_component_outs_from_db(db_components) -> list[ComponentOut]:
    """Build ComponentOut list from DB ScanComponent records."""
    outs = []
    for db_comp in db_components:
        vulns_raw = db_comp.vulnerabilities or []
        vuln_outs = [
            VulnOut(
                id=v.get("id", ""),
                summary=v.get("summary", ""),
                severity=v.get("severity", "UNKNOWN"),
                cvss_score=float(v.get("cvss_score") or 0.0),
                fixed_version=v.get("fixed_version"),
                published=v.get("published"),
            )
            for v in vulns_raw
            if isinstance(v, dict)
        ]
        outs.append(
            ComponentOut(
                id=db_comp.id,
                name=db_comp.name,
                version=db_comp.version,
                purl=db_comp.purl,
                cpe=db_comp.cpe,
                supplier=db_comp.supplier,
                licenses=db_comp.licenses,
                component_type=db_comp.component_type,
                risk_level=db_comp.risk_level,
                risk_score=db_comp.risk_score,
                missing_fields=db_comp.missing_fields,
                vulnerabilities=vuln_outs,
            )
        )
    return outs
