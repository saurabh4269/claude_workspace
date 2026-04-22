"""
CI/CD integration endpoint for Verity.
Designed for automated pipelines — returns a pass/fail result with
machine-readable details instead of the full scan payload.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.deps import get_current_user, get_db
from app.api.schemas import CIScanOut
from app.config import settings
from app.core.compliance import check_ntia
from app.core.parser import ParseError, parse
from app.core.policy import evaluate_policy, parse_policy
from app.core.risk_analyzer import analyze
from app.core.scorer import score
from app.core.validator import validate
from app.core.vuln_checker import check_vulnerabilities
from app.db.models import User, WorkspacePolicy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ci", tags=["ci"])

_ALLOWED_EXTENSIONS = {".json", ".xml", ".spdx", ".tv"}


@router.post("/scan", response_model=CIScanOut)
async def ci_scan(
    file: UploadFile = File(...),
    workspace_id: Optional[str] = Form(default=None),
    fail_on_policy: bool = Form(default=True),
    fail_on_critical: bool = Form(default=True),
    min_quality_score: Optional[float] = Form(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> CIScanOut:
    """
    Lightweight CI endpoint — parses, scores, and evaluates policy.
    Returns pass/fail with a summary suitable for CI pipelines.
    """
    filename = file.filename or "unknown"
    lower_name = filename.lower()
    if not any(lower_name.endswith(ext) for ext in _ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported file type: {filename}",
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
        raise HTTPException(status_code=422, detail=f"Could not decode file: {exc}") from exc

    try:
        doc = parse(content, filename=filename)
    except ParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    validation_result = validate(doc)

    vuln_results: dict = {}
    if settings.VULN_CHECK_ENABLED:
        vuln_results = await check_vulnerabilities(doc.components, enabled=True)

    risk_report = analyze(doc, vuln_results=vuln_results)

    qs = None
    overall_score = None
    grade = None
    try:
        qs = score(doc)
        overall_score = qs.overall_score
        grade = qs.grade
    except Exception as exc:
        logger.warning("Quality scoring failed in CI: %s", exc)

    ntia_compliant = validation_result.ntia_compliant

    # Policy evaluation
    policy_overall: Optional[str] = None
    policy_failures: list[str] = []
    if workspace_id:
        try:
            pol_result = await db.execute(
                select(WorkspacePolicy).where(WorkspacePolicy.workspace_id == workspace_id)
            )
            pol_row = pol_result.scalar_one_or_none()
            if pol_row:
                rules = parse_policy(pol_row.policy_yaml)
                if rules:
                    comp_dicts = [
                        {
                            "name": c.name, "version": c.version, "purl": c.purl,
                            "licenses": c.licenses, "supplier": c.supplier,
                            "vulnerabilities": _get_comp_vulns(c, vuln_results),
                        }
                        for c in doc.components
                    ]
                    scan_data = {
                        "quality_score": overall_score or 0.0,
                        "risk_score": risk_report.overall_risk_score,
                        "risk_level": risk_report.overall_risk_level,
                        "components": comp_dicts,
                    }
                    pol_eval = evaluate_policy(rules, scan_data)
                    policy_overall = pol_eval.overall
                    policy_failures = [
                        o.detail for o in pol_eval.outcomes
                        if o.triggered and o.action == "fail"
                    ]
        except Exception as exc:
            logger.warning("CI policy evaluation failed: %s", exc)

    # Determine pass/fail
    passed = True
    if fail_on_critical and risk_report.overall_risk_level == "CRITICAL":
        passed = False
    if fail_on_policy and policy_overall == "fail":
        passed = False
    if min_quality_score is not None and (overall_score or 0.0) < min_quality_score:
        passed = False

    return CIScanOut(
        filename=filename,
        overall_score=overall_score,
        grade=grade,
        risk_level=risk_report.overall_risk_level,
        ntia_compliant=ntia_compliant,
        policy_result=policy_overall,
        policy_failures=policy_failures,
        passed=passed,
    )


def _get_comp_vulns(comp, vuln_results: dict) -> list:
    from app.core.vuln_checker import _component_key
    return vuln_results.get(_component_key(comp)) or []
