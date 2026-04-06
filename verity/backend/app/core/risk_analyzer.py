"""
Risk analyzer for Verity.
Scores each component and produces an overall document risk level.
"""

from dataclasses import dataclass, field
from typing import Optional

from app.core.parser import SBOMDocument, Component


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ComponentRisk:
    component_name: str
    risk_level: str
    risk_score: float
    factors: list[str]  # Human-readable risk factors


@dataclass
class RiskReport:
    overall_risk_level: str
    overall_risk_score: float
    component_risks: list[ComponentRisk]
    summary: dict  # Counts per risk level: {"LOW": n, "MEDIUM": n, "HIGH": n, "CRITICAL": n}


# ---------------------------------------------------------------------------
# License classification
# ---------------------------------------------------------------------------

# AGPL and SSPL carry the highest copyleft risk for most commercial use cases
_CRITICAL_COPYLEFT = {"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"}

# GPL-2.0 and GPL-3.0 are strong copyleft but not network-copyleft
_HIGH_COPYLEFT = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "GPL-2.0+",
    "GPL-3.0+",
}

# LGPL and MPL are weak copyleft
_MEDIUM_COPYLEFT = {
    "LGPL-2.0",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-1.0",
    "MPL-1.1",
    "MPL-2.0",
    "EUPL-1.0",
    "EUPL-1.1",
    "EUPL-1.2",
    "CDDL-1.0",
    "CDDL-1.1",
    "EPL-1.0",
    "EPL-2.0",
}


def _classify_license(license_id: str) -> Optional[tuple[str, int]]:
    """
    Return (severity_label, points) if a license is copyleft, else None.
    Performs prefix matching to catch variants like "GPL-3.0-only".
    """
    # Normalize: strip whitespace and common suffixes used in SPDX expressions
    normalized = license_id.strip().replace(" ", "-")

    for lic in _CRITICAL_COPYLEFT:
        if normalized.upper() == lic.upper() or normalized.upper().startswith(lic.upper()):
            return ("CRITICAL copyleft license (AGPL/SSPL)", 30)

    for lic in _HIGH_COPYLEFT:
        if normalized.upper() == lic.upper() or normalized.upper().startswith(lic.upper()):
            return ("HIGH copyleft license (GPL)", 20)

    for lic in _MEDIUM_COPYLEFT:
        if normalized.upper() == lic.upper() or normalized.upper().startswith(lic.upper()):
            return ("MEDIUM copyleft license (LGPL/MPL)", 10)

    return None


# ---------------------------------------------------------------------------
# Score to risk level mapping
# ---------------------------------------------------------------------------

def _score_to_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 21:
        return "MEDIUM"
    return "LOW"


_LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ---------------------------------------------------------------------------
# Main analyze function
# ---------------------------------------------------------------------------

def analyze(
    doc: SBOMDocument,
    vuln_results: Optional[dict] = None,
) -> RiskReport:
    """
    Analyze risk for all components in the SBOM document.

    Args:
        doc: Parsed SBOMDocument.
        vuln_results: Optional mapping of component identifier (purl or name@version)
            to a list of vulnerability dicts. Each vuln dict should contain at least
            {"id": str, "cvss_score": float}.

    Returns:
        RiskReport with per-component and overall risk assessment.
    """
    if vuln_results is None:
        vuln_results = {}

    component_risks: list[ComponentRisk] = []

    for comp in doc.components:
        comp_risk = _score_component(comp, vuln_results)
        component_risks.append(comp_risk)

    # Overall risk level = highest component level, escalated if many HIGH+ components
    overall_level = _compute_overall_level(component_risks)

    # Overall risk score = mean of component scores (or 0 if no components)
    if component_risks:
        overall_score = sum(cr.risk_score for cr in component_risks) / len(component_risks)
    else:
        overall_score = 0.0

    summary = {
        "LOW": sum(1 for cr in component_risks if cr.risk_level == "LOW"),
        "MEDIUM": sum(1 for cr in component_risks if cr.risk_level == "MEDIUM"),
        "HIGH": sum(1 for cr in component_risks if cr.risk_level == "HIGH"),
        "CRITICAL": sum(1 for cr in component_risks if cr.risk_level == "CRITICAL"),
    }

    return RiskReport(
        overall_risk_level=overall_level,
        overall_risk_score=round(overall_score, 2),
        component_risks=component_risks,
        summary=summary,
    )


def _score_component(comp: Component, vuln_results: dict) -> ComponentRisk:
    """Score a single component and return its ComponentRisk."""
    score = 0.0
    factors: list[str] = []

    # Missing version
    if not comp.version:
        score += 15
        factors.append("Missing version (+15)")

    # Missing unique identifier (PURL and CPE both absent)
    if not comp.purl and not comp.cpe:
        score += 20
        factors.append("Missing PURL and CPE (+20)")

    # Missing supplier
    if not comp.supplier:
        score += 10
        factors.append("Missing supplier (+10)")

    # No license information
    if not comp.licenses:
        score += 10
        factors.append("No license information (+10)")
    else:
        # Check copyleft risk across all licenses listed
        copyleft_seen: set[str] = set()
        for lic in comp.licenses:
            result = _classify_license(lic)
            if result and lic not in copyleft_seen:
                label, points = result
                score += points
                factors.append(f"{label}: {lic} (+{points})")
                copyleft_seen.add(lic)

    # Vulnerability risk
    # Look up by PURL first, then by name@version
    vuln_key = comp.purl or (
        f"{comp.name}@{comp.version}" if comp.version else comp.name
    )
    vulns = vuln_results.get(vuln_key) or []

    # Also try name@version if purl lookup returned nothing
    if not vulns and comp.purl and comp.version:
        fallback_key = f"{comp.name}@{comp.version}"
        vulns = vuln_results.get(fallback_key) or []

    for vuln in vulns:
        cvss = float(vuln.get("cvss_score") or 0.0)
        vuln_id = vuln.get("id") or "unknown"
        if cvss >= 9.0:
            score += 50
            factors.append(f"CRITICAL vulnerability {vuln_id} CVSS {cvss} (+50)")
        elif cvss >= 7.0:
            score += 35
            factors.append(f"HIGH vulnerability {vuln_id} CVSS {cvss} (+35)")
        elif cvss >= 4.0:
            score += 20
            factors.append(f"MEDIUM vulnerability {vuln_id} CVSS {cvss} (+20)")
        else:
            score += 10
            factors.append(f"LOW vulnerability {vuln_id} CVSS {cvss} (+10)")

    risk_level = _score_to_level(score)

    return ComponentRisk(
        component_name=comp.name,
        risk_level=risk_level,
        risk_score=round(score, 2),
        factors=factors,
    )


def _compute_overall_level(component_risks: list[ComponentRisk]) -> str:
    """
    Determine overall document risk level.
    Uses the highest individual component risk level, then escalates
    if more than 30% of components are HIGH or CRITICAL.
    """
    if not component_risks:
        return "LOW"

    # Start with the highest component level
    max_level = max(
        (_LEVEL_ORDER.get(cr.risk_level, 0) for cr in component_risks),
        default=0,
    )
    overall = list(_LEVEL_ORDER.keys())[max_level]

    # Escalation: if >30% are HIGH or CRITICAL, bump up one level
    total = len(component_risks)
    high_or_critical = sum(
        1 for cr in component_risks
        if _LEVEL_ORDER.get(cr.risk_level, 0) >= _LEVEL_ORDER["HIGH"]
    )
    if total > 0 and (high_or_critical / total) > 0.30:
        current_order = _LEVEL_ORDER.get(overall, 0)
        escalated_order = min(current_order + 1, 3)
        overall = [k for k, v in _LEVEL_ORDER.items() if v == escalated_order][0]

    return overall
