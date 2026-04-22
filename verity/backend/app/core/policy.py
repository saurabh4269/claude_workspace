"""
Policy engine for Verity.

Evaluates workspace-level YAML rules against a completed scan result.
Rule types: license_denylist, license_allowlist, threshold, vulnerability,
            component_denylist.

Actions: warn | fail
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ---------------------------------------------------------------------------
# Policy result types
# ---------------------------------------------------------------------------

@dataclass
class RuleOutcome:
    rule_id: str
    description: str
    action: str          # "warn" | "fail"
    triggered: bool
    detail: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "action": self.action,
            "triggered": self.triggered,
            "detail": self.detail,
        }


@dataclass
class PolicyResult:
    overall: str         # "pass" | "warn" | "fail"
    outcomes: list[RuleOutcome]

    def to_dict(self) -> dict:
        return {
            "overall": self.overall,
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


# ---------------------------------------------------------------------------
# Policy parser
# ---------------------------------------------------------------------------

def parse_policy(yaml_text: str) -> list[dict]:
    """Parse YAML policy text into a list of rule dicts."""
    if not _YAML_AVAILABLE:
        logger.warning("PyYAML not installed — policy evaluation skipped")
        return []
    try:
        data = yaml.safe_load(yaml_text)
        if not isinstance(data, dict):
            return []
        rules = data.get("rules") or []
        return [r for r in rules if isinstance(r, dict)]
    except Exception as exc:
        logger.warning("Failed to parse policy YAML: %s", exc)
        return []


_DEFAULT_POLICY_YAML = """
name: Default Policy
rules: []
"""


# ---------------------------------------------------------------------------
# Policy evaluator
# ---------------------------------------------------------------------------

def evaluate_policy(
    rules: list[dict],
    scan_data: dict,
) -> PolicyResult:
    """
    Evaluate a list of policy rules against a scan result dict.

    scan_data keys expected:
      - quality_score: float
      - risk_score: float
      - risk_level: str
      - components: list of component dicts (name, purl, licenses, risk_score,
                    vulnerabilities)
      - category_scores: dict from quality scorer
    """
    outcomes: list[RuleOutcome] = []

    for rule in rules:
        rule_id = rule.get("id") or "unnamed"
        description = rule.get("description") or rule_id
        action = (rule.get("action") or "warn").lower()
        rule_type = (rule.get("type") or "").lower()

        try:
            triggered, detail = _evaluate_rule(rule, rule_type, scan_data)
        except Exception as exc:
            logger.warning("Rule %s evaluation error: %s", rule_id, exc)
            triggered, detail = False, f"Evaluation error: {exc}"

        outcomes.append(RuleOutcome(
            rule_id=rule_id,
            description=description,
            action=action,
            triggered=triggered,
            detail=detail,
        ))

    # Determine overall status
    if any(o.triggered and o.action == "fail" for o in outcomes):
        overall = "fail"
    elif any(o.triggered and o.action == "warn" for o in outcomes):
        overall = "warn"
    else:
        overall = "pass"

    return PolicyResult(overall=overall, outcomes=outcomes)


def _evaluate_rule(rule: dict, rule_type: str, scan_data: dict) -> tuple[bool, str]:
    components = scan_data.get("components") or []

    if rule_type == "license_denylist":
        denied = [str(l).upper() for l in (rule.get("licenses") or [])]
        violating = []
        for comp in components:
            for lic in (comp.get("licenses") or []):
                if lic.upper() in denied:
                    violating.append(f"{comp.get('name', '?')} ({lic})")
        if violating:
            return True, f"Denied licenses found: {', '.join(violating[:5])}"
        return False, "No denied licenses found"

    if rule_type == "license_allowlist":
        allowed = {str(l).upper() for l in (rule.get("licenses") or [])}
        violating = []
        for comp in components:
            for lic in (comp.get("licenses") or []):
                if lic.upper() not in allowed and not lic.startswith("LicenseRef-"):
                    violating.append(f"{comp.get('name', '?')} ({lic})")
        if violating:
            return True, f"Licenses outside allowlist: {', '.join(violating[:5])}"
        return False, "All licenses within allowlist"

    if rule_type == "component_denylist":
        patterns = [str(p) for p in (rule.get("patterns") or rule.get("names") or [])]
        violating = []
        for comp in components:
            name = comp.get("name") or ""
            purl = comp.get("purl") or ""
            for pat in patterns:
                if fnmatch.fnmatch(name.lower(), pat.lower()) or fnmatch.fnmatch(purl.lower(), pat.lower()):
                    violating.append(name)
                    break
        if violating:
            return True, f"Denied components found: {', '.join(violating[:5])}"
        return False, "No denied components"

    if rule_type == "threshold":
        metric = rule.get("metric") or ""
        operator = (rule.get("operator") or "lt").lower()
        threshold = float(rule.get("value") or 0)
        actual = _get_metric(metric, scan_data)
        triggered = _compare(actual, operator, threshold)
        return triggered, f"{metric} = {actual:.2f} (threshold: {operator} {threshold})"

    if rule_type == "vulnerability":
        severity_filter = (rule.get("severity") or "").upper()
        epss_min = float(rule.get("epss_min") or 0)
        kev_only = bool(rule.get("kev_only") or False)
        matching = []
        for comp in components:
            for vuln in (comp.get("vulnerabilities") or []):
                sev = (vuln.get("severity") or "").upper()
                epss = float(vuln.get("epss_score") or 0)
                in_kev = bool(vuln.get("in_kev"))
                sev_match = not severity_filter or sev == severity_filter
                epss_match = epss >= epss_min
                kev_match = (not kev_only) or in_kev
                if sev_match and epss_match and kev_match:
                    matching.append(f"{comp.get('name', '?')}: {vuln.get('id', '?')}")
        if matching:
            return True, f"Matching vulnerabilities: {', '.join(matching[:5])}"
        return False, "No matching vulnerabilities"

    return False, f"Unknown rule type: {rule_type}"


def _get_metric(metric: str, scan_data: dict) -> float:
    # Flat metrics
    flat = {
        "quality_score": float(scan_data.get("quality_score") or 0),
        "risk_score": float(scan_data.get("risk_score") or 0),
    }
    if metric in flat:
        return flat[metric]

    # Category score: e.g. "licensing_score"
    category_scores = scan_data.get("category_scores") or {}
    if isinstance(category_scores, dict):
        cats = category_scores.get("categories") or []
        for cat in cats:
            cat_name = (cat.get("name") or "").lower().replace(" ", "_").replace("&", "")
            if metric.replace("_score", "") in cat_name:
                return float(cat.get("score") or 0)

    # Per-component ratios computed on the fly
    components = scan_data.get("components") or []
    n = len(components)
    if n == 0:
        return 0.0

    ratios = {
        "comp_with_version": sum(1 for c in components if c.get("version")) / n,
        "comp_with_purl": sum(1 for c in components if c.get("purl")) / n,
        "comp_with_supplier": sum(1 for c in components if c.get("supplier")) / n,
        "comp_with_license": sum(1 for c in components if c.get("licenses")) / n,
    }
    return ratios.get(metric, 0.0)


def _compare(actual: float, operator: str, threshold: float) -> bool:
    if operator == "lt":
        return actual < threshold
    if operator == "lte":
        return actual <= threshold
    if operator == "gt":
        return actual > threshold
    if operator == "gte":
        return actual >= threshold
    if operator == "eq":
        return actual == threshold
    return False
