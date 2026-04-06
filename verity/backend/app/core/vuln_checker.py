"""
Vulnerability checker for Verity.
Queries OSV.dev (primary) and optionally NVD for CVE enrichment.
Uses async httpx with batching and exponential backoff.
"""

import asyncio
import logging
from typing import Optional

import httpx

from app.config import settings
from app.core.parser import Component

logger = logging.getLogger(__name__)

# In-process cache: key = purl or "name@version@ecosystem", value = list of vuln dicts
_cache: dict[str, list[dict]] = {}

# Maximum components per OSV batch request
_OSV_BATCH_SIZE = 1000

# Backoff delays in seconds for rate-limit / transient errors
_BACKOFF_DELAYS = [2, 4, 8]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def check_vulnerabilities(
    components: list[Component],
    enabled: bool = True,
) -> dict:
    """
    Check all components for known vulnerabilities.

    Args:
        components: List of parsed components.
        enabled: If False, returns an empty dict immediately.

    Returns:
        Dict mapping component identifier (purl or name@version) to a list
        of vulnerability dicts:
        {
            "id": str,
            "summary": str,
            "severity": str,
            "cvss_score": float,
            "fixed_version": str | None,
            "published": str | None,
        }
    """
    if not enabled or not components:
        return {}

    results: dict[str, list[dict]] = {}

    # Separate components that have a PURL from those that do not
    purl_components: list[Component] = []
    name_components: list[Component] = []

    for comp in components:
        key = _component_key(comp)
        if key in _cache:
            results[key] = _cache[key]
        elif comp.purl:
            purl_components.append(comp)
        else:
            name_components.append(comp)

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Query components with PURLs via OSV batch API
        if purl_components:
            batch_results = await _query_osv_purl_batch(client, purl_components)
            results.update(batch_results)

        # Query components without PURLs by name + version
        if name_components:
            batch_results = await _query_osv_name_batch(client, name_components)
            results.update(batch_results)

        # Optional NVD enrichment for any CVE IDs found in OSV results
        if settings.nvd_enabled and settings.NVD_API_KEY:
            await _enrich_with_nvd(client, results, settings.NVD_API_KEY)

    # Populate cache
    for key, vulns in results.items():
        _cache[key] = vulns

    return results


# ---------------------------------------------------------------------------
# OSV batch queries
# ---------------------------------------------------------------------------

async def _query_osv_purl_batch(
    client: httpx.AsyncClient,
    components: list[Component],
) -> dict:
    """Batch query OSV for components that have a PURL."""
    results: dict[str, list[dict]] = {}

    for batch_start in range(0, len(components), _OSV_BATCH_SIZE):
        batch = components[batch_start : batch_start + _OSV_BATCH_SIZE]
        queries = [{"package": {"purl": comp.purl}} for comp in batch]

        raw_responses = await _osv_querybatch(client, queries)
        if raw_responses is None:
            # On failure, mark all in batch as empty
            for comp in batch:
                results[_component_key(comp)] = []
            continue

        for comp, resp in zip(batch, raw_responses):
            key = _component_key(comp)
            vulns = _parse_osv_response(resp)
            results[key] = vulns

    return results


async def _query_osv_name_batch(
    client: httpx.AsyncClient,
    components: list[Component],
) -> dict:
    """
    Batch query OSV for components without PURLs.
    Uses name + version fallback. Ecosystem is guessed from component type
    or left unset (OSV will search across all ecosystems).
    """
    results: dict[str, list[dict]] = {}

    for batch_start in range(0, len(components), _OSV_BATCH_SIZE):
        batch = components[batch_start : batch_start + _OSV_BATCH_SIZE]
        queries = []
        for comp in batch:
            query: dict = {"package": {"name": comp.name}}
            ecosystem = _guess_ecosystem(comp)
            if ecosystem:
                query["package"]["ecosystem"] = ecosystem
            if comp.version:
                query["version"] = comp.version
            queries.append(query)

        raw_responses = await _osv_querybatch(client, queries)
        if raw_responses is None:
            for comp in batch:
                results[_component_key(comp)] = []
            continue

        for comp, resp in zip(batch, raw_responses):
            key = _component_key(comp)
            vulns = _parse_osv_response(resp)
            results[key] = vulns

    return results


async def _osv_querybatch(
    client: httpx.AsyncClient,
    queries: list[dict],
) -> Optional[list[dict]]:
    """
    POST to the OSV querybatch endpoint.
    Retries on rate-limit (429) or transient (5xx) errors with exponential backoff.

    Returns list of per-query response dicts, or None on permanent failure.
    """
    url = f"{settings.OSV_API_URL}/querybatch"
    payload = {"queries": queries}

    for attempt, delay in enumerate([0] + _BACKOFF_DELAYS):
        if delay:
            await asyncio.sleep(delay)
        try:
            response = await client.post(url, json=payload)
        except httpx.RequestError as exc:
            logger.warning("OSV request error (attempt %d): %s", attempt + 1, exc)
            if attempt == len(_BACKOFF_DELAYS):
                return None
            continue

        if response.status_code == 200:
            try:
                data = response.json()
                return data.get("results") or []
            except Exception as exc:
                logger.warning("Failed to parse OSV response: %s", exc)
                return None

        if response.status_code == 429 or response.status_code >= 500:
            logger.warning(
                "OSV returned %d on attempt %d, retrying after %ds",
                response.status_code,
                attempt + 1,
                delay,
            )
            continue

        # Non-retryable HTTP error
        logger.warning("OSV returned non-retryable status %d", response.status_code)
        return None

    logger.warning("OSV batch query failed after all retries")
    return None


# ---------------------------------------------------------------------------
# OSV response parsing
# ---------------------------------------------------------------------------

def _parse_osv_response(resp: dict) -> list[dict]:
    """
    Convert a single OSV query result into our normalized vuln dicts.
    resp is one element from the "results" array in the querybatch response.
    """
    if not isinstance(resp, dict):
        return []

    vulns: list[dict] = []
    for osv_vuln in resp.get("vulns") or []:
        vuln = _normalize_osv_vuln(osv_vuln)
        if vuln:
            vulns.append(vuln)
    return vulns


def _normalize_osv_vuln(osv: dict) -> Optional[dict]:
    """Convert an OSV vulnerability record to our internal format."""
    if not isinstance(osv, dict):
        return None

    vuln_id = osv.get("id") or ""
    summary = osv.get("summary") or osv.get("details") or ""
    published = osv.get("published") or None

    # Extract CVSS score and severity from the "severity" array
    cvss_score, severity = _extract_severity(osv.get("severity") or [])

    # Extract fixed version from "affected[].ranges[].events"
    fixed_version = _extract_fixed_version(osv)

    return {
        "id": vuln_id,
        "summary": summary[:500] if summary else "",
        "severity": severity,
        "cvss_score": cvss_score,
        "fixed_version": fixed_version,
        "published": published,
    }


def _extract_severity(severity_list: list) -> tuple[float, str]:
    """
    Extract the highest CVSS score and corresponding severity label
    from the OSV severity array.
    """
    best_score = 0.0
    best_severity = "UNKNOWN"

    for sev in severity_list:
        if not isinstance(sev, dict):
            continue
        score_str = sev.get("score") or ""
        sev_type = (sev.get("type") or "").upper()

        # CVSS vectors: extract numeric base score
        score = _parse_cvss_score(score_str, sev_type)
        if score > best_score:
            best_score = score
            best_severity = _cvss_to_label(score)

    return best_score, best_severity


def _parse_cvss_score(score_str: str, sev_type: str) -> float:
    """
    Parse a numeric CVSS score from either a plain number or a CVSS vector string.
    """
    if not score_str:
        return 0.0
    # If it looks like a CVSS vector (starts with "CVSS:"), extract the base score
    # from the "B" (base) metric group. The vector does not embed the score directly,
    # so we return 0 and rely on the database score when available.
    if score_str.startswith("CVSS:"):
        return 0.0
    try:
        return float(score_str)
    except (ValueError, TypeError):
        return 0.0


def _cvss_to_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _extract_fixed_version(osv: dict) -> Optional[str]:
    """Extract the earliest fixed version from affected ranges."""
    for affected in osv.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed and fixed not in ("0", ""):
                    return fixed
    return None


# ---------------------------------------------------------------------------
# NVD enrichment
# ---------------------------------------------------------------------------

async def _enrich_with_nvd(
    client: httpx.AsyncClient,
    results: dict,
    api_key: str,
) -> None:
    """
    For any CVE IDs found in OSV results, query NVD to get a precise CVSS score.
    Updates the vuln dicts in-place.
    """
    headers = {"apiKey": api_key}

    for key, vulns in results.items():
        for vuln in vulns:
            cve_id = vuln.get("id") or ""
            if not cve_id.upper().startswith("CVE-"):
                continue
            # Only enrich if the score is missing (0.0)
            if vuln.get("cvss_score", 0.0) > 0.0:
                continue

            nvd_score, nvd_severity = await _query_nvd_cve(client, cve_id, headers)
            if nvd_score > 0.0:
                vuln["cvss_score"] = nvd_score
                vuln["severity"] = nvd_severity


async def _query_nvd_cve(
    client: httpx.AsyncClient,
    cve_id: str,
    headers: dict,
) -> tuple[float, str]:
    """Query the NVD CVE API for a single CVE and return (cvss_score, severity)."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    for attempt, delay in enumerate([0] + _BACKOFF_DELAYS):
        if delay:
            await asyncio.sleep(delay)
        try:
            resp = await client.get(url, params=params, headers=headers)
        except httpx.RequestError as exc:
            logger.warning("NVD request error for %s: %s", cve_id, exc)
            return 0.0, "UNKNOWN"

        if resp.status_code == 200:
            try:
                data = resp.json()
                return _parse_nvd_cvss(data)
            except Exception as exc:
                logger.warning("Failed to parse NVD response for %s: %s", cve_id, exc)
                return 0.0, "UNKNOWN"

        if resp.status_code == 429 or resp.status_code >= 500:
            continue

        break

    return 0.0, "UNKNOWN"


def _parse_nvd_cvss(data: dict) -> tuple[float, str]:
    """Extract the highest CVSS base score from a NVD CVE API 2.0 response."""
    try:
        vulnerabilities = data.get("vulnerabilities") or []
        for vuln_item in vulnerabilities:
            cve = vuln_item.get("cve") or {}
            metrics = cve.get("metrics") or {}
            # Prefer CVSS v3.1, then v3.0, then v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key) or []
                for metric in metric_list:
                    cvss_data = metric.get("cvssData") or {}
                    score = float(cvss_data.get("baseScore") or 0.0)
                    if score > 0:
                        return score, _cvss_to_label(score)
    except (KeyError, TypeError, ValueError):
        pass
    return 0.0, "UNKNOWN"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _component_key(comp: Component) -> str:
    """Canonical cache/result key for a component."""
    if comp.purl:
        return comp.purl
    if comp.version:
        return f"{comp.name}@{comp.version}"
    return comp.name


def _guess_ecosystem(comp: Component) -> Optional[str]:
    """
    Guess the OSV ecosystem from the component type or PURL prefix.
    Returns None if unknown (OSV will search all ecosystems).
    """
    comp_type = (comp.component_type or "").lower()
    # Mapping from common component type strings to OSV ecosystem names
    type_map = {
        "npm": "npm",
        "javascript": "npm",
        "pypi": "PyPI",
        "python": "PyPI",
        "maven": "Maven",
        "java": "Maven",
        "nuget": "NuGet",
        "csharp": "NuGet",
        "dotnet": "NuGet",
        "gem": "RubyGems",
        "ruby": "RubyGems",
        "cargo": "crates.io",
        "rust": "crates.io",
        "golang": "Go",
        "go": "Go",
        "composer": "Packagist",
        "php": "Packagist",
        "hex": "Hex",
        "erlang": "Hex",
        "elixir": "Hex",
        "pub": "Pub",
        "dart": "Pub",
        "swift": "SwiftURL",
    }
    for token, ecosystem in type_map.items():
        if token in comp_type:
            return ecosystem
    return None
