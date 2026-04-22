"""
Vulnerability checker for Verity.
Queries OSV.dev (primary) and optionally NVD for CVE enrichment.
Enriches with EPSS scores (FIRST.org) and CISA KEV status.
"""

import asyncio
import logging
from typing import Optional

import httpx

from app.config import settings
from app.core.parser import Component

logger = logging.getLogger(__name__)

# In-process cache
_cache: dict[str, list[dict]] = {}
_kev_cache: set[str] = set()   # CVE IDs in the CISA KEV catalog
_kev_loaded: bool = False
_epss_cache: dict[str, tuple[float, float]] = {}  # cve_id -> (score, percentile)

_OSV_BATCH_SIZE = 1000
_EPSS_BATCH_SIZE = 100
_BACKOFF_DELAYS = [2, 4, 8]

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def check_vulnerabilities(
    components: list[Component],
    enabled: bool = True,
) -> dict:
    """
    Check all components for known vulnerabilities.

    Returns dict mapping component key (purl or name@version) to list of vuln dicts:
    {
        "id": str,
        "summary": str,
        "severity": str,
        "cvss_score": float,
        "fixed_version": str | None,
        "published": str | None,
        "epss_score": float | None,
        "epss_percentile": float | None,
        "in_kev": bool,
    }
    """
    if not enabled or not components:
        return {}

    results: dict[str, list[dict]] = {}
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
        if purl_components:
            batch_results = await _query_osv_purl_batch(client, purl_components)
            results.update(batch_results)

        if name_components:
            batch_results = await _query_osv_name_batch(client, name_components)
            results.update(batch_results)

        if settings.nvd_enabled and settings.NVD_API_KEY:
            await _enrich_with_nvd(client, results, settings.NVD_API_KEY)

        # Collect all unique CVE IDs found
        all_cve_ids = {
            v["id"] for vulns in results.values()
            for v in vulns
            if (v.get("id") or "").upper().startswith("CVE-")
        }

        if all_cve_ids:
            await _enrich_with_epss(client, results, all_cve_ids)
            await _enrich_with_kev(client, results)

    for key, vulns in results.items():
        _cache[key] = vulns

    return results


async def load_kev_catalog(client: Optional[httpx.AsyncClient] = None) -> set[str]:
    """
    Load CISA KEV catalog into the in-process cache.
    Returns the set of KEV CVE IDs.
    Called at startup for best performance.
    """
    global _kev_cache, _kev_loaded
    if _kev_loaded:
        return _kev_cache

    should_close = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=30.0)

    try:
        resp = await client.get(KEV_URL)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities") or []
            _kev_cache = {v["cveID"] for v in vulns if v.get("cveID")}
            _kev_loaded = True
            logger.info("CISA KEV catalog loaded: %d entries", len(_kev_cache))
        else:
            logger.warning("Failed to load KEV catalog: HTTP %d", resp.status_code)
    except Exception as exc:
        logger.warning("Failed to load KEV catalog: %s", exc)
    finally:
        if should_close:
            await client.aclose()

    return _kev_cache


# ---------------------------------------------------------------------------
# EPSS enrichment (FIRST.org public API, no auth required)
# ---------------------------------------------------------------------------

async def _enrich_with_epss(
    client: httpx.AsyncClient,
    results: dict,
    cve_ids: set[str],
) -> None:
    """Add EPSS score and percentile to each vulnerability dict."""
    # Batch fetch EPSS for all CVE IDs
    cve_list = list(cve_ids)
    epss_data: dict[str, tuple[float, float]] = {}

    for i in range(0, len(cve_list), _EPSS_BATCH_SIZE):
        batch = cve_list[i:i + _EPSS_BATCH_SIZE]
        # Check cache first
        uncached = [c for c in batch if c not in _epss_cache]
        if uncached:
            fetched = await _fetch_epss_batch(client, uncached)
            _epss_cache.update(fetched)
        for cve_id in batch:
            if cve_id in _epss_cache:
                epss_data[cve_id] = _epss_cache[cve_id]

    # Apply to results
    for vulns in results.values():
        for vuln in vulns:
            cve_id = vuln.get("id") or ""
            if cve_id in epss_data:
                score, pct = epss_data[cve_id]
                vuln["epss_score"] = round(score, 4)
                vuln["epss_percentile"] = round(pct, 2)
            else:
                vuln.setdefault("epss_score", None)
                vuln.setdefault("epss_percentile", None)


async def _fetch_epss_batch(
    client: httpx.AsyncClient,
    cve_ids: list[str],
) -> dict[str, tuple[float, float]]:
    """Fetch EPSS scores for a batch of CVE IDs."""
    params = {"cve": ",".join(cve_ids), "scope": "time-series"}
    # Use envelope=false for simpler parsing
    params_simple = {"cve": ",".join(cve_ids)}
    results: dict[str, tuple[float, float]] = {}
    try:
        resp = await client.get(EPSS_API, params=params_simple)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("data") or []:
                cve = item.get("cve") or ""
                try:
                    score = float(item.get("epss") or 0)
                    pct = float(item.get("percentile") or 0) * 100
                    results[cve] = (score, pct)
                except (ValueError, TypeError):
                    pass
    except Exception as exc:
        logger.warning("EPSS fetch failed: %s", exc)
    return results


# ---------------------------------------------------------------------------
# CISA KEV enrichment
# ---------------------------------------------------------------------------

async def _enrich_with_kev(
    client: httpx.AsyncClient,
    results: dict,
) -> None:
    """Mark vulnerabilities that are in the CISA KEV catalog."""
    global _kev_loaded
    if not _kev_loaded:
        await load_kev_catalog(client)

    for vulns in results.values():
        for vuln in vulns:
            cve_id = vuln.get("id") or ""
            vuln["in_kev"] = cve_id in _kev_cache


# ---------------------------------------------------------------------------
# OSV batch queries (unchanged logic, minor type cleanup)
# ---------------------------------------------------------------------------

async def _query_osv_purl_batch(
    client: httpx.AsyncClient,
    components: list[Component],
) -> dict:
    results: dict[str, list[dict]] = {}
    for batch_start in range(0, len(components), _OSV_BATCH_SIZE):
        batch = components[batch_start:batch_start + _OSV_BATCH_SIZE]
        queries = [{"package": {"purl": comp.purl}} for comp in batch]
        raw_responses = await _osv_querybatch(client, queries)
        if raw_responses is None:
            for comp in batch:
                results[_component_key(comp)] = []
            continue
        for comp, resp in zip(batch, raw_responses):
            key = _component_key(comp)
            results[key] = _parse_osv_response(resp)
    return results


async def _query_osv_name_batch(
    client: httpx.AsyncClient,
    components: list[Component],
) -> dict:
    results: dict[str, list[dict]] = {}
    for batch_start in range(0, len(components), _OSV_BATCH_SIZE):
        batch = components[batch_start:batch_start + _OSV_BATCH_SIZE]
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
            results[key] = _parse_osv_response(resp)
    return results


async def _osv_querybatch(
    client: httpx.AsyncClient,
    queries: list[dict],
) -> Optional[list[dict]]:
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
            logger.warning("OSV returned %d on attempt %d", response.status_code, attempt + 1)
            continue
        logger.warning("OSV non-retryable status %d", response.status_code)
        return None
    logger.warning("OSV batch query failed after all retries")
    return None


# ---------------------------------------------------------------------------
# OSV response parsing
# ---------------------------------------------------------------------------

def _parse_osv_response(resp: dict) -> list[dict]:
    if not isinstance(resp, dict):
        return []
    vulns: list[dict] = []
    for osv_vuln in resp.get("vulns") or []:
        vuln = _normalize_osv_vuln(osv_vuln)
        if vuln:
            vulns.append(vuln)
    return vulns


def _normalize_osv_vuln(osv: dict) -> Optional[dict]:
    if not isinstance(osv, dict):
        return None
    vuln_id = osv.get("id") or ""
    summary = osv.get("summary") or osv.get("details") or ""
    published = osv.get("published") or None
    cvss_score, severity = _extract_severity(osv.get("severity") or [])
    fixed_version = _extract_fixed_version(osv)
    return {
        "id": vuln_id,
        "summary": summary[:500] if summary else "",
        "severity": severity,
        "cvss_score": cvss_score,
        "fixed_version": fixed_version,
        "published": published,
        "epss_score": None,
        "epss_percentile": None,
        "in_kev": False,
    }


def _extract_severity(severity_list: list) -> tuple[float, str]:
    best_score = 0.0
    best_severity = "UNKNOWN"
    for sev in severity_list:
        if not isinstance(sev, dict):
            continue
        score_str = sev.get("score") or ""
        score = _parse_cvss_score(score_str)
        if score > best_score:
            best_score = score
            best_severity = _cvss_to_label(score)
    return best_score, best_severity


def _parse_cvss_score(score_str: str) -> float:
    if not score_str or score_str.startswith("CVSS:"):
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
    headers = {"apiKey": api_key}
    for key, vulns in results.items():
        for vuln in vulns:
            cve_id = vuln.get("id") or ""
            if not cve_id.upper().startswith("CVE-"):
                continue
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
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
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
                return _parse_nvd_cvss(resp.json())
            except Exception:
                return 0.0, "UNKNOWN"
        if resp.status_code == 429 or resp.status_code >= 500:
            continue
        break
    return 0.0, "UNKNOWN"


def _parse_nvd_cvss(data: dict) -> tuple[float, str]:
    try:
        for vuln_item in data.get("vulnerabilities") or []:
            metrics = (vuln_item.get("cve") or {}).get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                for metric in metrics.get(key) or []:
                    score = float((metric.get("cvssData") or {}).get("baseScore") or 0)
                    if score > 0:
                        return score, _cvss_to_label(score)
    except (KeyError, TypeError, ValueError):
        pass
    return 0.0, "UNKNOWN"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _component_key(comp: Component) -> str:
    if comp.purl:
        return comp.purl
    if comp.version:
        return f"{comp.name}@{comp.version}"
    return comp.name


def _guess_ecosystem(comp: Component) -> Optional[str]:
    comp_type = (comp.component_type or "").lower()
    type_map = {
        "npm": "npm", "javascript": "npm",
        "pypi": "PyPI", "python": "PyPI",
        "maven": "Maven", "java": "Maven",
        "nuget": "NuGet", "csharp": "NuGet", "dotnet": "NuGet",
        "gem": "RubyGems", "ruby": "RubyGems",
        "cargo": "crates.io", "rust": "crates.io",
        "golang": "Go", "go": "Go",
        "composer": "Packagist", "php": "Packagist",
        "hex": "Hex", "erlang": "Hex", "elixir": "Hex",
        "pub": "Pub", "dart": "Pub",
        "swift": "SwiftURL",
    }
    for token, ecosystem in type_map.items():
        if token in comp_type:
            return ecosystem
    return None
