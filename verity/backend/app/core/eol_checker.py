"""
End-of-life / end-of-support checker for SBOM components.

Uses the endoflife.date public JSON API (https://endoflife.date/api/) which
is freely available without authentication.

Returns a per-component dict: {component_id: is_eol | None}
  True  — the component's declared version cycle is past its EOL date
  False — the component's version cycle is still supported
  None  — the product was not found in endoflife.date (check is N/A)
"""

from __future__ import annotations

import asyncio
import datetime
import re
from typing import Optional

import httpx

from app.core.parser import Component

# ---------------------------------------------------------------------------
# Product name normalisation
# Maps common package names / display names to endoflife.date product slugs.
# Extend this table as new products are encountered.
# ---------------------------------------------------------------------------

_SLUG_MAP: dict[str, str] = {
    # Python ecosystem
    "python": "python",
    "python3": "python",
    "cpython": "python",
    "django": "django",
    "flask": "flask",
    "fastapi": "fastapi",
    # Node.js ecosystem
    "node": "nodejs",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "npm": "npm",
    # Java ecosystem
    "java": "java",
    "openjdk": "java",
    "jdk": "java",
    "spring": "spring-framework",
    "spring-framework": "spring-framework",
    # Databases
    "mysql": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "mongodb": "mongodb",
    "redis": "redis",
    "mariadb": "mariadb",
    # Web servers / runtimes
    "nginx": "nginx",
    "apache": "apache",
    "tomcat": "tomcat",
    "elasticsearch": "elasticsearch",
    # OS / platform
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "rhel": "rhel",
    "fedora": "fedora",
    "alpine": "alpine",
    # Languages
    "ruby": "ruby",
    "php": "php",
    "go": "go",
    "golang": "go",
    "rust": "rust",
    "kotlin": "kotlin",
    "scala": "scala",
    ".net": "dotnet",
    "dotnet": "dotnet",
    "dotnet-core": "dotnet",
    # Kubernetes / containers
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "docker": "docker",
    "helm": "helm",
    # Other common packages
    "ansible": "ansible",
    "jenkins": "jenkins",
    "gradle": "gradle",
    "maven": "maven",
}

_EOL_API_BASE = "https://endoflife.date/api"
_REQUEST_TIMEOUT = 5.0   # seconds per product lookup


def _normalise_name(name: str) -> Optional[str]:
    """Return the endoflife.date product slug for a component name, or None."""
    if not name:
        return None
    key = name.strip().lower()
    # Direct lookup
    if key in _SLUG_MAP:
        return _SLUG_MAP[key]
    # Strip common version suffixes (python3.11 → python3 → python)
    stripped = re.sub(r"[\d.]+$", "", key).strip("-_")
    if stripped in _SLUG_MAP:
        return _SLUG_MAP[stripped]
    return None


def _extract_major_minor(version: str) -> Optional[str]:
    """Extract the major.minor prefix from a version string."""
    if not version:
        return None
    m = re.match(r"(\d+)(?:\.(\d+))?", version.strip())
    if not m:
        return None
    major = m.group(1)
    minor = m.group(2)
    return f"{major}.{minor}" if minor else major


def _is_cycle_eol(cycle: dict) -> bool:
    """Return True if this release cycle has passed its EOL date."""
    eol = cycle.get("eol")
    if eol is True:
        return True
    if eol is False or eol is None:
        return False
    if isinstance(eol, str):
        try:
            eol_date = datetime.date.fromisoformat(eol)
            return eol_date < datetime.date.today()
        except ValueError:
            return False
    return False


async def _fetch_product(client: httpx.AsyncClient, slug: str) -> Optional[list[dict]]:
    """Fetch cycle data for a product slug. Returns None on any error."""
    try:
        resp = await client.get(f"{_EOL_API_BASE}/{slug}.json", timeout=_REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


async def check_eol_async(components: list[Component]) -> dict[str, Optional[bool]]:
    """
    Check end-of-life status for a list of components.

    Returns {component_id: bool | None} where:
      True  = EOL
      False = still supported
      None  = product unknown to endoflife.date
    """
    results: dict[str, Optional[bool]] = {}

    # Group by product slug to avoid duplicate API calls
    slug_to_comps: dict[str, list[Component]] = {}
    comp_slugs: dict[str, Optional[str]] = {}

    for comp in components:
        comp_id = comp.purl or comp.bom_ref or comp.name or "unknown"
        slug = _normalise_name(comp.name or "")
        comp_slugs[comp_id] = slug
        if slug:
            slug_to_comps.setdefault(slug, []).append(comp)
        else:
            results[comp_id] = None  # unknown product

    if not slug_to_comps:
        return results

    async with httpx.AsyncClient() as client:
        tasks = {slug: _fetch_product(client, slug) for slug in slug_to_comps}
        fetched: dict[str, Optional[list[dict]]] = {}
        for slug, coro in tasks.items():
            fetched[slug] = await coro

    for comp in components:
        comp_id = comp.purl or comp.bom_ref or comp.name or "unknown"
        slug = comp_slugs.get(comp_id)
        if not slug:
            results[comp_id] = None
            continue

        cycles = fetched.get(slug)
        if cycles is None:
            results[comp_id] = None
            continue

        version = comp.version or ""
        major_minor = _extract_major_minor(version)

        # Find the matching cycle
        matched = False
        for cycle in cycles:
            cycle_name = str(cycle.get("cycle", "")).strip()
            if major_minor and (cycle_name == major_minor or cycle_name == major_minor.split(".")[0]):
                results[comp_id] = _is_cycle_eol(cycle)
                matched = True
                break

        if not matched:
            # No matching cycle found — treat as unknown
            results[comp_id] = None

    return results


def check_eol(components: list[Component]) -> dict[str, Optional[bool]]:
    """Synchronous wrapper for check_eol_async."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Inside an async context — caller should use check_eol_async directly
            return {
                (c.purl or c.bom_ref or c.name or "unknown"): None
                for c in components
            }
        return loop.run_until_complete(check_eol_async(components))
    except Exception:
        return {
            (c.purl or c.bom_ref or c.name or "unknown"): None
            for c in components
        }
