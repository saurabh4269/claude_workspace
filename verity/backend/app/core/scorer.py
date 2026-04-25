"""
Multi-category weighted SBOM quality scoring engine for Verity.

Produces a QualityScore (0.0–10.0) with per-category breakdowns and a letter grade.
The score measures SBOM structural completeness, not security risk (that is the
RiskReport from risk_analyzer.py). Both are complementary.

Score categories and weights (base total: 82):
  1. Structural Validity          — weight  8
  2. Identification               — weight 10
  3. Provenance                   — weight 12
  4. Integrity                    — weight 15
  5. Completeness                 — weight 12
  6. License Compliance           — weight 15
  7. Vulnerability & Traceability — weight 10

Component Security Health (weight 8) is appended as an informational category
when vulnerability results are supplied; it is excluded from the base denominator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from app.core.parser import SBOMDocument, Component
from app.core.licenses.spdx_db import (
    is_absent, is_valid_spdx, is_deprecated, is_restrictive,
)

# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FeatureResult:
    key: str
    score: float          # 0.0–10.0
    applicable: bool      # False = exclude from denominator (N/A for this format)
    weight: float
    detail: str           # human-readable explanation


@dataclass
class CategoryResult:
    name: str
    weight: int
    score: float          # 0.0–10.0, weighted mean of applicable features
    features: list[FeatureResult]
    # weighted_score is computed externally in quality_score_to_dict so the
    # denominator reflects the actual sum of all category weights in the result.


@dataclass
class QualityScore:
    overall_score: float          # 0.0–10.0
    grade: str                    # A/B/C/D/F
    categories: list[CategoryResult]
    sbom_format: str
    total_components: int


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _per_component(have: int, total: int) -> float:
    if total <= 0:
        return 0.0
    if have >= total:
        return 10.0
    # Cap at 9.9 when have < total to avoid false perfect score
    return min(9.9, round(10.0 * have / total, 2))


def _boolean(condition: bool) -> float:
    return 10.0 if condition else 0.0


def _tiered(value: int) -> float:
    """0, 5, or 10."""
    if value >= 2:
        return 10.0
    if value == 1:
        return 5.0
    return 0.0


def _category_score(features: list[FeatureResult]) -> float:
    applicable = [f for f in features if f.applicable]
    if not applicable:
        return 0.0
    total_weight = sum(f.weight for f in applicable)
    if total_weight <= 0:
        return 0.0
    weighted_sum = sum(f.score * f.weight for f in applicable)
    return round(weighted_sum / total_weight, 2)


def _overall_score(categories: list[CategoryResult]) -> float:
    total_weight = sum(c.weight for c in categories)
    if total_weight <= 0:
        return 0.0
    weighted_sum = sum(c.score * c.weight for c in categories)
    return round(weighted_sum / total_weight, 2)


def _grade(score: float) -> str:
    if score >= 9.0:
        return "A"
    if score >= 8.0:
        return "B"
    if score >= 7.0:
        return "C"
    if score >= 5.0:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# PURL / CPE validation
# ---------------------------------------------------------------------------

_PURL_PATTERN = re.compile(
    r"^pkg:[a-zA-Z][a-zA-Z0-9.+\-]*/[^@\s]+",
    re.IGNORECASE,
)

_CPE23_PATTERN = re.compile(
    r"^cpe:2\.3:[aho\*\-]"
    r"(:[^:]*){10}$",
    re.IGNORECASE,
)

_CPE22_PATTERN = re.compile(r"^cpe:/", re.IGNORECASE)


def _is_valid_purl(purl: str) -> bool:
    if not purl:
        return False
    return bool(_PURL_PATTERN.match(purl.strip()))


def _is_valid_cpe(cpe: str) -> bool:
    if not cpe:
        return False
    cpe = cpe.strip()
    return bool(_CPE23_PATTERN.match(cpe) or _CPE22_PATTERN.match(cpe))


# ---------------------------------------------------------------------------
# Strong checksum algorithms (NIST SP 800-107 / SP 800-208)
# ---------------------------------------------------------------------------

_STRONG_ALGOS: frozenset[str] = frozenset({
    "SHA-224", "SHA224",
    "SHA-256", "SHA256",
    "SHA-384", "SHA384",
    "SHA-512", "SHA512",
    "SHA-512/224", "SHA512224",
    "SHA-512/256", "SHA512256",
    "SHA3-224", "SHA3_224", "SHA-3-224",
    "SHA3-256", "SHA3_256", "SHA-3-256",
    "SHA3-384", "SHA3_384", "SHA-3-384",
    "SHA3-512", "SHA3_512", "SHA-3-512",
    "BLAKE2b-256", "BLAKE2B-256",
    "BLAKE2b-384", "BLAKE2B-384",
    "BLAKE2b-512", "BLAKE2B-512",
    "BLAKE3",
    "STREEBOG-256", "STREEBOG256",
    "STREEBOG-512", "STREEBOG512",
})

_WEAK_ALGOS: frozenset[str] = frozenset({
    "MD5", "MD2", "MD4", "MD6",
    "SHA-1", "SHA1",
    "ADLER-32", "ADLER32",
})


def _has_strong_checksum(comp: Component) -> bool:
    if not comp.hashes:
        return False
    for algo in comp.hashes:
        if algo.upper().replace("-", "").replace("_", "") in {
            a.upper().replace("-", "").replace("_", "") for a in _STRONG_ALGOS
        }:
            return True
    return False


def _has_any_checksum(comp: Component) -> bool:
    return bool(comp.hashes)


# ---------------------------------------------------------------------------
# Category 1: Structural Validity (weight 10)
# ---------------------------------------------------------------------------

def _score_structural(doc: SBOMDocument) -> CategoryResult:
    fmt = (doc.format or "").lower()
    version = doc.spec_version or ""

    supported_cdx = {"1.4", "1.5", "1.6"}
    supported_spdx = {"2.1", "2.2", "2.3", "2.2.1", "2.2.2", "2.3.1", "3.0", "3.0.0", "3.0.1"}

    spec_detected = fmt in ("cyclonedx", "spdx")
    # SPDX encodes version as "SPDX-2.3" — strip the prefix for comparison
    norm_version = version.removeprefix("SPDX-") if fmt == "spdx" else version
    if fmt == "cyclonedx":
        spec_version_ok = any(norm_version.startswith(v) for v in supported_cdx)
    elif fmt == "spdx":
        spec_version_ok = any(norm_version.startswith(v) for v in supported_spdx)
    else:
        spec_version_ok = False

    features = [
        FeatureResult(
            key="spec_detected",
            score=_boolean(spec_detected),
            applicable=True,
            weight=0.30,
            detail=f"Format detected: {doc.format or 'unknown'}",
        ),
        FeatureResult(
            key="spec_version_supported",
            score=_boolean(spec_version_ok),
            applicable=True,
            weight=0.30,
            detail=f"Spec version: {version or 'not declared'}"
                   + ("" if spec_version_ok else " (not in supported range)"),
        ),
        FeatureResult(
            key="file_format_valid",
            score=_boolean(spec_detected),
            applicable=True,
            weight=0.20,
            detail="File format matches declared spec",
        ),
        FeatureResult(
            key="schema_valid",
            score=_boolean(getattr(doc, "schema_valid", True)),
            # JSON schema validation only applies to JSON serializations
            applicable=getattr(doc, "file_format", "json") == "json",
            weight=0.20,
            detail=(
                "JSON schema validation" + (" passed" if getattr(doc, "schema_valid", True) else " failed")
                if getattr(doc, "file_format", "json") == "json"
                else f"Schema validation N/A for {getattr(doc, 'file_format', 'unknown')} format"
            ),
        ),
    ]

    return CategoryResult(
        name="Structural Validity",
        weight=8,
        score=_category_score(features),
        features=features,
    )


# ---------------------------------------------------------------------------
# Category 2: Identification (weight 10)
# Name, version, and local unique ID — the three fields every component must
# have for basic identification. PURL/CPE belong in Vulnerability & Traceability
# because their primary purpose is enabling vulnerability lookups.
# ---------------------------------------------------------------------------

def _score_identity(doc: SBOMDocument) -> CategoryResult:
    comps = doc.components
    n = len(comps)

    if n == 0:
        features = [
            FeatureResult("comp_with_name", 0.0, False, 0.40, "No components"),
            FeatureResult("comp_with_version", 0.0, False, 0.35, "No components"),
            FeatureResult("comp_with_local_id", 0.0, False, 0.25, "No components"),
        ]
        return CategoryResult("Identification", 10, 0.0, features)

    has_name = sum(1 for c in comps if c.name and c.name.strip())
    has_version = sum(1 for c in comps if c.version and c.version.strip())

    # Local unique ID: bom-ref (CycloneDX) or SPDXID (SPDX) — must be non-empty and unique
    bom_refs = [c.bom_ref for c in comps if c.bom_ref and c.bom_ref.strip()]
    from collections import Counter
    ref_counts = Counter(bom_refs)
    has_unique_local_id = sum(
        1 for c in comps
        if c.bom_ref and c.bom_ref.strip() and ref_counts[c.bom_ref] == 1
    )

    features = [
        FeatureResult(
            key="comp_with_name",
            score=_per_component(has_name, n),
            applicable=True,
            weight=0.40,
            detail=f"{has_name}/{n} components have names",
        ),
        FeatureResult(
            key="comp_with_version",
            score=_per_component(has_version, n),
            applicable=True,
            weight=0.35,
            detail=f"{has_version}/{n} components have versions",
        ),
        FeatureResult(
            key="comp_with_local_id",
            score=_per_component(has_unique_local_id, n),
            applicable=True,
            weight=0.25,
            detail=f"{has_unique_local_id}/{n} components have a unique bom-ref/SPDXID",
        ),
    ]

    return CategoryResult("Identification", 10, _category_score(features), features)


# ---------------------------------------------------------------------------
# Category 3: Provenance (weight 12)
# ---------------------------------------------------------------------------

def _score_provenance(doc: SBOMDocument) -> CategoryResult:
    fmt = (doc.format or "").lower()
    is_cdx = fmt == "cyclonedx"

    # Timestamp
    has_ts = bool(doc.created and doc.created.strip())

    # Authors
    has_authors = bool(doc.authors and any(a.strip() for a in doc.authors))

    # Tool with version — tiered: 0=no tools, 1=tools but no version, 2=name+version
    tool_tier = 0
    if doc.tools:
        for t in doc.tools:
            if isinstance(t, dict):
                has_name = bool(t.get("name") or t.get("vendor"))
                has_ver = bool(t.get("version"))
            elif isinstance(t, str):
                has_name = True
                has_ver = False
            else:
                continue
            if has_name and has_ver:
                tool_tier = 2
                break
            elif has_name:
                tool_tier = max(tool_tier, 1)

    # Namespace
    has_namespace = bool(doc.document_namespace and doc.document_namespace.strip())

    # Supplier (CDX-only: metadata.supplier)
    has_supplier = bool(getattr(doc, "supplier", None))

    # Lifecycle (CDX 1.5+)
    has_lifecycle = bool(getattr(doc, "lifecycles", None))

    features = [
        FeatureResult(
            key="sbom_creation_timestamp",
            score=_boolean(has_ts),
            applicable=True,
            weight=0.20,
            detail=f"Creation timestamp: {doc.created or 'missing'}",
        ),
        FeatureResult(
            key="sbom_authors",
            score=_boolean(has_authors),
            applicable=True,
            weight=0.20,
            detail=f"Authors/creators: {len(doc.authors or [])} found",
        ),
        FeatureResult(
            key="sbom_tool_version",
            score=_tiered(tool_tier),
            applicable=True,
            weight=0.20,
            detail=(
                "Tool with name+version found" if tool_tier == 2
                else "Tools present but missing versions" if tool_tier == 1
                else "No tools declared"
            ),
        ),
        FeatureResult(
            key="sbom_namespace",
            score=_boolean(has_namespace),
            applicable=True,
            weight=0.15,
            detail=f"Namespace/serialNumber: {'present' if has_namespace else 'missing'}",
        ),
        FeatureResult(
            key="sbom_supplier",
            score=_boolean(has_supplier),
            applicable=is_cdx,
            weight=0.15,
            detail="Document-level supplier: " + ("present" if has_supplier else "missing (CDX-only)"),
        ),
        FeatureResult(
            key="sbom_lifecycle",
            score=_boolean(has_lifecycle),
            applicable=is_cdx,
            weight=0.10,
            detail="Lifecycle phase: " + ("declared" if has_lifecycle else "not declared (CDX-only)"),
        ),
    ]

    return CategoryResult("Provenance", 12, _category_score(features), features)


# ---------------------------------------------------------------------------
# Category 4: Integrity (weight 15)
# ---------------------------------------------------------------------------

def _score_integrity(doc: SBOMDocument) -> CategoryResult:
    comps = doc.components
    n = len(comps)

    has_any = sum(1 for c in comps if _has_any_checksum(c))
    has_strong = sum(1 for c in comps if _has_strong_checksum(c))

    # Document signature: check metadata attribute set by parser
    sig_tier = 0
    sig = getattr(doc, "signature", None)
    if sig:
        has_material = bool(
            sig.get("publicKey") or sig.get("certificate") or sig.get("certificates")
        )
        sig_tier = 2 if has_material else 1

    if n == 0:
        comp_features_applicable = False
        any_score = 0.0
        strong_score = 0.0
        any_detail = "No components"
        strong_detail = "No components"
    else:
        comp_features_applicable = True
        any_score = _per_component(has_any, n)
        strong_score = _per_component(has_strong, n)
        any_detail = f"{has_any}/{n} components have any checksum"
        strong_detail = f"{has_strong}/{n} components have SHA-256+ checksum"

    features = [
        FeatureResult(
            key="comp_with_checksums",
            score=any_score,
            applicable=comp_features_applicable,
            weight=0.60,
            detail=any_detail,
        ),
        FeatureResult(
            key="comp_with_strong_checksum",
            score=strong_score,
            applicable=comp_features_applicable,
            weight=0.30,
            detail=strong_detail,
        ),
        FeatureResult(
            key="sbom_signature",
            score=_tiered(sig_tier),
            applicable=True,
            weight=0.10,
            detail=(
                "Document signature verified" if sig_tier == 2
                else "Document signature present (no key material)" if sig_tier == 1
                else "No document signature"
            ),
        ),
    ]

    return CategoryResult("Integrity", 15, _category_score(features), features)


# ---------------------------------------------------------------------------
# Category 5: License Compliance (weight 15)
# Weights aligned with sbomqs v2.0 catalog.
# ---------------------------------------------------------------------------

def _score_licensing(doc: SBOMDocument) -> CategoryResult:
    comps = doc.components
    n = len(comps)
    fmt = (doc.format or "").lower()
    version = doc.spec_version or ""
    is_cdx16 = fmt == "cyclonedx" and version.startswith("1.6")

    data_license = getattr(doc, "data_license", None) or ""
    has_data_license = bool(data_license.strip()) and data_license.strip().upper() not in ("NOASSERTION", "NONE")

    if n == 0:
        features = [
            FeatureResult("comp_has_license", 0.0, False, 0.20, "No components"),
            FeatureResult("comp_has_valid_spdx_license", 0.0, False, 0.20, "No components"),
            FeatureResult("comp_has_declared_license", 0.0, False, 0.15, "No components"),
            FeatureResult("comp_no_deprecated_license", 0.0, False, 0.15, "No components"),
            FeatureResult("comp_no_restrictive_license", 0.0, False, 0.20, "No components"),
            FeatureResult(
                key="sbom_has_data_license",
                score=_boolean(has_data_license),
                applicable=True,
                weight=0.10,
                detail=f"SBOM data license: {data_license or 'missing'}",
            ),
        ]
        return CategoryResult("License Compliance", 15, 0.0, features)

    has_license = 0
    has_valid_spdx = 0
    has_declared = 0
    no_deprecated = 0
    no_restrictive = 0

    for comp in comps:
        lics = comp.licenses or []
        # Filter out NOASSERTION/NONE
        real_lics = [l for l in lics if not is_absent(l)]

        if real_lics:
            has_license += 1
            if all(is_valid_spdx(l) for l in real_lics):
                has_valid_spdx += 1
            if not any(is_deprecated(l) for l in real_lics):
                no_deprecated += 1
            if not any(is_restrictive(l) for l in real_lics):
                no_restrictive += 1
        else:
            # No license = not deprecated, but also not restrictive
            no_deprecated += 1
            no_restrictive += 1

        # Declared license: CDX 1.6+ acknowledgement=declared
        # For other formats, check if parser extracted declared_licenses
        declared = getattr(comp, "declared_licenses", None) or []
        if declared and any(not is_absent(l) for l in declared):
            has_declared += 1
        elif not is_cdx16 and fmt != "cyclonedx":
            # SPDX: PackageLicenseDeclared field
            if declared:
                has_declared += 1

    features = [
        FeatureResult(
            key="comp_has_license",
            score=_per_component(has_license, n),
            applicable=True,
            weight=0.20,
            detail=f"{has_license}/{n} components have license info",
        ),
        FeatureResult(
            key="comp_has_valid_spdx_license",
            score=_per_component(has_valid_spdx, has_license) if has_license else 0.0,
            applicable=has_license > 0,
            weight=0.20,
            detail=f"{has_valid_spdx}/{has_license} licensed components use valid SPDX IDs",
        ),
        FeatureResult(
            key="comp_has_declared_license",
            score=_per_component(has_declared, n),
            applicable=True,
            weight=0.15,
            detail=f"{has_declared}/{n} components have declared (upstream) license",
        ),
        FeatureResult(
            key="comp_no_deprecated_license",
            score=_per_component(no_deprecated, n),
            applicable=True,
            weight=0.15,
            detail=f"{n - no_deprecated}/{n} components use deprecated SPDX IDs",
        ),
        FeatureResult(
            key="comp_no_restrictive_license",
            score=_per_component(no_restrictive, n),
            applicable=True,
            weight=0.20,
            detail=f"{n - no_restrictive}/{n} components have copyleft/restrictive licenses",
        ),
        FeatureResult(
            key="sbom_has_data_license",
            score=_boolean(has_data_license),
            applicable=True,
            weight=0.10,
            detail=f"SBOM data license: {data_license or 'missing'}",
        ),
    ]

    return CategoryResult("License Compliance", 15, _category_score(features), features)


# ---------------------------------------------------------------------------
# Category 6: Vulnerability & Traceability (weight 10)
# PURL enables OSV/GHSA/ecosystem matching; CPE enables NVD matching.
# Both are given equal weight (0.50/0.50) because both are first-class NTIA
# unique identifiers and cover different vulnerability databases.
# CPE is always applicable — its absence is a real quality gap even when
# PURLs are present, because NVD-based scanning cannot proceed without CPEs.
# ---------------------------------------------------------------------------

def _score_vuln_traceability(doc: SBOMDocument) -> CategoryResult:
    comps = doc.components
    n = len(comps)

    if n == 0:
        features = [
            FeatureResult("comp_with_valid_purl", 0.0, False, 0.50, "No components"),
            FeatureResult("comp_with_valid_cpe", 0.0, False, 0.50, "No components"),
        ]
        return CategoryResult("Vulnerability & Traceability", 10, 0.0, features)

    valid_purl = sum(1 for c in comps if _is_valid_purl(c.purl or ""))
    valid_cpe = sum(1 for c in comps if _is_valid_cpe(c.cpe or ""))

    features = [
        FeatureResult(
            key="comp_with_valid_purl",
            score=_per_component(valid_purl, n),
            applicable=True,
            weight=0.50,
            detail=f"{valid_purl}/{n} components have syntactically valid PURLs",
        ),
        FeatureResult(
            key="comp_with_valid_cpe",
            score=_per_component(valid_cpe, n),
            applicable=True,
            weight=0.50,
            detail=f"{valid_cpe}/{n} components have syntactically valid CPEs",
        ),
    ]

    return CategoryResult("Vulnerability & Traceability", 10, _category_score(features), features)


# ---------------------------------------------------------------------------
# Category 7: Completeness (weight 12)
# Weights aligned with sbomqs v2.0 catalog. sbom_dependency_graph is NOT a
# separate feature — whether any dep edges exist is already captured by
# comp_with_dependencies (per-component coverage at 0.25 weight).
# ---------------------------------------------------------------------------

def _score_completeness(doc: SBOMDocument) -> CategoryResult:
    comps = doc.components
    n = len(comps)
    fmt = (doc.format or "").lower()

    # Primary component
    primary = getattr(doc, "primary_component", None)
    has_primary = bool(primary)

    # Dependency graph
    dep_graph = getattr(doc, "dependency_graph", None)
    is_cdx = fmt == "cyclonedx"
    # CDX-only: compositions/completeness declarations
    compositions = getattr(doc, "compositions", None) or []
    has_completeness = bool(compositions)

    # comp_with_dependencies is N/A for SPDX SBOMs that have no DEPENDS_ON edges.
    # CDX has an explicit per-component dependencies[] array (always applicable).
    dep_edges = dep_graph.get("edges", []) if dep_graph else []
    dep_type_edges = [
        e for e in dep_edges
        if isinstance(e, (list, tuple)) and len(e) >= 3
        and e[2].upper() in ("DEPENDS_ON", "CONTAINS", "DYNAMIC_LINK", "STATIC_LINK")
    ]
    comp_deps_applicable = is_cdx or bool(dep_type_edges)

    if n == 0:
        features = [
            FeatureResult("primary_component", _boolean(has_primary), True, 0.20,
                          "Primary component: " + ("identified" if has_primary else "missing")),
            FeatureResult("comp_with_dependencies", 0.0, False, 0.25, "No components"),
            FeatureResult("sbom_completeness_declared", _boolean(has_completeness), is_cdx, 0.15,
                          "Completeness declared: " + ("yes" if has_completeness else "missing")),
            FeatureResult("comp_with_supplier", 0.0, False, 0.15, "No components"),
            FeatureResult("comp_with_source_url", 0.0, False, 0.15, "No components"),
            FeatureResult("comp_with_purpose", 0.0, False, 0.10, "No components"),
        ]
        return CategoryResult("Completeness", 12, _category_score(features), features)

    has_supplier = sum(1 for c in comps if c.supplier and c.supplier.strip())
    has_source = sum(1 for c in comps if _has_source_url(c))
    has_purpose = sum(1 for c in comps if c.component_type and c.component_type.strip())

    # Per-component: how many appear as a source node in dependency edges
    dep_nodes = set()
    if dep_graph:
        for edge in dep_graph.get("edges") or []:
            if isinstance(edge, (list, tuple)) and len(edge) >= 1:
                dep_nodes.add(edge[0])
    comp_ids = {getattr(c, "bom_ref", None) or c.name or "" for c in comps}
    has_comp_deps = len(dep_nodes & comp_ids)

    features = [
        FeatureResult(
            key="primary_component",
            score=_boolean(has_primary),
            applicable=True,
            weight=0.20,
            detail="Primary component: " + ("identified" if has_primary else "not identified"),
        ),
        FeatureResult(
            key="comp_with_dependencies",
            score=_per_component(has_comp_deps, n) if comp_deps_applicable else 0.0,
            applicable=comp_deps_applicable,
            weight=0.25,
            detail=(
                f"{has_comp_deps}/{n} components appear in dependency graph"
                if comp_deps_applicable
                else "N/A — SPDX SBOM has no DEPENDS_ON/CONTAINS relationships"
            ),
        ),
        FeatureResult(
            key="sbom_completeness_declared",
            score=_boolean(has_completeness),
            applicable=is_cdx,
            weight=0.15,
            detail="Dependency completeness declared: " + ("yes (compositions present)" if has_completeness else "not declared"),
        ),
        FeatureResult(
            key="comp_with_supplier",
            score=_per_component(has_supplier, n),
            applicable=True,
            weight=0.15,
            detail=f"{has_supplier}/{n} components have supplier",
        ),
        FeatureResult(
            key="comp_with_source_url",
            score=_per_component(has_source, n),
            applicable=True,
            weight=0.15,
            detail=f"{has_source}/{n} components have VCS/source URL",
        ),
        FeatureResult(
            key="comp_with_purpose",
            score=_per_component(has_purpose, n),
            applicable=True,
            weight=0.10,
            detail=f"{has_purpose}/{n} components declare a type/purpose",
        ),
    ]

    return CategoryResult("Completeness", 12, _category_score(features), features)


def _has_source_url(comp: Component) -> bool:
    """VCS or source URL in external references."""
    ext_refs = getattr(comp, "external_references", []) or []
    for ref in ext_refs:
        if isinstance(ref, dict):
            ref_type = (ref.get("type") or ref.get("referenceType") or "").lower()
            if ref_type in ("vcs", "source-distribution", "distribution"):
                return True
    return False


# ---------------------------------------------------------------------------
# Category 8: Component Security Health (weight 8, requires vuln_results)
# Informational — only computed when vulnerability data is available.
# ---------------------------------------------------------------------------

def _score_security_health(
    doc: SBOMDocument,
    vuln_results: dict,
    eol_results: Optional[dict] = None,
) -> CategoryResult:
    """
    Aggregate security health metrics across components.
    Scoring is inverted: lower exposure → higher score (10 = 0% exposed).

    eol_results: optional dict from eol_checker.check_eol — {comp_id: bool|None}
    """
    comps = doc.components
    n = len(comps)

    if n == 0 or not vuln_results:
        features = [
            FeatureResult("sec_no_vulnerable_components", 0.0, False, 0.35, "No data"),
            FeatureResult("sec_no_critical_cvss", 0.0, False, 0.25, "No data"),
            FeatureResult("sec_no_high_epss", 0.0, False, 0.15, "No data"),
            FeatureResult("sec_not_in_kev", 0.0, False, 0.15, "No data"),
            FeatureResult("sec_eol_components", 0.0, False, 0.05, "No data"),
            FeatureResult("sec_malicious_components", 0.0, False, 0.05, "No data"),
        ]
        return CategoryResult("Component Security Health", 8, 0.0, features)

    def _comp_key(comp: Component) -> str:
        return comp.purl or comp.name or ""

    vulnerable = 0
    critical_cvss = 0
    high_epss = 0
    in_kev = 0
    malicious = 0

    for comp in comps:
        key = _comp_key(comp)
        vulns = vuln_results.get(key, []) or []
        if vulns:
            vulnerable += 1
            if any(float(v.get("cvss_score") or 0) >= 9.0 for v in vulns):
                critical_cvss += 1
            if any(float(v.get("epss_score") or 0) >= 0.5 for v in vulns):
                high_epss += 1
            if any(v.get("in_kev") for v in vulns):
                in_kev += 1
            # NEW-02: malicious package check — OSV MAL-* entries
            if any(
                str(v.get("id", "")).startswith("MAL-")
                or v.get("is_malicious", False)
                for v in vulns
            ):
                malicious += 1

    def _inverted(count: int, total: int) -> float:
        if total <= 0:
            return 10.0
        pct = count / total
        return round(max(0.0, 10.0 * (1.0 - pct)), 2)

    has_epss_data = any(
        any(v.get("epss_score") is not None for v in (vuln_results.get(_comp_key(c)) or []))
        for c in comps
    )
    has_kev_data = any(
        any("in_kev" in v for v in (vuln_results.get(_comp_key(c)) or []))
        for c in comps
    )

    # NEW-01: EOL check — only applicable for components whose product is known
    eol_count = 0
    eol_applicable_n = 0
    if eol_results:
        for comp in comps:
            key = _comp_key(comp)
            eol_val = eol_results.get(key)
            if eol_val is not None:   # None = unknown product, skip
                eol_applicable_n += 1
                if eol_val is True:
                    eol_count += 1
    eol_applicable = eol_applicable_n > 0

    features = [
        FeatureResult(
            key="sec_no_vulnerable_components",
            score=_inverted(vulnerable, n),
            applicable=True,
            weight=0.35,
            detail=f"{vulnerable}/{n} components have known CVEs",
        ),
        FeatureResult(
            key="sec_no_critical_cvss",
            score=_inverted(critical_cvss, n),
            applicable=vulnerable > 0,
            weight=0.25,
            detail=f"{critical_cvss}/{n} components have CVSS >= 9.0 (Critical)",
        ),
        FeatureResult(
            key="sec_no_high_epss",
            score=_inverted(high_epss, n),
            applicable=has_epss_data,
            weight=0.15,
            detail=f"{high_epss}/{n} components have EPSS >= 0.5",
        ),
        FeatureResult(
            key="sec_not_in_kev",
            score=_inverted(in_kev, n),
            applicable=has_kev_data,
            weight=0.15,
            detail=f"{in_kev}/{n} components have CVEs in CISA KEV",
        ),
        FeatureResult(
            key="sec_eol_components",
            score=_inverted(eol_count, eol_applicable_n) if eol_applicable else 0.0,
            applicable=eol_applicable,
            weight=0.05,
            detail=(
                f"{eol_count}/{eol_applicable_n} known components are end-of-life"
                if eol_applicable else "EOL data not available — no recognised product names"
            ),
        ),
        FeatureResult(
            key="sec_malicious_components",
            score=_inverted(malicious, n),
            applicable=True,
            weight=0.05,
            detail=(
                f"{malicious}/{n} components flagged as malicious (OSV MAL-* entries)"
                if malicious else "No malicious packages detected"
            ),
        ),
    ]

    return CategoryResult("Component Security Health", 8, _category_score(features), features)


# ---------------------------------------------------------------------------
# Main score function
# ---------------------------------------------------------------------------

def score(
    doc: SBOMDocument,
    vuln_results: Optional[dict] = None,
    eol_results: Optional[dict] = None,
) -> QualityScore:
    """
    Compute the quality score for an SBOMDocument.

    Categories 1–7 are structural quality metrics and form the basis of the
    overall score (base denominator: 82). Category 8 (Component Security Health)
    is appended for display when vuln_results are provided, but is EXCLUDED from
    the overall score denominator — it measures software security posture, not
    SBOM document quality.

    eol_results: optional dict from eol_checker.check_eol_async — {comp_id: bool|None}
    """
    structural_categories = [
        _score_structural(doc),
        _score_identity(doc),
        _score_provenance(doc),
        _score_integrity(doc),
        _score_licensing(doc),
        _score_vuln_traceability(doc),
        _score_completeness(doc),
    ]

    # Overall score is always derived from the 7 structural categories only.
    overall = _overall_score(structural_categories)

    all_categories = structural_categories.copy()
    if vuln_results is not None:
        all_categories.append(_score_security_health(doc, vuln_results, eol_results))

    return QualityScore(
        overall_score=overall,
        grade=_grade(overall),
        categories=all_categories,
        sbom_format=doc.format or "unknown",
        total_components=len(doc.components),
    )


def quality_score_to_dict(qs: QualityScore) -> dict:
    """Serialize QualityScore to a plain dict for JSON storage."""
    total_weight = sum(c.weight for c in qs.categories) or 1
    return {
        "overall_score": qs.overall_score,
        "grade": qs.grade,
        "sbom_format": qs.sbom_format,
        "total_components": qs.total_components,
        "categories": [
            {
                "name": c.name,
                "weight": c.weight,
                "score": c.score,
                "weighted_score": round(c.score * c.weight / total_weight, 4),
                "features": [
                    {
                        "key": f.key,
                        "score": f.score,
                        "applicable": f.applicable,
                        "weight": f.weight,
                        "detail": f.detail,
                    }
                    for f in c.features
                ],
            }
            for c in qs.categories
        ],
    }
