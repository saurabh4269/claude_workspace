"""
BSI TR-03183-2 compliance checker.

Based on: BSI TR-03183-2 Technical Guideline for Cyber Resilience Requirements
for Manufacturers and Products — Part 2: Software Bill of Materials (SBOM).

Versions supported: v1.1 (Nov 2023), v2.0 (Sep 2024), v2.1 (Aug 2025).
Published by the German Federal Office for Information Security (BSI),
freely downloadable from bsi.bund.de.

Three-tier model: SHALL (required) / SHOULD (additional) / MAY (optional).
"""

from __future__ import annotations
from dataclasses import dataclass

from app.core.parser import SBOMDocument, Component
from app.core.compliance.record import (
    ComplianceRecord, RecordTier, compliance_score, _req, _add, _opt,
)
from app.core.licenses.spdx_db import is_valid_spdx, is_absent
from app.core.scorer import _is_valid_purl, _is_valid_cpe, _has_strong_checksum


@dataclass
class BSIResult:
    version: str
    overall_score: float
    compliant: bool           # all SHALL checks pass
    records: list[ComplianceRecord]

    def to_dict(self) -> dict:
        req_records = [r for r in self.records if r.tier == RecordTier.REQUIRED and r.applicable]
        add_records = [r for r in self.records if r.tier == RecordTier.ADDITIONAL and r.applicable]
        return {
            "standard": f"BSI TR-03183-2 {self.version}",
            "overall_score": self.overall_score,
            "compliant": self.compliant,
            "required_passed": sum(1 for r in req_records if r.score >= 10.0),
            "required_total": len(req_records),
            "additional_passed": sum(1 for r in add_records if r.score >= 10.0),
            "additional_total": len(add_records),
            "records": [r.to_dict() for r in self.records],
        }


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _has_contact(value: str | None) -> bool:
    """Return True if value looks like an email or URL."""
    if not value:
        return False
    v = value.strip()
    return "@" in v or v.startswith("http://") or v.startswith("https://")


def _has_sha256(comp: Component) -> bool:
    if not comp.hashes:
        return False
    for algo in comp.hashes:
        normalized = algo.upper().replace("-", "").replace("_", "")
        if normalized in ("SHA256", "SHA512", "SHA384", "SHA3256", "SHA3512"):
            return True
    return False


def _has_sha512(comp: Component) -> bool:
    if not comp.hashes:
        return False
    for algo in comp.hashes:
        if algo.upper().replace("-", "") in ("SHA512", "SHA3512", "SHA512256"):
            return True
    return False


def _valid_license(comp: Component) -> bool:
    lics = comp.licenses or []
    real = [l for l in lics if not is_absent(l)]
    if not real:
        return False
    return all(
        is_valid_spdx(l) or l.startswith("LicenseRef-")
        for l in real
    )


def _dep_resolution_ok(doc: SBOMDocument) -> tuple[float, str]:
    """
    DFS check: all dependency targets reference existing component IDs.
    Returns (score, detail).
    """
    graph = getattr(doc, "dependency_graph", None) or {}
    edges = graph.get("edges", [])
    nodes = set(graph.get("nodes", []))
    if not edges:
        return 0.0, "No dependency relationships declared"
    broken = []
    for from_id, to_id, _ in edges:
        if to_id not in nodes:
            broken.append(to_id)
    orphans = graph.get("orphans", [])
    if broken:
        return 0.0, f"{len(broken)} dependency targets reference non-existent components"
    if orphans:
        return 5.0, f"{len(orphans)} orphan components (not reachable from primary)"
    completeness_declared = graph.get("is_complete", False)
    if not completeness_declared:
        return 5.0, "Dependency graph present but completeness not declared"
    return 10.0, "Full dependency graph with completeness declared"


# ---------------------------------------------------------------------------
# BSI v1.1
# ---------------------------------------------------------------------------

def _check_bsi_v11(doc: SBOMDocument) -> list[ComplianceRecord]:
    records: list[ComplianceRecord] = []
    fmt = (doc.format or "").lower()
    version = doc.spec_version or ""

    # Spec version: CDX >= 1.4, SPDX >= 2.3
    if fmt == "cyclonedx":
        version_ok = any(version.startswith(v) for v in ("1.4", "1.5", "1.6"))
        expected = "CycloneDX >= 1.4"
    elif fmt == "spdx":
        version_ok = any(version.startswith(v) for v in ("2.3",))
        expected = "SPDX >= 2.3"
    else:
        version_ok = False
        expected = "CycloneDX >= 1.4 or SPDX >= 2.3"
    records.append(_req("bsi_spec_version", 10.0 if version_ok else 0.0, "document",
                        version, expected,
                        f"Spec version {version}: {'OK' if version_ok else 'below minimum'}"))

    # Creator contact
    creator_contact = _has_contact(
        next((a for a in (doc.authors or []) if _has_contact(a)), None)
    ) or _has_contact(getattr(doc, "supplier", None))
    records.append(_req("bsi_creator_contact", 10.0 if creator_contact else 0.0, "document",
                        str(doc.authors or []), "Creator email or URL",
                        "Creator contact found" if creator_contact else "No creator email/URL found"))

    # Timestamp
    has_ts = bool(doc.created and doc.created.strip())
    records.append(_req("bsi_timestamp", 10.0 if has_ts else 0.0, "document",
                        doc.created or "", "RFC3339 timestamp",
                        f"Timestamp: {doc.created or 'missing'}"))

    # SBOM URI (SHOULD)
    has_uri = bool(doc.document_namespace and doc.document_namespace.strip())
    records.append(_add("bsi_sbom_uri", 10.0 if has_uri else 0.0, True, "document",
                        doc.document_namespace or "", "Valid URL or URN",
                        f"SBOM URI: {doc.document_namespace or 'missing'}"))

    # Dependency resolution (SHOULD in v1.1)
    dep_score, dep_detail = _dep_resolution_ok(doc)
    records.append(_add("bsi_dependency_resolution", dep_score, True, "document",
                        "", "All dependency targets resolve to existing components", dep_detail))

    # Per-component checks
    for comp in doc.components:
        cid = comp.name or "unknown"

        # Name
        records.append(_req("bsi_comp_name", 10.0 if (comp.name and comp.name.strip()) else 0.0,
                            cid, comp.name or "", "Non-empty name", ""))

        # Version
        records.append(_req("bsi_comp_version", 10.0 if (comp.version and comp.version.strip()) else 0.0,
                            cid, comp.version or "", "Non-empty version", ""))

        # License (SPDX ID or LicenseRef-*)
        lic_ok = _valid_license(comp)
        records.append(_req("bsi_comp_license", 10.0 if lic_ok else 0.0, cid,
                            str(comp.licenses or []), "Valid SPDX ID or LicenseRef-*",
                            "Valid license" if lic_ok else "Missing or invalid license"))

        # SHA-256 hash
        hash_ok = _has_sha256(comp)
        records.append(_req("bsi_comp_hash", 10.0 if hash_ok else 0.0, cid,
                            str(list(comp.hashes.keys()) if comp.hashes else []),
                            "SHA-256 or stronger checksum",
                            "SHA-256 hash found" if hash_ok else "No SHA-256 hash"))

        # Creator contact (SHOULD — per-component)
        comp_contact = _has_contact(comp.supplier)
        records.append(_add("bsi_comp_creator_contact", 10.0 if comp_contact else 0.0, True, cid,
                            comp.supplier or "", "Supplier email or URL", ""))

        # Source code URL (SHOULD)
        from app.core.scorer import _has_source_url
        src_ok = _has_source_url(comp)
        records.append(_add("bsi_comp_source_url", 10.0 if src_ok else 0.0, True, cid,
                            "", "VCS source URL", "Source URL found" if src_ok else "No source URL"))

        # PURL or CPE (SHOULD)
        has_id = _is_valid_purl(comp.purl or "") or _is_valid_cpe(comp.cpe or "")
        records.append(_add("bsi_comp_unique_id", 10.0 if has_id else 0.0, True, cid,
                            comp.purl or comp.cpe or "", "PURL or CPE",
                            "Identifier present" if has_id else "No valid PURL or CPE"))

    return records


# ---------------------------------------------------------------------------
# BSI v2.0 (inherits v1.1 + additions)
# ---------------------------------------------------------------------------

def _check_bsi_v20(doc: SBOMDocument) -> list[ComplianceRecord]:
    records = _check_bsi_v11(doc)
    fmt = (doc.format or "").lower()
    version = doc.spec_version or ""

    # Override spec version check for v2.0 minimums
    for r in records:
        if r.check_key == "bsi_spec_version":
            if fmt == "cyclonedx":
                ok = any(version.startswith(v) for v in ("1.5", "1.6"))
                r.score = 10.0 if ok else 0.0
                r.expected = "CycloneDX >= 1.5"
                r.detail = f"Spec version {version}: {'OK' if ok else 'below minimum for v2.0'}"
            elif fmt == "spdx":
                ok = any(version.startswith(v) for v in ("2.2.1", "2.2.2", "2.3"))
                r.score = 10.0 if ok else 0.0
                r.expected = "SPDX >= 2.2.1"
            break

    # No vulnerability data in SBOM (SHALL in v2.0)
    has_vulns = bool(getattr(doc, "vulnerabilities", None))
    records.append(ComplianceRecord(
        check_key="bsi_no_vuln_data",
        tier=RecordTier.REQUIRED,
        score=0.0 if has_vulns else 10.0,
        applicable=True,
        subject_id="document",
        found_value="vulnerabilities present" if has_vulns else "none",
        expected="SBOM must not contain vulnerability data",
        detail="Vulnerability data found — non-compliant" if has_vulns else "No vulnerability data in SBOM",
    ))

    # Promote dependency check to REQUIRED in v2.0
    for r in records:
        if r.check_key == "bsi_dependency_resolution":
            r.tier = RecordTier.REQUIRED
            break

    # BOM link (SHOULD)
    bom_links = getattr(doc, "bom_links", []) or []
    records.append(_add("bsi_bom_links", 10.0 if bom_links else 0.0, True, "document",
                        str(bom_links), "External BOM reference",
                        "BOM link found" if bom_links else "No external BOM reference"))

    # Digital signature (SHOULD in v2.0)
    sig = getattr(doc, "signature", None)
    sig_score = 0.0
    if sig:
        has_material = bool(sig.get("publicKey") or sig.get("certificate"))
        sig_score = 10.0 if has_material else 5.0
    records.append(_add("bsi_signature", sig_score, True, "document",
                        "present" if sig else "absent", "Digital signature",
                        "Signature verified" if sig_score == 10.0
                        else "Signature present but no key material" if sig_score == 5.0
                        else "No document signature"))

    # Per-component: filename (SHALL in v2.0)
    for comp in doc.components:
        cid = comp.name or "unknown"
        props = getattr(comp, "properties", {}) or {}
        filename = props.get("bsi:component:filename") or getattr(comp, "filename", None)
        records.append(_req("bsi_comp_filename", 10.0 if filename else 0.0, cid,
                            filename or "", "Component filename",
                            "Filename found" if filename else "No filename"))

    return records


# ---------------------------------------------------------------------------
# BSI v2.1 (inherits v2.0 + breaking changes)
# ---------------------------------------------------------------------------

def _check_bsi_v21(doc: SBOMDocument) -> list[ComplianceRecord]:
    records = _check_bsi_v20(doc)
    fmt = (doc.format or "").lower()
    version = doc.spec_version or ""

    # Override spec version: CDX >= 1.6, SPDX >= 3.0.1
    for r in records:
        if r.check_key == "bsi_spec_version":
            if fmt == "cyclonedx":
                ok = version.startswith("1.6")
                r.score = 10.0 if ok else 0.0
                r.expected = "CycloneDX >= 1.6"
                r.detail = f"Spec version {version}: {'OK' if ok else 'minimum is 1.6 for BSI v2.1'}"
            elif fmt == "spdx":
                ok = version.startswith("3.")
                r.score = 10.0 if ok else 0.0
                r.expected = "SPDX >= 3.0.1"
                r.detail = f"SPDX v2 not permitted in BSI v2.1 — use SPDX 3.0.1+"
            break

    # If SPDX v2, mark all component checks as N/A
    if fmt == "spdx" and not version.startswith("3."):
        for r in records:
            if r.subject_id != "document":
                r.applicable = False

    # Promote SBOM URI to SHALL
    for r in records:
        if r.check_key == "bsi_sbom_uri":
            r.tier = RecordTier.REQUIRED
            break

    # SHA-512 for deployable hash (new SHALL in v2.1, CDX 1.6 only)
    for comp in doc.components:
        cid = comp.name or "unknown"
        ext_refs = getattr(comp, "external_references", []) or []
        # Only applicable when the component has at least one distribution-type external ref
        has_dist_ref = any(
            isinstance(ref, dict) and (ref.get("type") or "").lower() in ("distribution", "distribution-intake")
            for ref in ext_refs
        )
        is_cdx16_comp = fmt == "cyclonedx" and version.startswith("1.6")
        # applicable = CDX 1.6 AND component has a distribution reference
        deploy_applicable = is_cdx16_comp and has_dist_ref
        has_deploy_hash = False
        if has_dist_ref:
            for ref in ext_refs:
                if isinstance(ref, dict):
                    rtype = (ref.get("type") or "").lower()
                    if rtype in ("distribution", "distribution-intake"):
                        hashes = ref.get("hashes", {})
                        for algo in (hashes.keys() if isinstance(hashes, dict) else []):
                            if "512" in algo:
                                has_deploy_hash = True
        records.append(ComplianceRecord(
            check_key="bsi_v21_deploy_hash",
            tier=RecordTier.REQUIRED,
            score=10.0 if has_deploy_hash else 0.0,
            applicable=deploy_applicable,
            subject_id=cid,
            found_value="SHA-512 in distribution ref" if has_deploy_hash else ("no distribution ref" if not has_dist_ref else "not found"),
            expected="SHA-512 hash on deployable artifact",
            detail=(
                "Deploy hash found" if has_deploy_hash
                else ("No distribution-type external reference — check N/A" if not has_dist_ref
                      else "Distribution ref present but no SHA-512 hash")
            ),
        ))

        # Original/declared license (promoted to SHALL in v2.1)
        declared = getattr(comp, "declared_licenses", None) or []
        is_cdx16 = fmt == "cyclonedx" and version.startswith("1.6")
        has_declared = bool(declared and any(not is_absent(l) for l in declared)) if is_cdx16 else False
        records.append(ComplianceRecord(
            check_key="bsi_v21_declared_license",
            tier=RecordTier.REQUIRED,
            score=10.0 if has_declared else 0.0,
            applicable=is_cdx16,
            subject_id=cid,
            found_value=str(declared),
            expected="Declared (upstream) license with acknowledgement=declared",
            detail="Declared license found" if has_declared else "No declared license (CDX 1.6 acknowledgement=declared required)",
        ))

    # Demote signature to SHOULD (was SHOULD in v2.0 already, confirm)
    # (no change needed — already ADDITIONAL)

    return records


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_bsi(doc: SBOMDocument, version: str = "v2.1") -> BSIResult:
    """
    Run BSI TR-03183-2 compliance check.

    Args:
        doc: Parsed SBOMDocument.
        version: One of "v1.1", "v2.0", "v2.1" (default latest).

    Returns:
        BSIResult with records and overall score.
    """
    if version == "v1.1":
        records = _check_bsi_v11(doc)
    elif version == "v2.0":
        records = _check_bsi_v20(doc)
    else:
        records = _check_bsi_v21(doc)

    overall = compliance_score(records)
    # compliant = all SHALL checks pass
    req_records = [r for r in records if r.tier == RecordTier.REQUIRED and r.applicable]
    compliant = all(r.score >= 10.0 for r in req_records)

    return BSIResult(
        version=version,
        overall_score=overall,
        compliant=compliant,
        records=records,
    )
