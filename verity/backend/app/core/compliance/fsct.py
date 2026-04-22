"""
FSCT (Framing Software Component Transparency) v3 compliance checker.

Based on: "Framing Software Component Transparency: Establishing a Common
Software Bill of Materials (SBOM)" — CISA / Linux Foundation, v3.
Freely available public document.

FSCT uses a minimum / recommended / aspirational model with scores
of 10, 12, and 15 for some elements (raw FSCT scale, not normalized to 10).
"""

from __future__ import annotations
from dataclasses import dataclass

from app.core.parser import SBOMDocument, Component
from app.core.compliance.record import (
    ComplianceRecord, RecordTier, compliance_score, _req, _add,
)
from app.core.scorer import _is_valid_purl, _is_valid_cpe, _has_strong_checksum, _has_source_url
from app.core.licenses.spdx_db import is_valid_spdx, is_absent


@dataclass
class FSCTResult:
    overall_score: float
    records: list[ComplianceRecord]

    def to_dict(self) -> dict:
        return {
            "standard": "FSCT v3",
            "overall_score": self.overall_score,
            "records": [r.to_dict() for r in self.records],
        }


def check_fsct(doc: SBOMDocument) -> FSCTResult:
    """Run FSCT v3 compliance check."""
    records: list[ComplianceRecord] = []

    # -----------------------------------------------------------------------
    # SBOM-level checks
    # -----------------------------------------------------------------------

    # Author: 10=name only, 12=name+contact (we cap at 10 for scoring denominator)
    has_author = bool(doc.authors and any(a.strip() for a in doc.authors))
    has_author_contact = has_author and any(
        "@" in a or "http" in a for a in (doc.authors or [])
    )
    author_score = 10.0 if has_author else 0.0
    records.append(_req("fsct_sbom_author", author_score, "document",
                        str(doc.authors or []), "Author with name",
                        "Author found with contact" if has_author_contact
                        else "Author found (name only)" if has_author
                        else "No author found"))

    # Timestamp
    has_ts = bool(doc.created and doc.created.strip())
    records.append(_req("fsct_sbom_timestamp", 10.0 if has_ts else 0.0, "document",
                        doc.created or "", "RFC3339 timestamp", ""))

    # Type/lifecycle (0=none, 15=aspirational)
    has_lifecycle = bool(getattr(doc, "lifecycles", None))
    records.append(_add("fsct_sbom_type", 10.0 if has_lifecycle else 0.0, True, "document",
                        str(getattr(doc, "lifecycles", [])), "Lifecycle phase declared",
                        "Lifecycle declared" if has_lifecycle else "No lifecycle declared"))

    # Primary component
    has_primary = bool(getattr(doc, "primary_component", None))
    records.append(_req("fsct_sbom_primary", 10.0 if has_primary else 0.0, "document",
                        str(getattr(doc, "primary_component", "")), "Primary component identified", ""))

    # Relationships (10=present, 12=complete)
    graph = getattr(doc, "dependency_graph", None) or {}
    has_rels = bool(graph.get("edges"))
    is_complete = graph.get("is_complete", False)
    rel_score = 10.0 if has_rels else 0.0
    records.append(_req("fsct_sbom_relationships", rel_score, "document",
                        f"{len(graph.get('edges', []))} edges",
                        "At least one dependency relationship",
                        "Complete dependency graph" if is_complete
                        else "Partial dependencies" if has_rels
                        else "No relationships declared"))

    # -----------------------------------------------------------------------
    # Per-component checks
    # -----------------------------------------------------------------------
    for comp in doc.components:
        cid = comp.name or "unknown"

        # Name
        records.append(_req("fsct_comp_name",
                            10.0 if (comp.name and comp.name.strip()) else 0.0,
                            cid, comp.name or "", "Non-empty name", ""))

        # Version
        records.append(_req("fsct_comp_version",
                            10.0 if (comp.version and comp.version.strip()) else 0.0,
                            cid, comp.version or "", "Non-empty version", ""))

        # Supplier ("unknown" is acceptable)
        has_supplier = bool(comp.supplier and comp.supplier.strip())
        records.append(_req("fsct_comp_supplier", 10.0 if has_supplier else 0.0,
                            cid, comp.supplier or "", "Supplier or 'unknown'", ""))

        # Unique ID (PURL, CPE, or other)
        has_id = _is_valid_purl(comp.purl or "") or _is_valid_cpe(comp.cpe or "")
        records.append(_req("fsct_comp_uniq_id", 10.0 if has_id else 0.0,
                            cid, comp.purl or comp.cpe or "", "PURL, CPE, SWHID, or SWID", ""))

        # Checksum: 0=none, 10=weak, 12=strong (cap at 10 for denominator)
        has_any_hash = bool(comp.hashes)
        has_strong = _has_strong_checksum(comp)
        hash_score = 10.0 if has_any_hash else 0.0
        records.append(_req("fsct_comp_checksum", hash_score, cid,
                            str(list(comp.hashes.keys()) if comp.hashes else []),
                            "Any checksum (strong preferred)",
                            "Strong checksum" if has_strong
                            else "Weak checksum (SHA-1/MD5)" if has_any_hash
                            else "No checksum"))

        # License: 0=none, partial=5, SPDX=10
        lics = [l for l in (comp.licenses or []) if not is_absent(l)]
        if not lics:
            lic_score = 0.0
            lic_detail = "No license"
        elif all(is_valid_spdx(l) for l in lics):
            lic_score = 10.0
            lic_detail = "Valid SPDX license"
        else:
            lic_score = 5.0
            lic_detail = "License name present but not valid SPDX ID"
        records.append(_req("fsct_comp_license", lic_score, cid,
                            str(lics), "Valid SPDX license ID", lic_detail))

        # Copyright
        copyright_text = getattr(comp, "copyright", None) or ""
        has_copyright = bool(copyright_text.strip()) and copyright_text.strip() not in (
            "NOASSERTION", "NONE", ""
        )
        records.append(_add("fsct_comp_copyright", 10.0 if has_copyright else 0.0, True,
                            cid, copyright_text, "Copyright text", ""))

    overall = compliance_score(records)
    return FSCTResult(overall_score=overall, records=records)
