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
    ComplianceRecord, RecordTier, compliance_score, raw_compliance_score, _req, _add,
)
from app.core.scorer import _is_valid_purl, _is_valid_cpe, _has_strong_checksum, _has_source_url
from app.core.licenses.spdx_db import is_valid_spdx, is_absent

# External-reference types and value prefixes that constitute alternative unique IDs.
# Based on: SoftWare Heritage persistent IDentifiers (SWHID), SWID ISO/IEC 19770-2,
# and OmniBOR (formerly GitOID) public specifications.
_SWHID_PREFIX = "swh:"
_OMNIBOR_TYPES = frozenset({"omnibor", "gitoid"})
_SWID_TYPES = frozenset({"swid"})


def _has_alternative_unique_id(comp: "Component") -> bool:
    """Return True if the component carries a SWHID, SWID, or OmniBOR identifier."""
    ext_refs = getattr(comp, "external_references", []) or []
    for ref in ext_refs:
        if not isinstance(ref, dict):
            continue
        rtype = (ref.get("type") or ref.get("referenceType") or "").lower()
        url = ref.get("url") or ref.get("locator") or ""
        if rtype in _OMNIBOR_TYPES:
            return True
        if rtype in _SWID_TYPES:
            return True
        if url.startswith(_SWHID_PREFIX):
            return True
        if rtype == "vcs" and url.startswith(_SWHID_PREFIX):
            return True
    return False


@dataclass
class FSCTResult:
    overall_score: float       # clamped 0.0–10.0
    raw_score: float           # unclamped; >10.0 signals aspirational achievements
    records: list[ComplianceRecord]

    def to_dict(self) -> dict:
        return {
            "standard": "FSCT v3",
            "overall_score": self.overall_score,
            "raw_score": self.raw_score,
            "records": [r.to_dict() for r in self.records],
        }


def check_fsct(doc: SBOMDocument) -> FSCTResult:
    """Run FSCT v3 compliance check."""
    records: list[ComplianceRecord] = []

    # -----------------------------------------------------------------------
    # SBOM-level checks
    # -----------------------------------------------------------------------

    # Author: 10=name only (minimum), 12=name+contact info (recommended per FSCT v3)
    has_author = bool(doc.authors and any(a.strip() for a in doc.authors))
    has_author_contact = has_author and any(
        "@" in a or "http" in a for a in (doc.authors or [])
    )
    author_score = 12.0 if has_author_contact else (10.0 if has_author else 0.0)
    records.append(_req("fsct_sbom_author", author_score, "document",
                        str(doc.authors or []), "Author with name (12=adds contact info)",
                        "Author found with contact info (recommended)" if has_author_contact
                        else "Author found — name only (minimum)" if has_author
                        else "No author found"))

    # Timestamp
    has_ts = bool(doc.created and doc.created.strip())
    records.append(_req("fsct_sbom_timestamp", 10.0 if has_ts else 0.0, "document",
                        doc.created or "", "RFC3339 timestamp", ""))

    # Type/lifecycle: 0=none, 10=one lifecycle, 15=multiple (aspirational)
    lifecycles = getattr(doc, "lifecycles", None) or []
    has_lifecycle = bool(lifecycles)
    lifecycle_score = 15.0 if len(lifecycles) > 1 else (10.0 if has_lifecycle else 0.0)
    records.append(_add("fsct_sbom_type", lifecycle_score, True, "document",
                        str(lifecycles), "Lifecycle phase declared",
                        f"Multiple lifecycles (aspirational): {lifecycles}" if lifecycle_score == 15.0
                        else f"Lifecycle declared: {lifecycles}" if has_lifecycle
                        else "No lifecycle declared"))

    # Primary component
    has_primary = bool(getattr(doc, "primary_component", None))
    records.append(_req("fsct_sbom_primary", 10.0 if has_primary else 0.0, "document",
                        str(getattr(doc, "primary_component", "")), "Primary component identified", ""))

    # Relationships: 0=none, 10=partial, 12=complete (recommended)
    graph = getattr(doc, "dependency_graph", None) or {}
    has_rels = bool(graph.get("edges"))
    is_complete = graph.get("is_complete", False)
    rel_score = 12.0 if is_complete else (10.0 if has_rels else 0.0)
    records.append(_req("fsct_sbom_relationships", rel_score, "document",
                        f"{len(graph.get('edges', []))} edges",
                        "At least one dependency relationship",
                        "Complete dependency graph (recommended)" if is_complete
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

        # Unique ID: PURL, CPE, SWHID, SWID, or OmniBOR
        has_purl = _is_valid_purl(comp.purl or "")
        has_cpe = _is_valid_cpe(comp.cpe or "")
        has_alt_id = _has_alternative_unique_id(comp)
        has_id = has_purl or has_cpe or has_alt_id
        id_found = (
            comp.purl if has_purl
            else comp.cpe if has_cpe
            else "SWHID/SWID/OmniBOR" if has_alt_id
            else ""
        )
        records.append(_req("fsct_comp_uniq_id", 10.0 if has_id else 0.0,
                            cid, id_found, "PURL, CPE, SWHID, SWID, or OmniBOR", ""))

        # Checksum: 0=none, 10=weak/minimum, 12=strong/recommended (FSCT tier model)
        has_any_hash = bool(comp.hashes)
        has_strong = _has_strong_checksum(comp)
        if has_strong:
            hash_score = 12.0   # meets FSCT recommended practice
        elif has_any_hash:
            hash_score = 10.0   # meets minimum only
        else:
            hash_score = 0.0
        records.append(_req("fsct_comp_checksum", hash_score, cid,
                            str(list(comp.hashes.keys()) if comp.hashes else []),
                            "Any checksum (strong hash preferred)",
                            "Strong checksum (SHA-256+) — recommended" if has_strong
                            else "Weak checksum (SHA-1/MD5) — minimum only" if has_any_hash
                            else "No checksum"))

        # License: FSCT v3 four-tier scoring (0/10/12/15)
        #   0  = no license information
        #  10  = any license name present (minimum)
        #  12  = valid SPDX license ID (recommended)
        #  15  = SPDX ID + URL or embedded text confirming license terms (aspirational)
        lics = [l for l in (comp.licenses or []) if not is_absent(l)]
        has_spdx = lics and all(is_valid_spdx(l) for l in lics)
        has_url_or_text = getattr(comp, "license_has_url_or_text", False)
        if not lics:
            lic_score = 0.0
            lic_detail = "No license information"
        elif has_spdx and has_url_or_text:
            lic_score = 15.0
            lic_detail = "Valid SPDX ID + license URL/text (aspirational)"
        elif has_spdx:
            lic_score = 12.0
            lic_detail = "Valid SPDX license ID (recommended)"
        else:
            lic_score = 10.0
            lic_detail = "License name present (minimum — not a valid SPDX ID)"
        records.append(_req("fsct_comp_license", lic_score, cid,
                            str(lics), "License ID=10/SPDX=12/SPDX+URL=15", lic_detail))

        # Copyright
        copyright_text = getattr(comp, "copyright", None) or ""
        has_copyright = bool(copyright_text.strip()) and copyright_text.strip() not in (
            "NOASSERTION", "NONE", ""
        )
        records.append(_add("fsct_comp_copyright", 10.0 if has_copyright else 0.0, True,
                            cid, copyright_text, "Copyright text", ""))

    overall = compliance_score(records)
    raw = raw_compliance_score(records)
    return FSCTResult(overall_score=overall, raw_score=raw, records=records)
