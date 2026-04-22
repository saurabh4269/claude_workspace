"""
OpenChain Telco (OCT) SBOM Guide v1.1 compliance checker.

Based on: OpenChain Telco SBOM Guide Version 1.1 (May 2024).
Published by the OpenChain Project under CC BY 4.0.

SPDX-only format. CycloneDX input immediately fails the format check.
"""

from __future__ import annotations
from dataclasses import dataclass

from app.core.parser import SBOMDocument
from app.core.compliance.record import (
    ComplianceRecord, RecordTier, compliance_score, _req,
)
from app.core.licenses.spdx_db import is_absent


@dataclass
class OCTResult:
    overall_score: float
    spdx_only_fail: bool
    records: list[ComplianceRecord]

    def to_dict(self) -> dict:
        return {
            "standard": "OpenChain Telco v1.1",
            "overall_score": self.overall_score,
            "spdx_only_fail": self.spdx_only_fail,
            "records": [r.to_dict() for r in self.records],
        }


def check_oct(doc: SBOMDocument) -> OCTResult:
    """Run OpenChain Telco v1.1 compliance check."""
    fmt = (doc.format or "").lower()
    records: list[ComplianceRecord] = []

    # OCT is SPDX-only
    if fmt != "spdx":
        records.append(_req("oct_spec_format", 0.0, "document", fmt,
                            "SPDX format required",
                            f"OpenChain Telco requires SPDX format — got '{fmt}'"))
        return OCTResult(
            overall_score=0.0,
            spdx_only_fail=True,
            records=records,
        )

    records.append(_req("oct_spec_format", 10.0, "document", fmt, "SPDX", "SPDX format confirmed"))

    # Document-level checks
    version = doc.spec_version or ""
    records.append(_req("oct_spec_version", 10.0 if version else 0.0, "document",
                        version, "SPDX version present", ""))

    has_ts = bool(doc.created and doc.created.strip())
    records.append(_req("oct_created_timestamp", 10.0 if has_ts else 0.0, "document",
                        doc.created or "", "RFC3339 timestamp", ""))

    has_ns = bool(doc.document_namespace and doc.document_namespace.strip())
    records.append(_req("oct_namespace", 10.0 if has_ns else 0.0, "document",
                        doc.document_namespace or "", "Document namespace URI", ""))

    doc_name = getattr(doc, "document_name", None) or ""
    records.append(_req("oct_doc_name", 10.0 if doc_name else 0.0, "document",
                        doc_name, "Document name", ""))

    # Authors / creator info
    has_org = any(
        "organization" in (a or "").lower() or "@" in (a or "") or "tool" in (a or "").lower()
        for a in (doc.authors or [])
    ) or bool(doc.tools)
    records.append(_req("oct_creator", 10.0 if has_org else 0.0, "document",
                        str(doc.authors or []), "Organization or tool in creator", ""))

    # Data license
    data_license = getattr(doc, "data_license", None) or ""
    has_data_license = bool(data_license.strip())
    records.append(_req("oct_data_license", 10.0 if has_data_license else 0.0, "document",
                        data_license, "CC0-1.0 or other data license", ""))

    # Machine-readable format check (JSON or Tag-Value)
    file_fmt = getattr(doc, "file_format", "json").lower()
    machine_readable = file_fmt in ("json", "tv", "tag-value", "tagvalue")
    records.append(_req("oct_machine_format", 10.0 if machine_readable else 0.0, "document",
                        file_fmt, "JSON or Tag-Value format",
                        f"File format: {file_fmt}"))

    # Per-component checks
    for comp in doc.components:
        cid = comp.name or "unknown"

        records.append(_req("oct_pkg_name", 10.0 if (comp.name and comp.name.strip()) else 0.0,
                            cid, comp.name or "", "Package name", ""))

        records.append(_req("oct_pkg_version", 10.0 if (comp.version and comp.version.strip()) else 0.0,
                            cid, comp.version or "", "Package version", ""))

        has_supplier = bool(comp.supplier and comp.supplier.strip())
        records.append(_req("oct_pkg_supplier", 10.0 if has_supplier else 0.0,
                            cid, comp.supplier or "", "Supplier with email", ""))

        # Download location
        ext_refs = getattr(comp, "external_references", []) or []
        download_url = ""
        for ref in ext_refs:
            if isinstance(ref, dict):
                rtype = (ref.get("type") or ref.get("referenceType") or "").lower()
                if rtype in ("download", "distribution"):
                    download_url = ref.get("url") or ref.get("referenceLocator") or ""
                    break
        # Also check packageDownloadLocation (SPDX field)
        if not download_url:
            download_url = getattr(comp, "download_location", "") or ""
        has_dl = bool(download_url) and download_url.upper() not in ("NOASSERTION", "NONE")
        records.append(_req("oct_pkg_download_url", 10.0 if has_dl else 0.0,
                            cid, download_url, "Download URL", ""))

        # SHA-256 checksum
        has_sha256 = False
        if comp.hashes:
            for algo in comp.hashes:
                if "256" in algo:
                    has_sha256 = True
        records.append(_req("oct_pkg_hash", 10.0 if has_sha256 else 0.0,
                            cid, str(list(comp.hashes.keys()) if comp.hashes else []),
                            "SHA-256 checksum", ""))

        # Concluded license (not NOASSERTION)
        lics = [l for l in (comp.licenses or []) if not is_absent(l)]
        records.append(_req("oct_pkg_concluded_license", 10.0 if lics else 0.0,
                            cid, str(lics), "Concluded license (not NOASSERTION/NONE)", ""))

        # Declared license
        declared = getattr(comp, "declared_licenses", None) or []
        declared_real = [l for l in declared if not is_absent(l)]
        if not declared_real:
            # Fall back to concluded licenses as declared if no separate field
            declared_real = lics
        records.append(_req("oct_pkg_declared_license", 10.0 if declared_real else 0.0,
                            cid, str(declared_real), "Declared license", ""))

        # Copyright
        copyright_text = getattr(comp, "copyright", None) or ""
        has_cr = bool(copyright_text.strip()) and copyright_text.strip().upper() not in (
            "NOASSERTION", "NONE"
        )
        records.append(_req("oct_pkg_copyright", 10.0 if has_cr else 0.0,
                            cid, copyright_text, "Copyright text", ""))

        # PURL in external references
        has_purl = bool(comp.purl and comp.purl.strip())
        records.append(_req("oct_pkg_external_ref_purl", 10.0 if has_purl else 0.0,
                            cid, comp.purl or "", "PURL in external references", ""))

    overall = compliance_score(records)
    return OCTResult(overall_score=overall, spdx_only_fail=False, records=records)
