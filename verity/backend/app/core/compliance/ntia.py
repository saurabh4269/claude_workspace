"""
NTIA Minimum Elements compliance checker.

Based on: "The Minimum Elements For a Software Bill of Materials (SBOM)"
US Department of Commerce / NTIA, July 2021.
Public domain document, freely implementable.

The seven required element groups + two NTIA-recommended elements:
1. Supplier Name (per component)
2. Component Name (per component)
3. Version of Component (per component)
4. Other Unique Identifiers (per component)
5. Dependency Relationships (document-level)
6. Author of SBOM Data (document-level)
7. Timestamp (document-level)
8. SBOM Generation Tool (recommended — tool with name+version)
9. Machine-readable Format (recommended — JSON or XML encoding)
"""

from __future__ import annotations
from dataclasses import dataclass

from app.core.parser import SBOMDocument, Component
from app.core.compliance.record import (
    ComplianceRecord, RecordTier, compliance_score, _req,
)


@dataclass
class NTIAElementResult:
    element_name: str
    compliant: bool
    score: float
    failing_components: list[str]
    detail: str

    def to_dict(self) -> dict:
        return {
            "element_name": self.element_name,
            "compliant": self.compliant,
            "score": self.score,
            "failing_components": self.failing_components,
            "detail": self.detail,
        }


@dataclass
class NTIAResult:
    overall_compliant: bool
    overall_score: float
    elements: list[NTIAElementResult]
    records: list[ComplianceRecord]

    def to_dict(self) -> dict:
        return {
            "standard": "NTIA Minimum Elements",
            "version": "July 2021",
            "overall_compliant": self.overall_compliant,
            "overall_score": self.overall_score,
            "elements": [e.to_dict() for e in self.elements],
        }


def check_ntia(doc: SBOMDocument) -> NTIAResult:
    """
    Check NTIA minimum element compliance for an SBOMDocument.
    Returns per-element detail, not just a boolean.
    """
    records: list[ComplianceRecord] = []
    elements: list[NTIAElementResult] = []

    # -----------------------------------------------------------------------
    # Element 6: Author of SBOM Data (document-level)
    # -----------------------------------------------------------------------
    has_author = bool(doc.authors and any(a.strip() for a in doc.authors)) or bool(doc.tools)
    author_score = 10.0 if has_author else 0.0
    records.append(_req(
        "sbom_authors", author_score, "document",
        str(doc.authors or []) or str(doc.tools or []),
        "At least one creator/author or tool",
        "SBOM creator information found" if has_author else "No author or tool information found",
    ))
    elements.append(NTIAElementResult(
        element_name="Author of SBOM Data",
        compliant=has_author,
        score=author_score,
        failing_components=[],
        detail="Creator/author or tool info: " + ("present" if has_author else "missing"),
    ))

    # -----------------------------------------------------------------------
    # Element 7: Timestamp (document-level)
    # -----------------------------------------------------------------------
    has_ts = bool(doc.created and doc.created.strip())
    ts_score = 10.0 if has_ts else 0.0
    records.append(_req(
        "sbom_timestamp", ts_score, "document",
        doc.created or "",
        "RFC3339 creation timestamp",
        f"Timestamp: {doc.created}" if has_ts else "No creation timestamp found",
    ))
    elements.append(NTIAElementResult(
        element_name="Timestamp",
        compliant=has_ts,
        score=ts_score,
        failing_components=[],
        detail=f"Creation timestamp: {doc.created or 'missing'}",
    ))

    # -----------------------------------------------------------------------
    # Element 5: Dependency Relationships (document-level)
    # -----------------------------------------------------------------------
    dep_graph = getattr(doc, "dependency_graph", None) or {}
    has_deps = bool(dep_graph.get("edges"))
    dep_score = 10.0 if has_deps else 0.0
    records.append(_req(
        "sbom_dependencies", dep_score, "document",
        f"{len(dep_graph.get('edges', []))} dependency edges",
        "At least one dependency relationship declared",
        "Dependency relationships found" if has_deps else "No dependency relationships declared",
    ))
    elements.append(NTIAElementResult(
        element_name="Dependency Relationships",
        compliant=has_deps,
        score=dep_score,
        failing_components=[],
        detail=f"{len(dep_graph.get('edges', []))} dependency edges declared",
    ))

    # -----------------------------------------------------------------------
    # Per-component elements: Name, Supplier, Version, Unique Identifiers
    # -----------------------------------------------------------------------
    comps = doc.components
    if not comps:
        for elem_name, key in [
            ("Component Name", "comp_with_name"),
            ("Supplier Name", "comp_with_supplier"),
            ("Version of Component", "comp_with_version"),
            ("Other Unique Identifiers", "comp_with_uniq_ids"),
        ]:
            records.append(_req(key, 10.0, "document", "N/A", "N/A", "No components in SBOM"))
            elements.append(NTIAElementResult(elem_name, True, 10.0, [], "No components to check"))
    else:
        # Name
        no_name = [c.name for c in comps if not (c.name and c.name.strip())]
        name_score = 10.0 if not no_name else 0.0
        for c in comps:
            records.append(_req(
                "comp_with_name",
                10.0 if (c.name and c.name.strip()) else 0.0,
                c.name or "unknown",
                c.name or "",
                "Non-empty component name",
                "Name present" if (c.name and c.name.strip()) else "Name missing",
            ))
        elements.append(NTIAElementResult(
            element_name="Component Name",
            compliant=not no_name,
            score=name_score,
            failing_components=no_name,
            detail=f"{len(comps) - len(no_name)}/{len(comps)} components have names",
        ))

        # Supplier
        no_supplier = [c.name for c in comps if not (c.supplier and c.supplier.strip())]
        supplier_score = 10.0 if not no_supplier else 0.0
        for c in comps:
            records.append(_req(
                "comp_with_supplier",
                10.0 if (c.supplier and c.supplier.strip()) else 0.0,
                c.name or "unknown",
                c.supplier or "",
                "Supplier name",
                "Supplier present" if (c.supplier and c.supplier.strip()) else "Supplier missing",
            ))
        elements.append(NTIAElementResult(
            element_name="Supplier Name",
            compliant=not no_supplier,
            score=supplier_score,
            failing_components=no_supplier,
            detail=f"{len(comps) - len(no_supplier)}/{len(comps)} components have supplier",
        ))

        # Version
        no_version = [c.name for c in comps if not (c.version and c.version.strip())]
        version_score = 10.0 if not no_version else 0.0
        for c in comps:
            records.append(_req(
                "comp_with_version",
                10.0 if (c.version and c.version.strip()) else 0.0,
                c.name or "unknown",
                c.version or "",
                "Non-empty version string",
                "Version present" if (c.version and c.version.strip()) else "Version missing",
            ))
        elements.append(NTIAElementResult(
            element_name="Version of Component",
            compliant=not no_version,
            score=version_score,
            failing_components=no_version,
            detail=f"{len(comps) - len(no_version)}/{len(comps)} components have versions",
        ))

        # Unique Identifiers (PURL or CPE)
        no_id = [c.name for c in comps if not ((c.purl and c.purl.strip()) or (c.cpe and c.cpe.strip()))]
        id_score = 10.0 if not no_id else 0.0
        for c in comps:
            has_id = bool((c.purl and c.purl.strip()) or (c.cpe and c.cpe.strip()))
            records.append(_req(
                "comp_with_uniq_ids",
                10.0 if has_id else 0.0,
                c.name or "unknown",
                c.purl or c.cpe or "",
                "PURL or CPE",
                "Identifier present" if has_id else "No PURL or CPE found",
            ))
        elements.append(NTIAElementResult(
            element_name="Other Unique Identifiers",
            compliant=not no_id,
            score=id_score,
            failing_components=no_id,
            detail=f"{len(comps) - len(no_id)}/{len(comps)} components have PURL or CPE",
        ))

    # -----------------------------------------------------------------------
    # Element 8: SBOM Generation Tool (recommended — tool with name+version)
    # NTIA guidance: the authoring tool, along with its version, should be
    # identified to allow consumers to understand how the SBOM was generated.
    # -----------------------------------------------------------------------
    tool_with_version = False
    for t in (doc.tools or []):
        if isinstance(t, dict):
            has_tname = bool(t.get("name") or t.get("vendor"))
            has_tver = bool(t.get("version"))
            if has_tname and has_tver:
                tool_with_version = True
                break
    tool_score = 10.0 if tool_with_version else 0.0
    records.append(_req(
        "sbom_generation_tool",
        tool_score,
        "document",
        str(doc.tools or []),
        "Tool with name and version",
        "SBOM generation tool with version found" if tool_with_version else "No tool with version declared",
    ))
    elements.append(NTIAElementResult(
        element_name="SBOM Generation Tool",
        compliant=tool_with_version,
        score=tool_score,
        failing_components=[],
        detail="Tool with name+version: " + ("present" if tool_with_version else "missing"),
    ))

    # -----------------------------------------------------------------------
    # Element 9: Machine-readable Format (recommended)
    # NTIA guidance: SBOM should be in a machine-readable format (JSON or XML)
    # to enable automated processing. Tag-value (.spdx) is human-readable but
    # not machine-parseable by the majority of consumer tooling.
    # -----------------------------------------------------------------------
    machine_readable = getattr(doc, "file_format", "json") in ("json", "xml")
    mr_score = 10.0 if machine_readable else 0.0
    file_fmt = getattr(doc, "file_format", "json")
    records.append(_req(
        "sbom_machine_readable_format",
        mr_score,
        "document",
        file_fmt,
        "JSON or XML encoding",
        f"Machine-readable format ({file_fmt})" if machine_readable else f"Format '{file_fmt}' has limited machine-readability",
    ))
    elements.append(NTIAElementResult(
        element_name="Machine-readable Format",
        compliant=machine_readable,
        score=mr_score,
        failing_components=[],
        detail=f"SBOM encoding: {file_fmt} ({'machine-readable' if machine_readable else 'limited machine-readability'})",
    ))

    overall_score = compliance_score(records)
    overall_compliant = all(e.compliant for e in elements)

    return NTIAResult(
        overall_compliant=overall_compliant,
        overall_score=overall_score,
        elements=elements,
        records=records,
    )
