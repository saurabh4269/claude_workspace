"""
SBOM Parser: Supports CycloneDX (JSON/XML) and SPDX (JSON/tag-value) formats.
"""

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Component:
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    supplier: Optional[str] = None
    licenses: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    description: Optional[str] = None
    component_type: Optional[str] = None  # library, framework, application, etc.
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class SBOMDocument:
    format: str  # "cyclonedx" or "spdx"
    format_version: Optional[str] = None
    spec_version: Optional[str] = None
    document_name: Optional[str] = None
    document_namespace: Optional[str] = None
    created: Optional[str] = None
    authors: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


class ParseError(Exception):
    pass


def parse(content: str, filename: str = "") -> SBOMDocument:
    """Auto-detect format and parse SBOM content."""
    ext = filename.lower().split(".")[-1] if filename else ""

    # Try JSON first
    if ext in ("json", "") or content.strip().startswith("{"):
        try:
            data = json.loads(content)
            if "bomFormat" in data or "components" in data:
                return _parse_cyclonedx_json(data)
            if "spdxVersion" in data or "SPDXID" in data:
                return _parse_spdx_json(data)
        except json.JSONDecodeError:
            pass

    # Try XML (CycloneDX)
    if ext == "xml" or content.strip().startswith("<"):
        try:
            return _parse_cyclonedx_xml(content)
        except ET.ParseError:
            pass

    # Try SPDX tag-value
    if ext in ("spdx", "tv") or "SPDXVersion:" in content:
        return _parse_spdx_tagvalue(content)

    raise ParseError(f"Unable to detect SBOM format for: {filename!r}")


# ── CycloneDX JSON ──────────────────────────────────────────────────────────

def _parse_cyclonedx_json(data: dict) -> SBOMDocument:
    doc = SBOMDocument(
        format="cyclonedx",
        spec_version=data.get("specVersion"),
        format_version=data.get("version"),
        raw=data,
    )

    meta = data.get("metadata", {})
    doc.created = meta.get("timestamp")
    component_meta = meta.get("component", {})
    doc.document_name = component_meta.get("name") or data.get("serialNumber")
    doc.document_namespace = data.get("serialNumber")

    for tool in meta.get("tools", []):
        if isinstance(tool, dict):
            doc.tools.append(f"{tool.get('vendor', '')} {tool.get('name', '')} {tool.get('version', '')}".strip())
    for author in meta.get("authors", []):
        if isinstance(author, dict):
            doc.authors.append(author.get("name", ""))

    for comp in data.get("components", []):
        doc.components.append(_cyclonedx_component(comp))

    return doc


def _cyclonedx_component(c: dict) -> Component:
    licenses = []
    for lic in c.get("licenses", []):
        if isinstance(lic, dict):
            if "license" in lic:
                licenses.append(lic["license"].get("id") or lic["license"].get("name", ""))
            elif "expression" in lic:
                licenses.append(lic["expression"])

    hashes = {}
    for h in c.get("hashes", []):
        if isinstance(h, dict):
            hashes[h.get("alg", "").upper()] = h.get("content", "")

    return Component(
        name=c.get("name", ""),
        version=c.get("version"),
        purl=c.get("purl"),
        cpe=c.get("cpe"),
        supplier=c.get("supplier", {}).get("name") if isinstance(c.get("supplier"), dict) else c.get("supplier"),
        licenses=licenses,
        hashes=hashes,
        description=c.get("description"),
        component_type=c.get("type"),
        raw=c,
    )


# ── CycloneDX XML ───────────────────────────────────────────────────────────

def _parse_cyclonedx_xml(content: str) -> SBOMDocument:
    root = ET.fromstring(content)
    ns_match = re.match(r"\{(.+?)\}", root.tag)
    ns = ns_match.group(1) if ns_match else ""
    prefix = f"{{{ns}}}" if ns else ""

    doc = SBOMDocument(
        format="cyclonedx",
        spec_version=root.attrib.get("version"),
        raw={},
    )

    meta = root.find(f"{prefix}metadata")
    if meta is not None:
        ts = meta.find(f"{prefix}timestamp")
        doc.created = ts.text if ts is not None else None
        comp = meta.find(f"{prefix}component")
        if comp is not None:
            name_el = comp.find(f"{prefix}name")
            doc.document_name = name_el.text if name_el is not None else None

    components_el = root.find(f"{prefix}components")
    if components_el is not None:
        for c in components_el.findall(f"{prefix}component"):
            doc.components.append(_cyclonedx_xml_component(c, prefix))

    return doc


def _cyclonedx_xml_component(c, prefix: str) -> Component:
    def text(tag):
        el = c.find(f"{prefix}{tag}")
        return el.text if el is not None else None

    licenses = []
    for lic in c.findall(f".//{prefix}license"):
        id_el = lic.find(f"{prefix}id")
        name_el = lic.find(f"{prefix}name")
        if id_el is not None:
            licenses.append(id_el.text)
        elif name_el is not None:
            licenses.append(name_el.text)

    hashes = {}
    for h in c.findall(f"{prefix}hashes/{prefix}hash"):
        alg = h.attrib.get("alg", "").upper()
        if alg:
            hashes[alg] = h.text or ""

    return Component(
        name=text("name") or "",
        version=text("version"),
        purl=text("purl"),
        cpe=text("cpe"),
        supplier=text("supplier"),
        licenses=licenses,
        hashes=hashes,
        description=text("description"),
        component_type=c.attrib.get("type"),
        raw={},
    )


# ── SPDX JSON ───────────────────────────────────────────────────────────────

def _parse_spdx_json(data: dict) -> SBOMDocument:
    doc = SBOMDocument(
        format="spdx",
        spec_version=data.get("spdxVersion"),
        document_name=data.get("name"),
        document_namespace=data.get("documentNamespace"),
        created=data.get("creationInfo", {}).get("created"),
        raw=data,
    )

    creation_info = data.get("creationInfo", {})
    for creator in creation_info.get("creators", []):
        if creator.startswith("Tool:"):
            doc.tools.append(creator[5:].strip())
        elif creator.startswith("Organization:") or creator.startswith("Person:"):
            doc.authors.append(creator.split(":", 1)[1].strip())

    for pkg in data.get("packages", []):
        doc.components.append(_spdx_package_to_component(pkg))

    return doc


def _spdx_package_to_component(pkg: dict) -> Component:
    licenses = []
    for field in ("licenseConcluded", "licenseDeclared"):
        lic = pkg.get(field)
        if lic and lic not in ("NOASSERTION", "NONE"):
            licenses.append(lic)

    hashes = {}
    for ck in pkg.get("checksums", []):
        if isinstance(ck, dict):
            hashes[ck.get("algorithm", "").upper()] = ck.get("checksumValue", "")

    ext_refs = pkg.get("externalRefs", [])
    purl = next(
        (r.get("referenceLocator") for r in ext_refs if r.get("referenceType") == "purl"), None
    )
    cpe = next(
        (r.get("referenceLocator") for r in ext_refs
         if r.get("referenceType", "").startswith("cpe")), None
    )

    return Component(
        name=pkg.get("name", ""),
        version=pkg.get("versionInfo"),
        purl=purl,
        cpe=cpe,
        supplier=pkg.get("supplier"),
        licenses=list(set(licenses)),
        hashes=hashes,
        description=pkg.get("summary") or pkg.get("description"),
        raw=pkg,
    )


# ── SPDX Tag-Value ──────────────────────────────────────────────────────────

def _parse_spdx_tagvalue(content: str) -> SBOMDocument:
    doc = SBOMDocument(format="spdx", raw={})
    current_pkg: dict | None = None
    packages: list[dict] = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        tag, _, value = line.partition(":")
        tag = tag.strip()
        value = value.strip()

        if tag == "SPDXVersion":
            doc.spec_version = value
        elif tag == "DocumentName":
            doc.document_name = value
        elif tag == "DocumentNamespace":
            doc.document_namespace = value
        elif tag == "Created":
            doc.created = value
        elif tag == "Creator":
            if value.startswith("Tool:"):
                doc.tools.append(value[5:].strip())
            else:
                doc.authors.append(value.split(":", 1)[-1].strip())
        elif tag == "PackageName":
            if current_pkg:
                packages.append(current_pkg)
            current_pkg = {"name": value, "externalRefs": []}
        elif current_pkg is not None:
            if tag == "PackageVersion":
                current_pkg["versionInfo"] = value
            elif tag == "PackageSupplier":
                current_pkg["supplier"] = value
            elif tag == "PackageChecksum":
                alg, _, val = value.partition(":")
                current_pkg.setdefault("checksums", []).append(
                    {"algorithm": alg.strip().upper(), "checksumValue": val.strip()}
                )
            elif tag == "PackageLicenseConcluded":
                current_pkg["licenseConcluded"] = value
            elif tag == "PackageLicenseDeclared":
                current_pkg["licenseDeclared"] = value
            elif tag == "ExternalRef":
                parts = value.split()
                if len(parts) >= 3:
                    current_pkg["externalRefs"].append(
                        {"referenceCategory": parts[0], "referenceType": parts[1], "referenceLocator": parts[2]}
                    )
            elif tag in ("PackageSummary", "PackageDescription"):
                current_pkg["summary"] = value

    if current_pkg:
        packages.append(current_pkg)

    for pkg in packages:
        doc.components.append(_spdx_package_to_component(pkg))

    return doc
