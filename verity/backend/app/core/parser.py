"""
SBOM parser supporting CycloneDX (JSON and XML) and SPDX (JSON and tag-value).
Auto-detects the format from file content and extension.
"""

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


class ParseError(Exception):
    """Raised when SBOM content cannot be parsed."""
    pass


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
    component_type: Optional[str] = None
    raw: dict = field(default_factory=dict)


@dataclass
class SBOMDocument:
    format: str  # cyclonedx or spdx
    spec_version: Optional[str] = None
    document_name: Optional[str] = None
    document_namespace: Optional[str] = None
    created: Optional[str] = None
    authors: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


def parse(content: str, filename: str = "") -> SBOMDocument:
    """
    Auto-detect SBOM format and parse the content.

    Detection order:
    1. Try JSON parsing and inspect keys for CycloneDX or SPDX markers.
    2. Try XML parsing and inspect namespace for CycloneDX.
    3. Check for SPDX tag-value signature (SPDXVersion:).
    4. Use file extension as a final hint.

    Args:
        content: Raw string content of the SBOM file.
        filename: Original filename, used as a format hint.

    Returns:
        Parsed SBOMDocument.

    Raises:
        ParseError: If the format cannot be determined or parsing fails.
    """
    if not content or not content.strip():
        raise ParseError("SBOM content is empty")

    stripped = content.strip()

    # Attempt JSON
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON content: {exc}") from exc

        # CycloneDX JSON has a "bomFormat" key
        if isinstance(data, dict) and data.get("bomFormat", "").lower() == "cyclonedx":
            return _parse_cyclonedx_json(data)

        # SPDX JSON has a "spdxVersion" key
        if isinstance(data, dict) and "spdxVersion" in data:
            return _parse_spdx_json(data)

        # Use filename extension as a secondary hint
        lower_name = filename.lower()
        if "cyclonedx" in lower_name or lower_name.endswith(".cdx.json"):
            return _parse_cyclonedx_json(data)
        if "spdx" in lower_name:
            return _parse_spdx_json(data)

        # Try each parser and return the first that succeeds
        try:
            if isinstance(data, dict) and (
                "components" in data or "metadata" in data or "bomFormat" in data
            ):
                return _parse_cyclonedx_json(data)
        except ParseError:
            pass
        try:
            if isinstance(data, dict):
                return _parse_spdx_json(data)
        except ParseError:
            pass

        raise ParseError(
            "Cannot determine SBOM format from JSON content. "
            "Expected CycloneDX (bomFormat field) or SPDX (spdxVersion field)."
        )

    # Attempt XML (CycloneDX)
    if stripped.startswith("<"):
        return _parse_cyclonedx_xml(content)

    # Attempt SPDX tag-value (lines starting with "SPDXVersion:")
    if "SPDXVersion:" in content or "spdxVersion:" in content.lower():
        return _parse_spdx_tagvalue(content)

    # Extension-based final fallback
    lower_name = filename.lower()
    if lower_name.endswith(".spdx") or lower_name.endswith(".tv"):
        return _parse_spdx_tagvalue(content)

    raise ParseError(
        "Unsupported SBOM format. Supported: CycloneDX JSON/XML, SPDX JSON/tag-value."
    )


# ---------------------------------------------------------------------------
# CycloneDX JSON
# ---------------------------------------------------------------------------

def _parse_cyclonedx_json(data: dict) -> SBOMDocument:
    """Parse a CycloneDX JSON SBOM."""
    if not isinstance(data, dict):
        raise ParseError("CycloneDX JSON must be a JSON object")

    spec_version = data.get("specVersion") or data.get("version")
    metadata_raw = data.get("metadata") or {}
    component_raw = metadata_raw.get("component") or {}

    # Document name from metadata component or tools
    document_name = (
        component_raw.get("name")
        or data.get("serialNumber")
        or None
    )

    # Namespace / serial number
    document_namespace = data.get("serialNumber")

    # Created timestamp
    created = metadata_raw.get("timestamp")

    # Authors
    authors: list[str] = []
    for author in metadata_raw.get("authors") or []:
        name = author.get("name") if isinstance(author, dict) else str(author)
        if name:
            authors.append(name)

    # Tools
    tools: list[str] = []
    tools_raw = metadata_raw.get("tools") or []
    # CycloneDX 1.5+ wraps tools in {"components": [...]}
    if isinstance(tools_raw, dict):
        tools_raw = tools_raw.get("components") or tools_raw.get("tools") or []
    for tool in tools_raw:
        if isinstance(tool, dict):
            tool_name = tool.get("name") or tool.get("vendor") or ""
            tool_version = tool.get("version") or ""
            label = f"{tool_name} {tool_version}".strip()
            if label:
                tools.append(label)

    # Parse components
    components: list[Component] = []
    for raw_comp in data.get("components") or []:
        comp = _parse_cyclonedx_component(raw_comp)
        if comp is not None:
            components.append(comp)

    return SBOMDocument(
        format="cyclonedx",
        spec_version=str(spec_version) if spec_version is not None else None,
        document_name=document_name,
        document_namespace=document_namespace,
        created=created,
        authors=authors,
        tools=tools,
        components=components,
        metadata=metadata_raw,
    )


def _parse_cyclonedx_component(raw: dict) -> Optional[Component]:
    """Extract a Component from a CycloneDX JSON component dict."""
    if not isinstance(raw, dict):
        return None

    name = raw.get("name") or ""
    if not name:
        return None

    version = raw.get("version") or None
    purl = raw.get("purl") or None
    component_type = raw.get("type") or None
    description = raw.get("description") or None

    # CPE
    cpe = raw.get("cpe") or None

    # Supplier / publisher
    supplier = None
    supplier_raw = raw.get("supplier") or raw.get("publisher")
    if isinstance(supplier_raw, dict):
        supplier = supplier_raw.get("name") or None
    elif isinstance(supplier_raw, str):
        supplier = supplier_raw or None

    # Licenses
    licenses: list[str] = []
    for lic in raw.get("licenses") or []:
        if isinstance(lic, dict):
            # CycloneDX wraps license in {"license": {"id": "..."}} or {"expression": "..."}
            inner = lic.get("license") or lic
            lic_id = inner.get("id") or inner.get("name") or inner.get("expression") or ""
            if not lic_id:
                lic_id = lic.get("expression") or ""
            if lic_id:
                licenses.append(lic_id)
        elif isinstance(lic, str) and lic:
            licenses.append(lic)

    # Hashes
    hashes: dict[str, str] = {}
    for h in raw.get("hashes") or []:
        if isinstance(h, dict):
            alg = h.get("alg") or h.get("algorithm") or ""
            val = h.get("content") or h.get("value") or ""
            if alg and val:
                hashes[alg.upper()] = val

    return Component(
        name=name,
        version=version,
        purl=purl,
        cpe=cpe,
        supplier=supplier,
        licenses=licenses,
        hashes=hashes,
        description=description,
        component_type=component_type,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# CycloneDX XML
# ---------------------------------------------------------------------------

# CycloneDX XML namespace prefixes used across spec versions
_CDX_NAMESPACES = [
    "http://cyclonedx.org/schema/bom/1.6",
    "http://cyclonedx.org/schema/bom/1.5",
    "http://cyclonedx.org/schema/bom/1.4",
    "http://cyclonedx.org/schema/bom/1.3",
    "http://cyclonedx.org/schema/bom/1.2",
    "http://cyclonedx.org/schema/bom/1.1",
    "http://cyclonedx.org/schema/bom/1.0",
]


def _parse_cyclonedx_xml(content: str) -> SBOMDocument:
    """Parse a CycloneDX XML SBOM."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ParseError(f"Invalid XML: {exc}") from exc

    # Detect namespace
    ns = ""
    tag = root.tag
    if tag.startswith("{"):
        ns = tag[1 : tag.index("}")]

    ns_prefix = f"{{{ns}}}" if ns else ""

    # Spec version from attribute or namespace
    spec_version = root.get("version")
    if spec_version is None and ns:
        # Extract version from namespace URL, e.g. .../1.4
        parts = ns.rstrip("/").split("/")
        if parts:
            spec_version = parts[-1]

    metadata_el = root.find(f"{ns_prefix}metadata")

    # Created timestamp
    created = None
    if metadata_el is not None:
        ts_el = metadata_el.find(f"{ns_prefix}timestamp")
        if ts_el is not None:
            created = (ts_el.text or "").strip() or None

    # Authors
    authors: list[str] = []
    if metadata_el is not None:
        for author_el in metadata_el.findall(f".//{ns_prefix}author"):
            name_el = author_el.find(f"{ns_prefix}name")
            name = (name_el.text or "").strip() if name_el is not None else ""
            if not name:
                name = (author_el.text or "").strip()
            if name:
                authors.append(name)

    # Tools
    tools: list[str] = []
    if metadata_el is not None:
        for tool_el in metadata_el.findall(f".//{ns_prefix}tool"):
            tool_name_el = tool_el.find(f"{ns_prefix}name")
            tool_ver_el = tool_el.find(f"{ns_prefix}version")
            tool_name = (
                (tool_name_el.text or "").strip() if tool_name_el is not None else ""
            )
            tool_ver = (
                (tool_ver_el.text or "").strip() if tool_ver_el is not None else ""
            )
            label = f"{tool_name} {tool_ver}".strip()
            if label:
                tools.append(label)

    # Document name from metadata component
    document_name = None
    if metadata_el is not None:
        meta_comp = metadata_el.find(f"{ns_prefix}component")
        if meta_comp is not None:
            name_el = meta_comp.find(f"{ns_prefix}name")
            if name_el is not None:
                document_name = (name_el.text or "").strip() or None

    # Serial number
    document_namespace = root.get("serialNumber")

    # Parse components
    components: list[Component] = []
    components_el = root.find(f"{ns_prefix}components")
    if components_el is not None:
        for comp_el in components_el.findall(f"{ns_prefix}component"):
            comp = _parse_cyclonedx_xml_component(comp_el, ns_prefix)
            if comp is not None:
                components.append(comp)

    return SBOMDocument(
        format="cyclonedx",
        spec_version=spec_version,
        document_name=document_name,
        document_namespace=document_namespace,
        created=created,
        authors=authors,
        tools=tools,
        components=components,
        metadata={"namespace": ns},
    )


def _get_text(el: Optional[ET.Element], tag: str, ns_prefix: str) -> Optional[str]:
    """Get stripped text of a child element, or None."""
    child = el.find(f"{ns_prefix}{tag}") if el is not None else None
    if child is None:
        return None
    return (child.text or "").strip() or None


def _parse_cyclonedx_xml_component(
    el: ET.Element, ns_prefix: str
) -> Optional[Component]:
    """Extract a Component from a CycloneDX XML component element."""
    name = _get_text(el, "name", ns_prefix) or ""
    if not name:
        return None

    version = _get_text(el, "version", ns_prefix)
    purl = _get_text(el, "purl", ns_prefix)
    cpe = _get_text(el, "cpe", ns_prefix)
    description = _get_text(el, "description", ns_prefix)
    component_type = el.get("type")

    # Supplier
    supplier = None
    supplier_el = el.find(f"{ns_prefix}supplier")
    if supplier_el is not None:
        name_el = supplier_el.find(f"{ns_prefix}name")
        supplier = _get_text(supplier_el, "name", ns_prefix) if name_el is not None else None

    # Licenses
    licenses: list[str] = []
    licenses_el = el.find(f"{ns_prefix}licenses")
    if licenses_el is not None:
        for lic_el in licenses_el:
            # <license><id>...</id></license> or <expression>...</expression>
            lic_id_el = lic_el.find(f"{ns_prefix}id")
            lic_name_el = lic_el.find(f"{ns_prefix}name")
            expr_el = lic_el.find(f"{ns_prefix}expression")
            lic_str = (
                (_get_text(lic_el, "id", ns_prefix))
                or (_get_text(lic_el, "name", ns_prefix))
                or (_get_text(lic_el, "expression", ns_prefix))
                or ((lic_id_el.text or "") if lic_id_el is not None else "")
                or ((lic_name_el.text or "") if lic_name_el is not None else "")
                or ((expr_el.text or "") if expr_el is not None else "")
            )
            if lic_str:
                licenses.append(lic_str.strip())

    # Hashes
    hashes: dict[str, str] = {}
    hashes_el = el.find(f"{ns_prefix}hashes")
    if hashes_el is not None:
        for h_el in hashes_el.findall(f"{ns_prefix}hash"):
            alg = h_el.get("alg") or ""
            val = (h_el.text or "").strip()
            if alg and val:
                hashes[alg.upper()] = val

    return Component(
        name=name,
        version=version,
        purl=purl,
        cpe=cpe,
        supplier=supplier,
        licenses=licenses,
        hashes=hashes,
        description=description,
        component_type=component_type,
        raw={},
    )


# ---------------------------------------------------------------------------
# SPDX JSON
# ---------------------------------------------------------------------------

def _parse_spdx_json(data: dict) -> SBOMDocument:
    """Parse an SPDX JSON SBOM."""
    if not isinstance(data, dict):
        raise ParseError("SPDX JSON must be a JSON object")

    spec_version = data.get("spdxVersion") or None
    document_name = data.get("name") or None
    document_namespace = data.get("documentNamespace") or None
    created = None

    creation_info = data.get("creationInfo") or {}
    if isinstance(creation_info, dict):
        created = creation_info.get("created") or None

    # Authors from creationInfo.creators
    authors: list[str] = []
    tools: list[str] = []
    for creator in creation_info.get("creators") or []:
        creator_str = str(creator)
        if creator_str.startswith("Tool:"):
            tools.append(creator_str[5:].strip())
        elif creator_str.startswith("Organization:"):
            authors.append(creator_str[13:].strip())
        elif creator_str.startswith("Person:"):
            authors.append(creator_str[7:].strip())
        else:
            authors.append(creator_str)

    # Build a map of SPDX element IDs to package data for relationship traversal
    packages: list[Component] = []
    for pkg in data.get("packages") or []:
        comp = _parse_spdx_package(pkg)
        if comp is not None:
            packages.append(comp)

    return SBOMDocument(
        format="spdx",
        spec_version=spec_version,
        document_name=document_name,
        document_namespace=document_namespace,
        created=created,
        authors=authors,
        tools=tools,
        components=packages,
        metadata={"creationInfo": creation_info},
    )


def _parse_spdx_package(pkg: dict) -> Optional[Component]:
    """Extract a Component from an SPDX package dict."""
    if not isinstance(pkg, dict):
        return None

    name = pkg.get("name") or ""
    if not name:
        return None

    # NOASSERTION and NONE are sentinel values in SPDX
    def _spdx_val(v: Optional[str]) -> Optional[str]:
        if v in (None, "NOASSERTION", "NONE", ""):
            return None
        return v

    version = _spdx_val(pkg.get("versionInfo"))
    purl = None
    cpe = None
    supplier = _spdx_val(pkg.get("supplier"))
    description = _spdx_val(pkg.get("description") or pkg.get("summary"))

    # Strip "Organization:" or "Person:" prefix from supplier
    if supplier and ":" in supplier:
        supplier = supplier.split(":", 1)[1].strip() or None

    # External references: PURL and CPE live here
    for ref in pkg.get("externalRefs") or []:
        if not isinstance(ref, dict):
            continue
        ref_type = ref.get("referenceType") or ""
        ref_loc = ref.get("referenceLocator") or ""
        if ref_type.lower() == "purl" and ref_loc:
            purl = ref_loc
        elif ref_type.lower() in ("cpe22type", "cpe23type", "cpe") and ref_loc:
            cpe = ref_loc

    # Licenses
    licenses: list[str] = []
    concluded = _spdx_val(pkg.get("licenseConcluded"))
    declared = _spdx_val(pkg.get("licenseDeclared"))
    if concluded:
        licenses.append(concluded)
    if declared and declared != concluded:
        licenses.append(declared)

    # Hashes / checksums
    hashes: dict[str, str] = {}
    for cs in pkg.get("checksums") or []:
        if isinstance(cs, dict):
            alg = cs.get("algorithm") or ""
            val = cs.get("checksumValue") or ""
            if alg and val:
                hashes[alg.upper()] = val

    return Component(
        name=name,
        version=version,
        purl=purl,
        cpe=cpe,
        supplier=supplier,
        licenses=licenses,
        hashes=hashes,
        description=description,
        component_type=None,
        raw=pkg,
    )


# ---------------------------------------------------------------------------
# SPDX tag-value
# ---------------------------------------------------------------------------

def _parse_spdx_tagvalue(content: str) -> SBOMDocument:
    """Parse an SPDX tag-value (.spdx / .tv) SBOM."""
    lines = content.splitlines()

    spec_version: Optional[str] = None
    document_name: Optional[str] = None
    document_namespace: Optional[str] = None
    created: Optional[str] = None
    creators: list[str] = []
    authors: list[str] = []
    tools: list[str] = []

    # Collect document-level fields and package blocks
    current_pkg: Optional[dict] = None
    packages: list[dict] = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" not in line:
            continue

        tag, _, value = line.partition(":")
        tag = tag.strip()
        value = value.strip()

        # Document-level tags
        if tag == "SPDXVersion":
            spec_version = value
        elif tag == "DocumentName":
            document_name = value
        elif tag == "DocumentNamespace":
            document_namespace = value
        elif tag == "Created":
            created = value
        elif tag == "Creator":
            creators.append(value)
        # Package block tags
        elif tag == "PackageName":
            if current_pkg is not None:
                packages.append(current_pkg)
            current_pkg = {"PackageName": value}
        elif current_pkg is not None:
            current_pkg[tag] = value

    # Append the last package block
    if current_pkg is not None:
        packages.append(current_pkg)

    # Parse creators into authors/tools
    for creator in creators:
        if creator.startswith("Tool:"):
            tools.append(creator[5:].strip())
        elif creator.startswith("Organization:"):
            authors.append(creator[13:].strip())
        elif creator.startswith("Person:"):
            authors.append(creator[7:].strip())
        else:
            authors.append(creator)

    # Convert package dicts to Components
    components: list[Component] = []
    for pkg in packages:
        comp = _parse_spdx_tv_package(pkg)
        if comp is not None:
            components.append(comp)

    return SBOMDocument(
        format="spdx",
        spec_version=spec_version,
        document_name=document_name,
        document_namespace=document_namespace,
        created=created,
        authors=authors,
        tools=tools,
        components=components,
        metadata={"creators": creators},
    )


def _parse_spdx_tv_package(pkg: dict) -> Optional[Component]:
    """Convert a raw tag-value package dict into a Component."""
    name = pkg.get("PackageName") or ""
    if not name:
        return None

    def _tv_val(v: Optional[str]) -> Optional[str]:
        if v in (None, "NOASSERTION", "NONE", ""):
            return None
        return v

    version = _tv_val(pkg.get("PackageVersion"))
    purl = None
    cpe = None
    supplier = _tv_val(pkg.get("PackageSupplier"))

    # Strip "Organization:" or "Person:" prefix
    if supplier and ":" in supplier:
        supplier = supplier.split(":", 1)[1].strip() or None

    # ExternalRef lines may have been overwritten by repeated keys;
    # We handle the last value here. For proper multi-value support,
    # a full tag-value parser would accumulate them.
    ext_ref = pkg.get("ExternalRef") or ""
    if ext_ref:
        parts = ext_ref.split()
        if len(parts) >= 3:
            ref_cat, ref_type, ref_loc = parts[0], parts[1], parts[2]
            if ref_type.lower() == "purl":
                purl = ref_loc
            elif ref_type.lower() in ("cpe22type", "cpe23type"):
                cpe = ref_loc

    # Licenses
    licenses: list[str] = []
    concluded = _tv_val(pkg.get("PackageLicenseConcluded"))
    declared = _tv_val(pkg.get("PackageLicenseDeclared"))
    if concluded:
        licenses.append(concluded)
    if declared and declared != concluded:
        licenses.append(declared)

    # Checksums
    hashes: dict[str, str] = {}
    checksum = pkg.get("PackageChecksum") or ""
    if checksum and ":" in checksum:
        alg, _, val = checksum.partition(":")
        hashes[alg.strip().upper()] = val.strip()

    return Component(
        name=name,
        version=version,
        purl=purl,
        cpe=cpe,
        supplier=supplier,
        licenses=licenses,
        hashes=hashes,
        description=None,
        component_type=None,
        raw=pkg,
    )
