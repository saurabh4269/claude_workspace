"""
SBOM parser supporting CycloneDX (JSON and XML) and SPDX (JSON and tag-value).
Auto-detects format from content and extension.

Extracts dependency graphs, declared licenses, external references,
signature data, and other fields required for compliance checking.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
import yaml
from dataclasses import dataclass, field
from typing import Optional

from app.core.validation.schema_validator import validate_schema


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
    manufacturer: Optional[str] = None   # CDX manufacturer / SPDX PackageOriginator fallback
    licenses: list[str] = field(default_factory=list)
    declared_licenses: list[str] = field(default_factory=list)   # upstream-declared
    hashes: dict[str, str] = field(default_factory=dict)
    description: Optional[str] = None
    component_type: Optional[str] = None
    external_references: list[dict] = field(default_factory=list)
    properties: dict = field(default_factory=dict)
    copyright: Optional[str] = None
    download_location: Optional[str] = None
    filename: Optional[str] = None           # SPDX PackageFileName / CDX bsi:component:filename
    # bom-ref / SPDXID used for dependency graph edge resolution
    bom_ref: Optional[str] = None
    # SPDX-specific: FilesAnalyzed (True by default per spec)
    files_analyzed: Optional[bool] = None
    # True when any license entry carries a URL or embedded text (enables FSCT tier 15)
    license_has_url_or_text: bool = False
    raw: dict = field(default_factory=dict)


@dataclass
class DependencyGraph:
    nodes: list[str] = field(default_factory=list)   # bom-refs / spdxids
    # edges: list of (from_ref, to_ref, relationship_type)
    edges: list[tuple[str, str, str]] = field(default_factory=list)
    primary_component_ref: Optional[str] = None
    orphans: list[str] = field(default_factory=list)
    is_complete: bool = False
    max_depth: int = 0

    def to_dict(self) -> dict:
        return {
            "nodes": self.nodes,
            "edges": [(f, t, r) for f, t, r in self.edges],
            "primary_component_ref": self.primary_component_ref,
            "orphans": self.orphans,
            "is_complete": self.is_complete,
            "max_depth": self.max_depth,
        }


@dataclass
class SBOMDocument:
    format: str                              # cyclonedx | spdx
    spec_version: Optional[str] = None
    document_name: Optional[str] = None
    document_namespace: Optional[str] = None
    created: Optional[str] = None
    authors: list[str] = field(default_factory=list)
    tools: list = field(default_factory=list)   # list of str or dict
    components: list[Component] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    # Enhanced fields
    primary_component: Optional[str] = None      # name of primary component
    supplier: Optional[str] = None               # document-level supplier
    lifecycles: list[str] = field(default_factory=list)
    signature: Optional[dict] = None             # document-level signature block
    bom_links: list[str] = field(default_factory=list)
    data_license: Optional[str] = None
    vulnerabilities: list[dict] = field(default_factory=list)
    dependency_graph: Optional[dict] = None      # serialized DependencyGraph
    compositions: list[dict] = field(default_factory=list)   # CDX compositions entries
    schema_valid: bool = True
    file_format: str = "json"
    spdx_id: Optional[str] = None           # document-level SPDXID (always SPDXRef-DOCUMENT for valid SPDX)
    document_comment: Optional[str] = None  # SPDX DocumentComment / creationInfo.comment


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse(content: str, filename: str = "") -> SBOMDocument:
    """
    Auto-detect SBOM format and parse content.

    Detection order:
      1. JSON → CycloneDX (bomFormat) or SPDX (spdxVersion)
      2. XML → CycloneDX
      3. Tag-value → SPDX
      4. File extension as final hint

    Raises ParseError on unrecognized or malformed content.
    """
    if not content or not content.strip():
        raise ParseError("SBOM content is empty")

    stripped = content.strip()
    lower_name = filename.lower()

    # Determine file_format hint
    file_format = "json"
    if lower_name.endswith(".xml"):
        file_format = "xml"
    elif lower_name.endswith((".spdx", ".tv")):
        file_format = "tv"
    elif lower_name.endswith((".yaml", ".yml")):
        file_format = "yaml"

    # --- JSON ---
    if stripped.startswith(("{", "[")):
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc}") from exc

        if isinstance(data, dict):
            if data.get("bomFormat", "").lower() == "cyclonedx":
                doc = _parse_cyclonedx_json(data)
                doc.file_format = "json"
                return doc
            if "spdxVersion" in data:
                doc = _parse_spdx_json(data)
                doc.file_format = "json"
                return doc
            # Extension hints
            if "cyclonedx" in lower_name or lower_name.endswith(".cdx.json"):
                doc = _parse_cyclonedx_json(data)
                doc.file_format = "json"
                return doc
            if "spdx" in lower_name:
                doc = _parse_spdx_json(data)
                doc.file_format = "json"
                return doc
            # Structural guessing — require at least one recognizable SBOM field
            if "components" in data or "metadata" in data:
                doc = _parse_cyclonedx_json(data)
                doc.file_format = "json"
                return doc
            if "packages" in data or "files" in data or "relationships" in data:
                doc = _parse_spdx_json(data)
                doc.file_format = "json"
                return doc
            # No recognizable SBOM structure found
            raise ParseError(
                "Unsupported SBOM format. Supported: CycloneDX JSON/XML, SPDX JSON/tag-value."
            )
        raise ParseError("JSON SBOM must be a JSON object")

    # --- XML ---
    if stripped.startswith("<"):
        doc = _parse_cyclonedx_xml(content)
        doc.file_format = "xml"
        return doc

    # --- Tag-value ---
    if "SPDXVersion:" in content or "spdxVersion:" in content.lower():
        doc = _parse_spdx_tagvalue(content)
        doc.file_format = "tv"
        return doc
    if lower_name.endswith((".spdx", ".tv")):
        doc = _parse_spdx_tagvalue(content)
        doc.file_format = "tv"
        return doc

    # --- YAML (SPDX YAML format) ---
    if lower_name.endswith((".yaml", ".yml")):
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise ParseError(f"Invalid YAML: {exc}") from exc
        if isinstance(data, dict) and "spdxVersion" in data:
            doc = _parse_spdx_json(data)
            doc.file_format = "yaml"
            return doc
        raise ParseError("YAML SBOM must contain 'spdxVersion' — only SPDX YAML is supported")

    # Content-sniff YAML: try if content looks like YAML key-value pairs
    if "spdxVersion:" in stripped:
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and "spdxVersion" in data:
                doc = _parse_spdx_json(data)
                doc.file_format = "yaml"
                return doc
        except yaml.YAMLError:
            pass

    raise ParseError(
        "Unsupported SBOM format. Supported: CycloneDX JSON/XML, SPDX JSON/YAML/tag-value."
    )


# ---------------------------------------------------------------------------
# Dependency graph builder
# ---------------------------------------------------------------------------

def _build_dependency_graph(
    edges: list[tuple[str, str, str]],
    nodes: list[str],
    primary_ref: Optional[str],
    is_complete: bool,
) -> DependencyGraph:
    """
    Build a DependencyGraph with DFS traversal to find orphans and max depth.
    """
    node_set = set(nodes)

    # Adjacency list for DFS
    adj: dict[str, list[str]] = {n: [] for n in node_set}
    for from_ref, to_ref, _ in edges:
        if from_ref in adj:
            adj[from_ref].append(to_ref)

    # DFS from primary component
    visited: set[str] = set()
    max_depth = 0

    def dfs(node: str, depth: int) -> None:
        nonlocal max_depth
        if node in visited:
            return
        visited.add(node)
        max_depth = max(max_depth, depth)
        for child in adj.get(node, []):
            dfs(child, depth + 1)

    if primary_ref and primary_ref in node_set:
        dfs(primary_ref, 0)
    elif nodes:
        # If no primary, start from all roots (nodes with no incoming edges)
        has_incoming = {to_ref for _, to_ref, _ in edges}
        roots = [n for n in nodes if n not in has_incoming]
        for root in roots:
            dfs(root, 0)

    orphans = [n for n in nodes if n not in visited and n != primary_ref]

    return DependencyGraph(
        nodes=list(node_set),
        edges=edges,
        primary_component_ref=primary_ref,
        orphans=orphans,
        is_complete=is_complete,
        max_depth=max_depth,
    )


# ---------------------------------------------------------------------------
# CycloneDX JSON
# ---------------------------------------------------------------------------

def _parse_cyclonedx_json(data: dict) -> SBOMDocument:
    if not isinstance(data, dict):
        raise ParseError("CycloneDX JSON must be a JSON object")

    spec_version = str(data.get("specVersion") or "")
    metadata_raw = data.get("metadata") or {}
    component_raw = metadata_raw.get("component") or {}

    document_name = component_raw.get("name") or data.get("serialNumber") or None
    document_namespace = data.get("serialNumber")
    created = metadata_raw.get("timestamp")

    # Authors
    authors: list[str] = []
    for author in metadata_raw.get("authors") or []:
        val = author.get("name") if isinstance(author, dict) else str(author)
        if val:
            authors.append(val)

    # Supplier (document-level)
    supplier_raw = metadata_raw.get("supplier")
    doc_supplier = None
    if isinstance(supplier_raw, dict):
        doc_supplier = supplier_raw.get("name")
    elif isinstance(supplier_raw, str):
        doc_supplier = supplier_raw or None

    # Tools — keep as dicts for tier scoring
    tools: list = []
    tools_raw = metadata_raw.get("tools") or []
    if isinstance(tools_raw, dict):
        tools_raw = tools_raw.get("components") or tools_raw.get("tools") or []
    for tool in tools_raw:
        if isinstance(tool, dict):
            tools.append(tool)
        elif isinstance(tool, str):
            tools.append({"name": tool})

    # Lifecycles (CDX 1.5+)
    lifecycles: list[str] = []
    for lc in metadata_raw.get("lifecycles") or []:
        if isinstance(lc, dict):
            phase = lc.get("phase") or lc.get("name") or ""
            if phase:
                lifecycles.append(phase)
        elif isinstance(lc, str):
            lifecycles.append(lc)

    # Signature (CDX 1.5+)
    signature = data.get("signature") or metadata_raw.get("signature") or None

    # BOM links
    bom_links: list[str] = []
    for ext_ref in metadata_raw.get("externalReferences") or []:
        if isinstance(ext_ref, dict) and (ext_ref.get("type") or "").lower() == "bom":
            url = ext_ref.get("url") or ""
            if url:
                bom_links.append(url)

    # Data license (CDX metadata.licenses — the SBOM's own license, not component licenses)
    cdx_data_license = None
    for lic_entry in metadata_raw.get("licenses") or []:
        if isinstance(lic_entry, dict):
            inner = lic_entry.get("license") or lic_entry
            lid = inner.get("id") or inner.get("name") or lic_entry.get("expression") or ""
            if lid:
                cdx_data_license = lid
                break

    # Vulnerabilities (CDX 1.4+)
    vulnerabilities = data.get("vulnerabilities") or []

    # Primary component name
    primary_component = component_raw.get("name") or None
    primary_ref = component_raw.get("bom-ref") or None

    # Parse components
    components: list[Component] = []
    for raw_comp in data.get("components") or []:
        comp = _parse_cyclonedx_component(raw_comp, spec_version)
        if comp is not None:
            components.append(comp)

    # Build node list from components
    node_refs = [c.bom_ref for c in components if c.bom_ref]

    # Dependency graph from "dependencies" array
    edges: list[tuple[str, str, str]] = []
    is_complete = False
    for dep in data.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        from_ref = dep.get("ref") or ""
        for to_ref in dep.get("dependsOn") or []:
            edges.append((from_ref, str(to_ref), "DEPENDS_ON"))

    # Compositions: check for aggregate=complete
    for comp_obj in data.get("compositions") or []:
        if isinstance(comp_obj, dict):
            if (comp_obj.get("aggregate") or "").lower() == "complete":
                is_complete = True

    graph = _build_dependency_graph(edges, node_refs, primary_ref, is_complete)

    # JSON schema validation against embedded official CycloneDX schemas
    schema_valid = validate_schema(data, "cyclonedx", spec_version or "")

    doc = SBOMDocument(
        format="cyclonedx",
        spec_version=spec_version or None,
        document_name=document_name,
        document_namespace=document_namespace,
        created=created,
        authors=authors,
        tools=tools,
        components=components,
        metadata=metadata_raw,
        primary_component=primary_component,
        supplier=doc_supplier,
        lifecycles=lifecycles,
        signature=signature,
        bom_links=bom_links,
        vulnerabilities=vulnerabilities,
        dependency_graph=graph.to_dict(),
        compositions=data.get("compositions") or [],
        schema_valid=schema_valid,
        data_license=cdx_data_license,
    )
    return doc


def _parse_cyclonedx_component(raw: dict, spec_version: str = "") -> Optional[Component]:
    if not isinstance(raw, dict):
        return None
    name = raw.get("name") or ""
    if not name:
        return None

    version = raw.get("version") or None
    purl = raw.get("purl") or None
    cpe = raw.get("cpe") or None
    component_type = raw.get("type") or None
    description = raw.get("description") or None
    bom_ref = raw.get("bom-ref") or None
    copyright_text = raw.get("copyright") or None

    # Supplier
    supplier = None
    supplier_raw = raw.get("supplier") or raw.get("publisher")
    if isinstance(supplier_raw, dict):
        supplier = supplier_raw.get("name") or None
    elif isinstance(supplier_raw, str):
        supplier = supplier_raw or None

    # Manufacturer (CDX — fallback when supplier absent)
    manufacturer = None
    mfr_raw = raw.get("manufacturer")
    if isinstance(mfr_raw, dict):
        manufacturer = mfr_raw.get("name") or None
    elif isinstance(mfr_raw, str):
        manufacturer = mfr_raw or None

    # Licenses (concluded) + declared (CDX 1.6 acknowledgement field)
    licenses: list[str] = []
    declared_licenses: list[str] = []
    license_has_url_or_text = False
    for lic in raw.get("licenses") or []:
        if isinstance(lic, dict):
            inner = lic.get("license") or lic
            lic_id = (
                inner.get("id") or inner.get("name")
                or lic.get("expression") or ""
            )
            if not lic_id:
                lic_id = lic.get("expression") or ""
            ack = lic.get("acknowledgement") or ""
            if lic_id:
                licenses.append(lic_id)
                if ack.lower() == "declared":
                    declared_licenses.append(lic_id)
            # FSCT tier 15: URL or embedded text present
            if inner.get("url"):
                license_has_url_or_text = True
            text_field = inner.get("text")
            if text_field:
                text_content = (
                    text_field.get("content") if isinstance(text_field, dict)
                    else str(text_field)
                )
                if text_content and text_content.strip():
                    license_has_url_or_text = True
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

    # External references
    ext_refs = []
    for ref in raw.get("externalReferences") or []:
        if isinstance(ref, dict):
            ext_refs.append(ref)

    # Properties
    props: dict = {}
    for prop in raw.get("properties") or []:
        if isinstance(prop, dict):
            k = prop.get("name") or ""
            v = prop.get("value") or ""
            if k:
                props[k] = v

    # Download location
    download_location = None
    for ref in ext_refs:
        rtype = (ref.get("type") or "").lower()
        if rtype in ("distribution", "download"):
            download_location = ref.get("url") or None
            break

    return Component(
        name=name,
        version=version,
        purl=purl,
        cpe=cpe,
        supplier=supplier,
        manufacturer=manufacturer,
        licenses=licenses,
        declared_licenses=declared_licenses,
        hashes=hashes,
        description=description,
        component_type=component_type,
        external_references=ext_refs,
        properties=props,
        copyright=copyright_text,
        download_location=download_location,
        bom_ref=bom_ref,
        license_has_url_or_text=license_has_url_or_text,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# CycloneDX XML
# ---------------------------------------------------------------------------

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
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ParseError(f"Invalid XML: {exc}") from exc

    ns = ""
    tag = root.tag
    if tag.startswith("{"):
        ns = tag[1:tag.index("}")]
    ns_prefix = f"{{{ns}}}" if ns else ""

    spec_version = root.get("version")
    if spec_version is None and ns:
        parts = ns.rstrip("/").split("/")
        if parts:
            spec_version = parts[-1]

    metadata_el = root.find(f"{ns_prefix}metadata")
    created = None
    authors: list[str] = []
    tools: list = []
    document_name = None
    primary_component = None
    primary_ref = None
    doc_supplier = None
    lifecycles: list[str] = []

    if metadata_el is not None:
        ts_el = metadata_el.find(f"{ns_prefix}timestamp")
        if ts_el is not None:
            created = (ts_el.text or "").strip() or None

        for author_el in metadata_el.findall(f".//{ns_prefix}author"):
            name_el = author_el.find(f"{ns_prefix}name")
            name = (name_el.text or "").strip() if name_el is not None else ""
            if not name:
                name = (author_el.text or "").strip()
            if name:
                authors.append(name)

        for tool_el in metadata_el.findall(f".//{ns_prefix}tool"):
            tool_name = _get_text(metadata_el, "name", ns_prefix) or ""
            tool_ver = _get_text(tool_el, "version", ns_prefix) or ""
            n_el = tool_el.find(f"{ns_prefix}name")
            if n_el is not None:
                tool_name = (n_el.text or "").strip()
            tools.append({"name": tool_name, "version": tool_ver})

        meta_comp = metadata_el.find(f"{ns_prefix}component")
        if meta_comp is not None:
            name_el = meta_comp.find(f"{ns_prefix}name")
            if name_el is not None:
                primary_component = (name_el.text or "").strip() or None
                document_name = primary_component
            primary_ref = meta_comp.get("bom-ref")

        supplier_el = metadata_el.find(f".//{ns_prefix}supplier")
        if supplier_el is not None:
            name_el = supplier_el.find(f"{ns_prefix}name")
            if name_el is not None:
                doc_supplier = (name_el.text or "").strip() or None

    document_namespace = root.get("serialNumber")

    # Parse components
    components: list[Component] = []
    components_el = root.find(f"{ns_prefix}components")
    if components_el is not None:
        for comp_el in components_el.findall(f"{ns_prefix}component"):
            comp = _parse_cyclonedx_xml_component(comp_el, ns_prefix)
            if comp is not None:
                components.append(comp)

    # Dependency graph
    edges: list[tuple[str, str, str]] = []
    deps_el = root.find(f"{ns_prefix}dependencies")
    if deps_el is not None:
        for dep_el in deps_el.findall(f"{ns_prefix}dependency"):
            from_ref = dep_el.get("ref") or ""
            for child_el in dep_el.findall(f"{ns_prefix}dependency"):
                to_ref = child_el.get("ref") or ""
                if to_ref:
                    edges.append((from_ref, to_ref, "DEPENDS_ON"))

    node_refs = [c.bom_ref for c in components if c.bom_ref]
    graph = _build_dependency_graph(edges, node_refs, primary_ref, False)

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
        primary_component=primary_component,
        supplier=doc_supplier,
        lifecycles=lifecycles,
        dependency_graph=graph.to_dict(),
    )


def _get_text(el: Optional[ET.Element], tag: str, ns_prefix: str) -> Optional[str]:
    child = el.find(f"{ns_prefix}{tag}") if el is not None else None
    if child is None:
        return None
    return (child.text or "").strip() or None


def _parse_cyclonedx_xml_component(el: ET.Element, ns_prefix: str) -> Optional[Component]:
    name = _get_text(el, "name", ns_prefix) or ""
    if not name:
        return None

    version = _get_text(el, "version", ns_prefix)
    purl = _get_text(el, "purl", ns_prefix)
    cpe = _get_text(el, "cpe", ns_prefix)
    description = _get_text(el, "description", ns_prefix)
    component_type = el.get("type")
    bom_ref = el.get("bom-ref")

    supplier = None
    supplier_el = el.find(f"{ns_prefix}supplier")
    if supplier_el is not None:
        supplier = _get_text(supplier_el, "name", ns_prefix)

    manufacturer = None
    mfr_el = el.find(f"{ns_prefix}manufacturer")
    if mfr_el is not None:
        manufacturer = _get_text(mfr_el, "name", ns_prefix)

    licenses: list[str] = []
    declared_licenses: list[str] = []
    xml_license_has_url_or_text = False
    licenses_el = el.find(f"{ns_prefix}licenses")
    if licenses_el is not None:
        for lic_el in licenses_el:
            lic_id_el = lic_el.find(f"{ns_prefix}id")
            lic_name_el = lic_el.find(f"{ns_prefix}name")
            expr_el = lic_el.find(f"{ns_prefix}expression")
            url_el = lic_el.find(f"{ns_prefix}url")
            text_el = lic_el.find(f"{ns_prefix}text")
            ack = lic_el.get("acknowledgement") or ""
            lic_str = (
                (lic_id_el.text if lic_id_el is not None else None)
                or (lic_name_el.text if lic_name_el is not None else None)
                or (expr_el.text if expr_el is not None else None)
                or ""
            )
            if lic_str:
                lic_str = lic_str.strip()
                licenses.append(lic_str)
                if ack.lower() == "declared":
                    declared_licenses.append(lic_str)
            if url_el is not None and (url_el.text or "").strip():
                xml_license_has_url_or_text = True
            if text_el is not None and (text_el.text or "").strip():
                xml_license_has_url_or_text = True

    hashes: dict[str, str] = {}
    hashes_el = el.find(f"{ns_prefix}hashes")
    if hashes_el is not None:
        for h_el in hashes_el.findall(f"{ns_prefix}hash"):
            alg = h_el.get("alg") or ""
            val = (h_el.text or "").strip()
            if alg and val:
                hashes[alg.upper()] = val

    ext_refs = []
    ext_refs_el = el.find(f"{ns_prefix}externalReferences")
    if ext_refs_el is not None:
        for ref_el in ext_refs_el.findall(f"{ns_prefix}reference"):
            url_el = ref_el.find(f"{ns_prefix}url")
            ext_refs.append({
                "type": ref_el.get("type") or "",
                "url": (url_el.text or "").strip() if url_el is not None else "",
            })

    props: dict = {}
    props_el = el.find(f"{ns_prefix}properties")
    if props_el is not None:
        for prop_el in props_el.findall(f"{ns_prefix}property"):
            k = prop_el.get("name") or ""
            v = (prop_el.text or "").strip()
            if k:
                props[k] = v

    return Component(
        name=name,
        version=version,
        purl=purl,
        cpe=cpe,
        supplier=supplier,
        manufacturer=manufacturer,
        licenses=licenses,
        declared_licenses=declared_licenses,
        hashes=hashes,
        description=description,
        component_type=component_type,
        external_references=ext_refs,
        properties=props,
        bom_ref=bom_ref,
        license_has_url_or_text=xml_license_has_url_or_text,
        raw={},
    )


# ---------------------------------------------------------------------------
# SPDX JSON
# ---------------------------------------------------------------------------

def _parse_spdx_json(data: dict) -> SBOMDocument:
    if not isinstance(data, dict):
        raise ParseError("SPDX JSON must be a JSON object")

    spec_version = data.get("spdxVersion") or None
    document_name = data.get("name") or None
    document_namespace = data.get("documentNamespace") or None
    data_license = data.get("dataLicense") or None
    doc_spdx_id_json = data.get("SPDXID") or None
    creation_info = data.get("creationInfo") or {}
    created = creation_info.get("created") if isinstance(creation_info, dict) else None
    doc_comment = (creation_info.get("comment") if isinstance(creation_info, dict) else None) or None

    authors: list[str] = []
    tools: list = []
    for creator in (creation_info.get("creators") or [] if isinstance(creation_info, dict) else []):
        creator_str = str(creator)
        if creator_str.startswith("Tool:"):
            tool_name = creator_str[5:].strip()
            # Try to split name/version on space
            parts = tool_name.rsplit("-", 1)
            if len(parts) == 2 and parts[1].replace(".", "").isdigit():
                tools.append({"name": parts[0], "version": parts[1]})
            else:
                tools.append({"name": tool_name})
        elif creator_str.startswith("Organization:"):
            authors.append(creator_str)
        elif creator_str.startswith("Person:"):
            authors.append(creator_str)
        else:
            authors.append(creator_str)

    # Build component map for dependency resolution (spdxId → Component)
    spdx_id_map: dict[str, Component] = {}
    components: list[Component] = []
    for pkg in data.get("packages") or []:
        comp = _parse_spdx_package(pkg)
        if comp is not None:
            components.append(comp)
            spdx_id = pkg.get("SPDXID") or ""
            if spdx_id:
                spdx_id_map[spdx_id] = comp

    # Relationships
    edges: list[tuple[str, str, str]] = []
    primary_ref = None
    doc_spdx_id = data.get("SPDXID") or "SPDXRef-DOCUMENT"

    for rel in data.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        rel_type = rel.get("relationshipType") or ""
        from_el = rel.get("spdxElementId") or ""
        to_el = rel.get("relatedSpdxElement") or ""

        if rel_type == "DESCRIBES" and from_el == doc_spdx_id:
            primary_ref = to_el
        if rel_type in ("DEPENDS_ON", "CONTAINS", "DYNAMIC_LINK", "STATIC_LINK",
                        "RUNTIME_DEPENDENCY_OF", "DEV_DEPENDENCY_OF"):
            edges.append((from_el, to_el, rel_type))

    primary_component = None
    if primary_ref and primary_ref in spdx_id_map:
        primary_component = spdx_id_map[primary_ref].name

    node_refs = list(spdx_id_map.keys())
    graph = _build_dependency_graph(edges, node_refs, primary_ref, False)

    # JSON schema validation against embedded official SPDX schemas
    schema_valid = validate_schema(data, "spdx", spec_version or "")

    return SBOMDocument(
        format="spdx",
        spec_version=spec_version,
        document_name=document_name,
        document_namespace=document_namespace,
        created=created,
        authors=authors,
        tools=tools,
        components=components,
        metadata={"creationInfo": creation_info},
        primary_component=primary_component,
        data_license=data_license,
        dependency_graph=graph.to_dict(),
        schema_valid=schema_valid,
        spdx_id=doc_spdx_id_json,
        document_comment=doc_comment,
    )


def _parse_spdx_package(pkg: dict) -> Optional[Component]:
    if not isinstance(pkg, dict):
        return None

    name = pkg.get("name") or ""
    if not name:
        return None

    def _spdx_val(v: Optional[str]) -> Optional[str]:
        if v in (None, "NOASSERTION", "NONE", ""):
            return None
        return v

    version = _spdx_val(pkg.get("versionInfo"))
    purl = None
    cpe = None
    supplier_raw = _spdx_val(pkg.get("supplier"))
    supplier = None
    if supplier_raw and ":" in supplier_raw:
        supplier = supplier_raw.split(":", 1)[1].strip() or None
    else:
        supplier = supplier_raw

    # PackageOriginator — NTIA/BSI fallback when supplier is absent
    originator_raw = _spdx_val(pkg.get("originator"))
    manufacturer = None
    if originator_raw and ":" in originator_raw:
        manufacturer = originator_raw.split(":", 1)[1].strip() or None
    else:
        manufacturer = originator_raw

    description = _spdx_val(pkg.get("description") or pkg.get("summary"))
    copyright_text = _spdx_val(pkg.get("copyrightText"))
    download_location = _spdx_val(pkg.get("downloadLocation"))
    pkg_filename = _spdx_val(pkg.get("packageFileName"))
    bom_ref = pkg.get("SPDXID") or None
    files_analyzed_raw = pkg.get("filesAnalyzed")
    files_analyzed = bool(files_analyzed_raw) if files_analyzed_raw is not None else None

    ext_refs = []
    for ref in pkg.get("externalRefs") or []:
        if not isinstance(ref, dict):
            continue
        ref_type = ref.get("referenceType") or ""
        ref_loc = ref.get("referenceLocator") or ""
        if ref_type.lower() == "purl" and ref_loc:
            purl = ref_loc
        elif ref_type.lower() in ("cpe22type", "cpe23type", "cpe") and ref_loc:
            cpe = ref_loc
        ext_refs.append({
            "type": ref_type,
            "url": ref_loc,
            "referenceType": ref_type,
            "referenceLocator": ref_loc,
        })

    # Licenses: concluded + declared separately
    licenses: list[str] = []
    declared_licenses: list[str] = []
    concluded = _spdx_val(pkg.get("licenseConcluded"))
    declared = _spdx_val(pkg.get("licenseDeclared"))
    if concluded:
        licenses.append(concluded)
    if declared:
        declared_licenses.append(declared)
        if declared != concluded:
            licenses.append(declared)

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
        manufacturer=manufacturer,
        licenses=licenses,
        declared_licenses=declared_licenses,
        hashes=hashes,
        description=description,
        component_type=None,
        external_references=ext_refs,
        copyright=copyright_text,
        download_location=download_location,
        filename=pkg_filename,
        bom_ref=bom_ref,
        files_analyzed=files_analyzed,
        raw=pkg,
    )


# ---------------------------------------------------------------------------
# SPDX Tag-Value
# ---------------------------------------------------------------------------

def _parse_spdx_tagvalue(content: str) -> SBOMDocument:
    lines = content.splitlines()
    spec_version: Optional[str] = None
    document_name: Optional[str] = None
    document_namespace: Optional[str] = None
    data_license: Optional[str] = None
    created: Optional[str] = None
    document_comment: Optional[str] = None
    creators: list[str] = []
    authors: list[str] = []
    tools: list = []

    current_pkg: Optional[dict] = None
    packages: list[dict] = []
    relationships: list[str] = []
    doc_spdx_id = "SPDXRef-DOCUMENT"

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        tag, _, value = line.partition(":")
        tag = tag.strip()
        value = value.strip()

        if tag == "SPDXVersion":
            spec_version = value
        elif tag == "DataLicense":
            data_license = value
        elif tag == "DocumentName":
            document_name = value
        elif tag == "DocumentNamespace":
            document_namespace = value
        elif tag == "Created":
            created = value
        elif tag == "DocumentComment":
            document_comment = value
        elif tag == "Creator":
            creators.append(value)
        elif tag == "SPDXID" and current_pkg is None:
            doc_spdx_id = value
        elif tag == "Relationship":
            relationships.append(value)
        elif tag == "PackageName":
            if current_pkg is not None:
                packages.append(current_pkg)
            current_pkg = {"PackageName": value}
        elif current_pkg is not None:
            # Accumulate multi-value tags (ExternalRef, PackageChecksum)
            existing = current_pkg.get(tag)
            if existing is None:
                current_pkg[tag] = value
            elif isinstance(existing, list):
                existing.append(value)
            else:
                current_pkg[tag] = [existing, value]

    if current_pkg is not None:
        packages.append(current_pkg)

    for creator in creators:
        if creator.startswith("Tool:"):
            tn = creator[5:].strip()
            tools.append({"name": tn})
        elif creator.startswith("Organization:"):
            authors.append(creator)
        elif creator.startswith("Person:"):
            authors.append(creator)
        else:
            authors.append(creator)

    # Build component map
    spdx_id_map: dict[str, Component] = {}
    components: list[Component] = []
    for pkg in packages:
        comp = _parse_spdx_tv_package(pkg)
        if comp is not None:
            components.append(comp)
            spdx_id = pkg.get("SPDXID") or ""
            if spdx_id:
                spdx_id_map[spdx_id] = comp

    # Parse relationships
    edges: list[tuple[str, str, str]] = []
    primary_ref = None
    for rel_str in relationships:
        parts = rel_str.split()
        if len(parts) >= 3:
            from_id, rel_type, to_id = parts[0], parts[1], parts[2]
            if rel_type == "DESCRIBES" and from_id == doc_spdx_id:
                primary_ref = to_id
            if rel_type in ("DEPENDS_ON", "CONTAINS", "DYNAMIC_LINK", "STATIC_LINK"):
                edges.append((from_id, to_id, rel_type))

    primary_component = None
    if primary_ref and primary_ref in spdx_id_map:
        primary_component = spdx_id_map[primary_ref].name

    node_refs = list(spdx_id_map.keys())
    graph = _build_dependency_graph(edges, node_refs, primary_ref, False)

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
        primary_component=primary_component,
        data_license=data_license,
        dependency_graph=graph.to_dict(),
        file_format="tv",
        spdx_id=doc_spdx_id or None,
        document_comment=document_comment,
    )


def _parse_spdx_tv_package(pkg: dict) -> Optional[Component]:
    name = pkg.get("PackageName") or ""
    if not name:
        return None

    def _tv_val(v) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        if s in ("NOASSERTION", "NONE", ""):
            return None
        return s

    version = _tv_val(pkg.get("PackageVersion"))
    purl = None
    cpe = None
    supplier_raw = _tv_val(pkg.get("PackageSupplier"))
    supplier = None
    if supplier_raw and ":" in supplier_raw:
        supplier = supplier_raw.split(":", 1)[1].strip() or None
    else:
        supplier = supplier_raw

    originator_raw = _tv_val(pkg.get("PackageOriginator"))
    manufacturer = None
    if originator_raw and ":" in originator_raw:
        manufacturer = originator_raw.split(":", 1)[1].strip() or None
    else:
        manufacturer = originator_raw

    copyright_text = _tv_val(pkg.get("PackageCopyrightText"))
    download_location = _tv_val(pkg.get("PackageDownloadLocation"))
    pkg_filename = _tv_val(pkg.get("PackageFileName") or pkg.get("FileName"))
    bom_ref = _tv_val(pkg.get("SPDXID"))
    fa_raw = _tv_val(pkg.get("FilesAnalyzed"))
    files_analyzed = (fa_raw.lower() == "true") if fa_raw is not None else None

    # ExternalRef: can be a single string or list
    ext_refs = []
    ext_ref_raw = pkg.get("ExternalRef")
    if ext_ref_raw is None:
        ext_ref_raw = []
    elif isinstance(ext_ref_raw, str):
        ext_ref_raw = [ext_ref_raw]

    for ext_ref in ext_ref_raw:
        parts = str(ext_ref).split()
        if len(parts) >= 3:
            ref_cat, ref_type, ref_loc = parts[0], parts[1], parts[2]
            if ref_type.lower() == "purl":
                purl = ref_loc
            elif ref_type.lower() in ("cpe22type", "cpe23type"):
                cpe = ref_loc
            ext_refs.append({"type": ref_type, "url": ref_loc})

    # Licenses
    licenses: list[str] = []
    declared_licenses: list[str] = []
    concluded = _tv_val(pkg.get("PackageLicenseConcluded"))
    declared = _tv_val(pkg.get("PackageLicenseDeclared"))
    if concluded:
        licenses.append(concluded)
    if declared:
        declared_licenses.append(declared)
        if declared != concluded:
            licenses.append(declared)

    # Checksums
    hashes: dict[str, str] = {}
    cs_raw = pkg.get("PackageChecksum")
    if cs_raw is None:
        cs_raw = []
    elif isinstance(cs_raw, str):
        cs_raw = [cs_raw]
    for checksum in cs_raw:
        checksum = str(checksum)
        if ":" in checksum:
            alg, _, val = checksum.partition(":")
            hashes[alg.strip().upper()] = val.strip()

    return Component(
        name=name,
        version=version,
        purl=purl,
        cpe=cpe,
        supplier=supplier,
        manufacturer=manufacturer,
        licenses=licenses,
        declared_licenses=declared_licenses,
        hashes=hashes,
        description=None,
        component_type=None,
        external_references=ext_refs,
        copyright=copyright_text,
        download_location=download_location,
        filename=pkg_filename,
        bom_ref=bom_ref,
        files_analyzed=files_analyzed,
        raw=pkg,
    )
