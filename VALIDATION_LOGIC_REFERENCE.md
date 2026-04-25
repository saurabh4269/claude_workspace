# Verity SBOM Validator — Validation Logic Reference

This document describes every scoring rule, compliance check, and risk heuristic implemented in Verity. It is intended for subject-matter experts (SMEs) who want to audit the logic, flag errors, or suggest improvements.

---

## Table of Contents

1. [Supported Formats](#1-supported-formats)
2. [Quality Score — Overview](#2-quality-score--overview)
3. [Quality Score — Category Breakdown](#3-quality-score--category-breakdown)
   - 3.1 Structural Validity
   - 3.2 Identification
   - 3.3 Provenance
   - 3.4 Integrity
   - 3.5 License Compliance
   - 3.6 Vulnerability & Traceability
   - 3.7 Completeness
   - 3.8 Component Security Health (optional)
4. [Scored Compliance Profiles](#4-scored-compliance-profiles)
5. [Compliance Standards](#5-compliance-standards)
   - 5.1 NTIA Minimum Elements
   - 5.2 BSI TR-03183-2
   - 5.3 OpenChain Telco (OCT)
   - 5.4 FSCT v3
6. [Risk Analysis](#6-risk-analysis)
7. [Vulnerability Lookup](#7-vulnerability-lookup)
8. [EOL/EOS Detection](#8-eoleos-detection)
9. [License Classification](#9-license-classification)
10. [Open Questions & Areas for SME Review](#10-open-questions--areas-for-sme-review)

---

## 1. Supported Formats

| Format | Detection method | Versions recognized |
|--------|-----------------|---------------------|
| CycloneDX JSON | `bomFormat: CycloneDX` key | 1.4, 1.5, 1.6 |
| CycloneDX XML | `<bom xmlns=...cyclonedx...>` root | 1.4, 1.5, 1.6 |
| SPDX JSON | `spdxVersion` key | **2.1**, 2.2, 2.2.1, 2.2.2, 2.3, 2.3.1, 3.0, 3.0.0, 3.0.1 |
| SPDX Tag-Value | `SPDXVersion:` line | **2.1**, 2.2, 2.2.1, 2.2.2, 2.3, 2.3.1, 3.0, 3.0.0, 3.0.1 |
| SPDX YAML | `.yaml`/`.yml` extension + `spdxVersion` key | **2.1**, 2.2, 2.2.1, 2.2.2, 2.3, 2.3.1, 3.0, 3.0.0, 3.0.1 |

SPDX YAML is parsed by loading the YAML into a dict and passing it through the same path as SPDX JSON. The internal `file_format` field is set to `"yaml"` to distinguish it for display and for schema-validation applicability rules.

SPDX version strings carry a `SPDX-` prefix in the document (e.g. `"SPDX-2.3"`). The parser strips this prefix internally before comparisons; the original string is preserved in `doc.spec_version` for display.

---

## 2. Quality Score — Overview

The quality score is a **weighted mean across seven categories**, each of which is itself a weighted mean of its applicable features.

```
overall_score = Σ(category_score × category_weight) / Σ(category_weight)
```

Category weights (fixed, base total: **82**):

| # | Category | Weight |
|---|----------|--------|
| 1 | Structural Validity | 8 |
| 2 | Identification | 10 |
| 3 | Provenance | 12 |
| 4 | Integrity | 15 |
| 5 | License Compliance | 15 |
| 6 | Vulnerability & Traceability | 10 |
| 7 | Completeness | 12 |
| — | **Total** | **82** |

An optional **Component Security Health** category (weight 8) is appended when vulnerability and EOL results are supplied. It is excluded from the base denominator of 82; the denominator adjusts dynamically to include it when present.

Each category score is 0.0–10.0. The overall score is 0.0–10.0.

**Letter grades:**

| Score | Grade |
|-------|-------|
| ≥ 9.0 | A |
| ≥ 8.0 | B |
| ≥ 7.0 | C |
| ≥ 5.0 | D |
| < 5.0 | F |

**Feature applicability:** A feature with `applicable=False` is excluded from the category denominator. This handles format-specific features (e.g. CDX-only fields) and cases where a check is meaningless for an SBOM with no components.

**Per-component ratio scoring:** When a check applies to every component (e.g. "has a version"), the feature score is `min(9.9, 10 × have / total)`. The cap at 9.9 ensures that only a perfect score (`have == total`) reaches 10.0.

**Weighted score per category:** `weighted_score = round(category_score × category_weight / total_weight, 4)`. The denominator is computed from the actual weights present in the result, so the Component Security Health category is correctly included when it appears.

---

## 3. Quality Score — Category Breakdown

### 3.1 Structural Validity (weight 8)

Checks whether the SBOM file is well-formed and uses a recognized spec version.

| Feature key | Weight | What is checked | Pass condition |
|-------------|--------|-----------------|----------------|
| `spec_detected` | 0.30 | Format auto-detected as CycloneDX or SPDX | True |
| `spec_version_supported` | 0.30 | Spec version is in the known-good set | CDX: 1.4/1.5/1.6; SPDX: 2.2/2.2.1/2.2.2/2.3/3.0/3.0.0/3.0.1 |
| `file_format_valid` | 0.20 | Detected format matches declared spec | True |
| `schema_valid` | 0.20 | Full JSON Schema validation against embedded official schemas (CycloneDX 1.4/1.5/1.6; SPDX 2.2/2.3) | True — **N/A** for XML and tag-value |

**Notes for SME review:**
- JSON Schema validation uses the `jsonschema` library against the official CycloneDX and SPDX published schemas embedded in `app/core/validation/schemas/`. For versions without an embedded schema (e.g. SPDX 2.1, CDX 1.3), validation is skipped and the field returns `True` (not invalid).
- SPDX 3.x versions (3.0, 3.0.0, 3.0.1) are fully recognized for spec version scoring.

---

### 3.2 Identification (weight 10)

Checks whether each component can be uniquely identified. PURL and CPE identifiers belong here for **presence**; their **syntax validity** is checked in Category 6.

| Feature key | Weight | What is checked |
|-------------|--------|-----------------|
| `comp_with_name` | 0.40 | Non-empty `name` field |
| `comp_with_version` | 0.35 | Non-empty `version`/`versionInfo` field |
| `comp_with_local_id` | 0.25 | `bom-ref` (CDX) or `SPDXID` is non-empty **and unique** within the document |

**Local unique ID uniqueness:** Duplicated bom-refs are not counted as having a unique ID, because duplicate identifiers break dependency graph resolution.

**Notes for SME review:**
- PURL and CPE were removed from this category to eliminate double-counting. They are now the sole focus of Category 6 (Vulnerability & Traceability), which covers both presence and syntax.

---

### 3.3 Provenance (weight 12)

Checks document-level attribution — who created the SBOM, when, and with what tool.

| Feature key | Weight | What is checked | Applicable |
|-------------|--------|-----------------|------------|
| `sbom_creation_timestamp` | 0.20 | Non-empty `created`/`creationInfo.created` field | Always |
| `sbom_authors` | 0.20 | At least one non-empty author/creator string | Always |
| `sbom_tool_version` | 0.20 | Tool declared with both name and version — **tiered**: 0=no tools, 5=name-only, 10=name+version | Always |
| `sbom_namespace` | 0.20 | Non-empty `documentNamespace` (SPDX) or `serialNumber` (CDX) | Always |
| `sbom_supplier` | 0.15 | `metadata.supplier` present (CDX) | CDX only |
| `sbom_lifecycle` | 0.05 | `metadata.lifecycles` present (CDX 1.5+) | CDX only |

**Tool tier scoring:** `_tiered(0)=0`, `_tiered(1)=5`, `_tiered(2)=10`. The tool is considered fully scored when at least one tool has both a `name` (or `vendor`) and a `version`.

---

### 3.4 Integrity (weight 15)

Checks whether component hashes are present and use strong algorithms, and whether the document is signed.

| Feature key | Weight | What is checked |
|-------------|--------|-----------------|
| `comp_with_checksums` | 0.60 | Any hash algorithm present per component |
| `comp_with_strong_checksum` | 0.30 | Hash uses a strong algorithm (SHA-256+) — see list below |
| `sbom_signature` | 0.10 | Document signature block — **tiered**: 0=none, 5=signature present but no key material, 10=signature with public key or certificate |

**Strong hash algorithms** (based on NIST SP 800-107 / SP 800-208):

SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256/384/512, BLAKE3, STREEBOG-256, STREEBOG-512.

**SHA-256 normalisation:** Algorithm name strings are normalised before comparison: uppercased, then `-`, `_`, and spaces stripped. `sha-256`, `SHA256`, `sha_256` all match. Crucially, `BLAKE3-256` does **not** match SHA3-256 — BLAKE3 is a separate algorithm family.

**Weak algorithms** (penalised, not counted as strong): MD5, MD2, MD4, MD6, SHA-1, ADLER-32.

**Notes for SME review:**
- The `comp_with_checksums` weight (0.60) is higher than `comp_with_strong_checksum` (0.30) because even a weak checksum is better than none for integrity verification.
- Document-level signature checking only inspects the structural presence of `publicKey`, `certificate`, or `certificates` fields. Actual signature verification is not performed.
- STREEBOG (GOST R 34.11-2012) is included as a strong algorithm to support SBOM tooling from Russian-standard environments.

---

### 3.5 License Compliance (weight 15)

Checks whether licenses are declared, use valid SPDX identifiers, and are not deprecated or restrictive.

| Feature key | Weight | What is checked |
|-------------|--------|-----------------|
| `comp_has_license` | 0.20 | Component has at least one non-absent license (not NOASSERTION/NONE) |
| `comp_has_valid_spdx_license` | 0.20 | All licenses are valid SPDX identifiers — **N/A** if no component has a license |
| `comp_has_declared_license` | 0.15 | Separate upstream-declared license field populated (CDX `acknowledgement=declared`; SPDX `PackageLicenseDeclared`) |
| `comp_no_deprecated_license` | 0.15 | No deprecated SPDX identifiers used (e.g. `GPL-2.0+`) |
| `comp_no_restrictive_license` | 0.20 | No strong copyleft licenses (GPL, AGPL, etc.) — see [Section 9](#9-license-classification) |
| `sbom_has_data_license` | 0.10 | SBOM's own data license declared (`dataLicense` in SPDX; `metadata.licenses` in CDX) and not NOASSERTION/NONE |

**NOASSERTION/NONE handling:** These SPDX sentinel values are treated as absent.

**Notes for SME review:**
- `comp_no_restrictive_license` awards 10 points when a component has no restrictive licenses. This conflates legal risk with SBOM quality — a component legitimately using GPL should not penalise quality. SMEs may want this moved to Risk Analysis.
- `comp_has_declared_license` for CDX requires the `acknowledgement=declared` attribute (CDX 1.6+ only). Non-CDX-1.6 CDX SBOMs cannot pass this check.
- SPDX license list version in use: **3.23** (curated subset covering >99% of real-world SBOMs).

---

### 3.6 Vulnerability & Traceability (weight 10)

Checks whether components carry valid machine-readable identifiers for vulnerability lookup (PURL, CPE). Both presence and syntax are assessed here; this is the single authoritative location for these identifiers.

| Feature key | Weight | What is checked |
|-------------|--------|-----------------|
| `comp_with_valid_purl` | 0.50 | PURL present **and** matches `pkg:<type>/<name>[@version]` — **always applicable** |
| `comp_with_valid_cpe` | 0.50 | CPE present **and** matches CPE 2.3 or CPE 2.2 pattern — **always applicable** |

Both features are always applicable: absence of PURLs or CPEs is a real quality gap (NVD cannot match without a CPE; OSV is less precise without a PURL), so they must contribute to the score rather than being excluded from the denominator.

**PURL pattern:** `^pkg:[a-zA-Z][a-zA-Z0-9.+\-]*/[^@\s]+` — validates type and namespace/name. Does not validate type-specific rules.

**CPE 2.3 pattern:** `^cpe:2\.3:[aho\*\-](:[^:]*){10}$` — requires exactly 13 colon-separated components. CPE 2.2 pattern: `^cpe:/`.

**Notes for SME review:**
- PURL validation does not verify that the package type is a registered type. `pkg:foobar/xyz` passes syntax validation.
- CPE 2.2 matching (`^cpe:/`) is permissive.
- `comp_with_any_vuln_id` was removed. The two features above cover the same ground with more granularity and avoid double-counting.

---

### 3.7 Completeness (weight 12)

Checks whether the SBOM describes its dependency graph and provides full supplier/source context per component.

| Feature key | Weight | What is checked | Applicable |
|-------------|--------|-----------------|------------|
| `primary_component` | 0.20 | The top-level component being described is identified | Always |
| `comp_with_dependencies` | 0.25 | How many components appear as a source node in the graph | CDX always; SPDX only when at least one `DEPENDS_ON` relationship exists |
| `sbom_completeness_declared` | 0.15 | `compositions` section present (CDX) declaring completeness | CDX only |
| `comp_with_supplier` | 0.15 | Non-empty supplier per component | Always |
| `comp_with_source_url` | 0.15 | VCS or distribution external reference per component | Always |
| `comp_with_purpose` | 0.10 | Non-empty component type/purpose field | Always |

`sbom_dependency_graph` (formerly a separate 0.15-weight feature checking "at least one edge exists") was removed. Its intent is now captured by `comp_with_dependencies` at a higher weight (0.25), which measures how many components are wired into the graph — a stricter and more informative signal.

**`comp_with_dependencies` N/A rule for SPDX:** SPDX uses `DESCRIBES` and `CONTAINS` relationships to identify the document structure; only `DEPENDS_ON` relationships constitute dependency edges. If no `DEPENDS_ON` edges exist in an SPDX document, this feature is marked `applicable=False` rather than scoring 0, because an SPDX document without `DEPENDS_ON` may still correctly encode a complete component list — it simply did not declare transitive dependencies.

**Dependency graph edges:** Resolved from CDX `dependencies[].dependsOn` or SPDX `relationships` (type `DEPENDS_ON`).

---

### 3.8 Component Security Health (optional, weight 8)

This category is appended when vulnerability results (`vuln_results`) and/or EOL results (`eol_results`) are supplied to the scorer. It is excluded from the base denominator of 82.

| Feature key | Weight | What is checked |
|-------------|--------|-----------------|
| `sec_no_vulnerable_components` | 0.35 | Fraction of components with zero CVEs |
| `sec_no_critical_cvss` | 0.25 | Fraction of components with no CVSS ≥ 9.0 CVE |
| `sec_vuln_coverage` | 0.20 | At least one component was checked for vulnerabilities (coverage signal) |
| `sec_eol_components` | 0.05 | Fraction of components not flagged as end-of-life |
| `sec_malicious_components` | 0.05 | Fraction of components with no malicious OSV advisories |
| `sec_license_risk` | 0.10 | Fraction of components without CRITICAL or HIGH copyleft licenses |

**Malicious detection:** A component is flagged as malicious if any OSV advisory ID has a `MAL-` prefix, or if the advisory includes `"is_malicious": true`.

**EOL detection:** Uses endoflife.date API results (see [Section 8](#8-eoleos-detection)). `None` results (product unknown) are not counted against the score.

---

## 4. Scored Compliance Profiles

In addition to the pass/fail compliance checkers in Section 5, Verity can score an SBOM continuously against a specific compliance standard. A profile maps a subset of quality score feature keys to profile-specific weights, producing a 0–10 score and letter grade that reflects how well the SBOM performs on what that standard prioritises.

**Formula:**
```
profile_score = Σ(feature_score × profile_weight) / Σ(profile_weight for applicable features)
```

Features absent from the QualityScore or marked `applicable=False` are excluded from the denominator — not treated as zero.

### Available profiles

| Profile key | Standard | Feature count |
|-------------|----------|---------------|
| `ntia` | NTIA Minimum Elements | 8 |
| `bsi` / `bsi-v2.1` | BSI TR-03183-2 v2.1 | 13 |
| `fsct` | FSCT v3 | 10 |
| `oct` | OpenChain Telco v1.1 | 10 |

### NTIA profile feature weights

NTIA element 4 ("Other Unique Identifiers") is split into PURL and CPE sub-features, each with equal weight (0.10), reflecting that both are valid NTIA unique identifiers covering different vulnerability databases.

| Feature | Weight | Rationale |
|---------|--------|-----------|
| `comp_with_supplier` | 0.15 | NTIA required element 1 |
| `comp_with_name` | 0.15 | NTIA required element 2 |
| `comp_with_version` | 0.15 | NTIA required element 3 |
| `comp_with_valid_purl` | 0.10 | NTIA element 4 — PURL half |
| `comp_with_valid_cpe` | 0.10 | NTIA element 4 — CPE half |
| `comp_with_dependencies` | 0.15 | NTIA element 5 — dependency relationships |
| `sbom_authors` | 0.10 | NTIA element 6 — author of SBOM data |
| `sbom_creation_timestamp` | 0.10 | NTIA element 7 — timestamp |

### BSI v2.1 profile feature weights

| Feature | Weight |
|---------|--------|
| `comp_with_strong_checksum` | 0.15 |
| `comp_with_dependencies` | 0.10 |
| `comp_has_license` | 0.10 |
| `sbom_creation_timestamp` | 0.08 |
| `comp_with_name` | 0.08 |
| `comp_with_version` | 0.08 |
| `sbom_namespace` | 0.07 |
| `comp_has_declared_license` | 0.07 |
| `comp_with_valid_purl` | 0.07 |
| `spec_version_supported` | 0.05 |
| `schema_valid` | 0.05 |
| `sbom_signature` | 0.05 |
| `primary_component` | 0.05 |

### FSCT v3 profile feature weights

| Feature | Weight | Rationale |
|---------|--------|-----------|
| `comp_with_name` | 0.12 | FSCT component name |
| `comp_with_version` | 0.12 | FSCT component version |
| `comp_with_valid_purl` | 0.12 | FSCT unique identifier (PURL is primary) |
| `comp_has_license` | 0.12 | FSCT license information |
| `comp_with_supplier` | 0.10 | FSCT supplier |
| `comp_with_checksums` | 0.10 | FSCT checksum |
| `sbom_authors` | 0.08 | FSCT SBOM author |
| `sbom_creation_timestamp` | 0.08 | FSCT timestamp |
| `comp_with_dependencies` | 0.08 | FSCT relationship completeness |
| `primary_component` | 0.08 | FSCT primary component |

### OpenChain Telco v1.1 profile feature weights

| Feature | Weight |
|---------|--------|
| `comp_has_license` | 0.12 |
| `comp_with_valid_purl` | 0.12 |
| `comp_with_name` | 0.10 |
| `comp_with_version` | 0.10 |
| `comp_with_supplier` | 0.10 |
| `comp_with_checksums` | 0.10 |
| `sbom_creation_timestamp` | 0.10 |
| `sbom_namespace` | 0.10 |
| `sbom_authors` | 0.08 |
| `sbom_has_data_license` | 0.08 |

---

## 5. Compliance Standards

Compliance checks use a three-tier model:

| Tier | Keyword | Included in score | Description |
|------|---------|-------------------|-------------|
| REQUIRED | SHALL | Always | Failure is a non-compliance finding |
| ADDITIONAL | SHOULD | When applicable=True | Best-practice recommendation |
| OPTIONAL | MAY | Never | Advisory; shown for information only |

**Compliance score formula:**

```
compliance_score = min(mean(score) over all REQUIRED + applicable ADDITIONAL records, 10.0)
```

Each record has a score of 0, 5, or 10 (or 12/15 for FSCT tiered checks). The raw score before capping is also available as `raw_score` in the FSCT result.

---

### 5.1 NTIA Minimum Elements

**Source:** "The Minimum Elements For a Software Bill of Materials (SBOM)" — US Department of Commerce / NTIA, July 2021. Public domain.

| Element | Tier | Check |
|---------|------|-------|
| Author of SBOM Data | SHALL | At least one author string or tool declared |
| Timestamp | SHALL | Non-empty creation timestamp |
| Dependency Relationships | SHALL | At least one dependency edge in the graph, **or** a completeness declaration (`is_complete=True` or a compositions section) |
| Component Name | SHALL | Every component has a non-empty name |
| Supplier Name | SHALL | Every component has a non-empty supplier or manufacturer/originator (fallback) |
| Version of Component | SHALL | Every component has a non-empty version |
| Other Unique Identifiers | SHALL | Every component has a PURL or CPE |
| SBOM Generation Tool | SHOULD | At least one tool declared with both name and version |
| Machine-readable Format | SHOULD | File format is JSON or XML (tag-value scores lower) |

**Dependency fallback:** The NTIA dependency check accepts a completeness declaration (CycloneDX `compositions[].aggregate == "complete"`, or the parser-set `is_complete` flag) in lieu of explicit dependency edges. This avoids penalising SBOMs that correctly declare completeness without enumerating each edge.

**Notes for SME review:**
- The standard says "Other Unique Identifiers" — the implementation accepts PURL or CPE. SWID, SWHID, and hash-based identifiers are not yet accepted.
- Machine-readable format: tag-value (`.spdx`) format scores 0. This is a direct reading of NTIA guidance but may be contested.

---

### 5.2 BSI TR-03183-2

**Source:** BSI Technical Guideline TR-03183-2. Published by the German Federal Office for Information Security (BSI). Freely downloadable from bsi.bund.de.

**Three versions supported:** v1.1 (Nov 2023), v2.0 (Sep 2024), v2.1 (Aug 2025). Each version inherits from the previous via a call chain: `v2.1 → v2.0 → v1.1`.

#### BSI v1.1 checks (base, inherited by all versions)

| Check key | Tier | Description |
|-----------|------|-------------|
| `bsi_spec_format` | SHALL | Format is CycloneDX or SPDX |
| `bsi_spec_version` | SHALL | CycloneDX ≥ 1.4 or SPDX **≥ 2.2** |
| `bsi_sbom_uri` | SHOULD | Document namespace/serialNumber present |
| `bsi_timestamp` | SHALL | Creation timestamp present |
| `bsi_creator` | SHALL | Author or creator tool declared |
| `bsi_comp_name` | SHALL | Every component has a name |
| `bsi_comp_version` | SHALL | Every component has a version |
| `bsi_comp_supplier` | SHALL | Every component has a supplier |
| `bsi_comp_license` | SHALL | Every component has a license |
| `bsi_comp_purl` | SHALL | Every component has a PURL |
| `bsi_comp_hash` | SHOULD | Every component has a hash |
| `bsi_dependency_resolution` | SHOULD (→SHALL in v2.0) | At least one dependency edge; node set validated against all known bom-refs and component names |
| `bsi_comp_download_url` | SHOULD | Every component has a download location (not NOASSERTION/NONE) |
| `bsi_comp_source_hash` | SHOULD | Components with VCS external references include a hash on that reference — **N/A** if no VCS ref present |

**BSI v1.1 SPDX floor:** The minimum accepted SPDX version is **2.2** (not 2.3). Versions 2.2, 2.2.1, 2.2.2, 2.3, and 3.x all pass.

**Dependency node validation:** When checking `bsi_dependency_resolution`, the node set is built from `graph["nodes"]` plus all component `bom-ref` values and `name` values, preventing false "broken edge" failures when the parser-populated node list is incomplete.

#### BSI v2.0 additions (on top of v1.1)

| Check key | Tier | Description |
|-----------|------|-------------|
| `bsi_spec_version` | SHALL | Overrides v1.1: CDX ≥ 1.5 or SPDX ≥ 2.2.1 |
| `bsi_no_vuln_data` | SHALL | SBOM must not contain vulnerability data |
| `bsi_bom_links` | SHOULD | External BOM reference (bom-link) present |
| `bsi_signature` | SHOULD | Document signature present |
| `bsi_comp_filename` | SHALL | Every component has a filename property |
| `bsi_comp_type_property` | MAY | `bsi:component:executable`, `:archive`, or `:structured` property present |
| `bsi_comp_concluded_license` | SHOULD | Concluded (effective) license differs from declared — CDX 1.6 only, using `acknowledgement` field — **N/A** for non-CDX-1.6 |

#### BSI v2.1 additions (on top of v2.0)

| Check key | Tier | Description |
|-----------|------|-------------|
| `bsi_spec_version` | SHALL | Overrides v2.0: CDX ≥ 1.6 (SPDX 2.x not permitted — must use SPDX 3.0.1+) |
| `bsi_v21_deploy_hash` | SHALL | SHA-512 hash on distribution-type external reference (CDX 1.6 only, N/A if no dist ref) |
| `bsi_v21_declared_license` | SHALL | Declared (upstream) license with `acknowledgement=declared` (CDX 1.6 only) |
| `bsi_v21_effective_license` | MAY | `bsi:component:effectiveLicense` property |
| `bsi_v21_security_txt` | MAY | External reference of type `rfc-9116` (security.txt) |

**Notes for SME review:**
- `bsi_no_vuln_data` (v2.0 SHALL): flags the presence of any `vulnerabilities[]` array in a CycloneDX document.
- `bsi_comp_filename` uses BSI-specific property `bsi:component:filename`. May be absent in SBOMs not generated by BSI-aware tools, causing near-universal failure on this check.
- `bsi_v21_deploy_hash` is applicable only when the component has a distribution-type external reference.

---

### 5.3 OpenChain Telco (OCT)

**Source:** OpenChain Telco SBOM Guide v1.1, May 2024. Published by the OpenChain Project under CC BY 4.0. SPDX-only format.

**Format requirement:** CycloneDX input immediately fails with `spdx_only_fail=True` and a score of 0.

| Check key | Tier | Description |
|-----------|------|-------------|
| `oct_spec_format` | SHALL | SPDX format confirmed |
| `oct_spec_version` | SHALL | Non-empty SPDX version |
| `oct_created_timestamp` | SHALL | Creation timestamp present |
| `oct_namespace` | SHALL | Document namespace URI present |
| `oct_doc_name` | SHALL | Document name present |
| `oct_sbom_organization` | SHALL | Organization entry in Creator field |
| `oct_sbom_tool` | SHALL | Tool entry in Creator field |
| `oct_sbom_spdxid` | SHALL | `SPDXRef-DOCUMENT` present as document element identifier |
| `oct_sbom_comment` | SHOULD | DocumentComment field present |
| `oct_data_license` | SHALL | Data license declared (`dataLicense` field) |
| `oct_machine_format` | SHALL | JSON or tag-value format (not XML, not YAML) |
| `oct_human_format` | SHOULD | Same condition as machine format (machine-readable formats are also human-readable in this context) |
| `oct_pkg_spdxid` | SHALL | Every component has a `SPDXRef-*` identifier |
| `oct_pkg_name` | SHALL | Every component has a name |
| `oct_pkg_version` | SHALL | Every component has a version |
| `oct_pkg_supplier` | SHALL | Every component has a supplier |
| `oct_pkg_download_url` | SHALL | Every component has a download location (not NOASSERTION/NONE) |
| `oct_pkg_hash` | SHALL | Every component has a SHA-256 checksum |
| `oct_pkg_concluded_license` | SHALL | Every component has a concluded license (not NOASSERTION/NONE) |
| `oct_pkg_declared_license` | SHALL | Every component has a declared license |
| `oct_pkg_copyright` | SHALL | Every component has a copyright text |
| `oct_pkg_external_ref_purl` | SHALL | Every component has a PURL in external references |
| `oct_pkg_files_analyzed` | SHALL | Every component has `FilesAnalyzed` explicitly declared (true or false) |
| `oct_delivery_method` | SHOULD | Delivery method documented (placeholder; marked `applicable=False`) |
| `oct_delivery_timing` | SHOULD | Delivery timing documented (placeholder; marked `applicable=False`) |
| `oct_sbom_scope` | SHOULD | SBOM scope documented (placeholder; marked `applicable=False`) |

**Creator split:** `oct_sbom_organization` and `oct_sbom_tool` are separate checks (previously a single `oct_creator`). An SBOM must have both an `Organization:` entry and a `Tool:` entry in the Creator field.

**SHA-256 normalisation:** Algorithm name is normalised (uppercased, dashes/underscores/spaces stripped) before comparison to `SHA256`. This prevents BLAKE3-256 from being incorrectly accepted as SHA-256.

**Notes for SME review:**
- `oct_machine_format`: OCT requires JSON or Tag-Value but not XML. YAML is also excluded.
- `oct_pkg_download_url` falls back to `PackageDownloadLocation`; NOASSERTION is rejected.
- `oct_pkg_files_analyzed`: A value of `false` passes this check (explicit declaration is the requirement).
- Delivery/scope placeholders are `applicable=False` with score 5.0 — they contribute 5.0 to the mean rather than 0 or 10, since the intent is "not yet assessed" rather than "failing".

---

### 5.4 FSCT v3

**Source:** "Framing Software Component Transparency" — CISA / Linux Foundation, v3. Freely available public document.

FSCT uses a **minimum / recommended / aspirational** tier model with raw scores of 0/10/12/15, allowing an SBOM to exceed the 10.0 baseline. The `overall_score` is clamped at 10.0; the `raw_score` field exposes the uncapped value.

**SBOM-level checks:**

| Check key | Tier | Score | Description |
|-----------|------|-------|-------------|
| `fsct_sbom_author` | SHALL | 0/10/12 | Author name present=10 (minimum); name+contact info (email or URL)=12 (recommended) |
| `fsct_sbom_timestamp` | SHALL | 0/10 | Creation timestamp present |
| `fsct_sbom_type` | SHOULD | 0/10/15 | Lifecycle declared: 15 if multiple lifecycles (aspirational), 10 if one, 0 if none |
| `fsct_sbom_primary` | SHALL | 0/10 | Primary component identified |
| `fsct_sbom_relationships` | SHALL | 0/10/12 | Dependency relationships: 12 if complete graph, 10 if partial, 0 if none |

**Per-component checks:**

| Check key | Tier | Score | Description |
|-----------|------|-------|-------------|
| `fsct_comp_name` | SHALL | 0/10 | Non-empty name |
| `fsct_comp_version` | SHALL | 0/10 | Non-empty version |
| `fsct_comp_supplier` | SHALL | 0/10 | Supplier declared (including "unknown") |
| `fsct_comp_uniq_id` | SHALL | 0/10 | PURL, CPE, SWHID, SWID, or OmniBOR |
| `fsct_comp_checksum` | SHALL | 0/10/12 | 0=no checksum, 10=any checksum present, 12=strong checksum (SHA-256+) |
| `fsct_comp_license` | SHALL | 0/10/12/15 | 0=no license; 10=any license name (minimum); 12=valid SPDX ID (recommended); 15=SPDX ID + URL or embedded text (aspirational) |
| `fsct_comp_copyright` | SHOULD | 0/10 | Copyright text present |

**Checksum tiering:** `fsct_comp_checksum` scores 12.0 when a strong checksum (SHA-256+) is present, 10.0 when any weaker checksum is present, and 0 when no checksum is found. This can push the raw compliance score above 10.0.

**Alternative unique identifiers (FSCT unique IDs):** In addition to PURL and CPE, FSCT accepts:
- **SWHID** (Software Heritage persistent identifier): detected by the `swh:` URI prefix
- **SWID** (ISO/IEC 19770-2): detected by external reference type `swid`
- **OmniBOR** (formerly GitOID): detected by external reference type `omnibor` or `gitoid`

**Notes for SME review:**
- `fsct_sbom_relationships` scores 12 when `is_complete` is true. For SPDX, `is_complete` is never set (SPDX has no equivalent of CycloneDX compositions), so SPDX SBOMs are capped at 10 on this check.
- The `raw_score` field (returned in the API response and surfaced in the UI/PDF) shows the uncapped mean. `overall_score` is always ≤ 10.0.

---

## 6. Risk Analysis

The risk analyzer produces a per-component `RiskReport` by accumulating penalty points and mapping the total to a risk level.

### Per-component penalty points

| Factor | Points | Condition |
|--------|--------|-----------|
| Missing version | +15 | `component.version` is empty |
| Missing identifier | +20 | No PURL and no CPE |
| Missing supplier | +10 | `component.supplier` is empty |
| No license information | +10 | `component.licenses` is empty |
| MEDIUM copyleft license (LGPL/MPL/EPL/CDDL/EUPL) | +10 | Any license matches |
| HIGH copyleft license (GPL-2.0, GPL-3.0) | +20 | Any license matches |
| CRITICAL copyleft license (AGPL, SSPL) | +30 | Any license matches |
| LOW vulnerability (CVSS < 4.0) | +10 per vuln | OSV/NVD match |
| MEDIUM vulnerability (CVSS 4.0–6.9) | +20 per vuln | OSV/NVD match |
| HIGH vulnerability (CVSS 7.0–8.9) | +35 per vuln | OSV/NVD match |
| CRITICAL vulnerability (CVSS ≥ 9.0) | +50 per vuln | OSV/NVD match |

### Risk level thresholds

| Total points | Level |
|-------------|-------|
| ≥ 80 | CRITICAL |
| ≥ 50 | HIGH |
| ≥ 21 | MEDIUM |
| < 21 | LOW |

### Overall document risk level

1. Start with the highest individual component risk level.
2. If more than 30% of components are HIGH or CRITICAL, escalate the overall level by one tier.
3. The overall risk score is the **maximum** component score (not the mean).

**Notes for SME review:**
- Copyleft risk is included in component risk score. This conflates security risk with legal risk.
- The 30% escalation rule is an empirical heuristic. The threshold and fraction are tunable parameters.
- Vulnerability lookup key: PURL is preferred; fallback is `name@version`. Name-based lookup without an ecosystem hint is noisy.

---

## 7. Vulnerability Lookup

### Data sources

| Source | Role | Auth required |
|--------|------|---------------|
| [OSV.dev](https://osv.dev/docs/) `querybatch` API | Primary — covers GitHub, PyPI, npm, Maven, Go, Rust, Ruby, etc. | No |
| [NVD REST API v2](https://nvd.nist.gov/developers/vulnerabilities) | Enrichment — fills in CVSS scores missing from OSV | Yes (`NVD_API_KEY`) |
| [FIRST.org EPSS API](https://api.first.org/data/v1/epss) | EPSS score + percentile per CVE | No |
| [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Known Exploited Vulnerabilities flag | No |

### Malicious package detection

OSV advisories with an ID matching the `MAL-` prefix (e.g. `MAL-2024-1234`) are flagged as malicious. A component is also flagged if any advisory has `"is_malicious": true`. Malicious components contribute to the `sec_malicious_components` penalty in Category 8.

### Lookup strategy

1. **PURL-based:** preferred; uses `{"package": {"purl": purl}}` query.
2. **Name-based fallback:** for components without a PURL. Ecosystem is guessed from `component_type`.
3. **Results cached in-process** per scan.

### Retry policy

OSV queries retry with exponential backoff on HTTP 429 and 5xx responses. Delays: 2s, 4s, 8s (3 retries).

**Notes for SME review:**
- Non-CVE OSV advisories (e.g. GHSA IDs) that only have CVSS vectors and no numeric score will show 0.0 CVSS.
- Ecosystem guessing for name-based lookup can produce false positives.

---

## 8. EOL/EOS Detection

Verity queries the [endoflife.date](https://endoflife.date) public JSON API to check whether each component's product and version are past their end-of-life (EOL) or end-of-support (EOS) date.

### Lookup process

1. Component names are normalised to endoflife.date product slugs using a built-in mapping table (~50 entries, e.g. `python` → `python`, `nodejs` → `nodejs`, `openjdk` → `java`).
2. For each recognisable product, the API is queried at `https://endoflife.date/api/{slug}.json`.
3. The component version is matched against the returned release list.
4. Result: `True` (EOL), `False` (supported), or `None` (product unknown / version not found).

### Caching and error handling

- Results are cached in-process for the duration of a single scan (no cross-scan persistence).
- Any HTTP error or timeout returns `None` for all components — the check degrades gracefully rather than failing the scan.
- `None` results are not counted against the `sec_eol_components` score.

**Notes for SME review:**
- The slug mapping covers common products only. Bespoke or enterprise products not on endoflife.date always return `None`.
- Version matching uses the endoflife.date `cycle` field, which may use ranges (e.g. `3.12`) rather than exact versions. A component on version `3.12.1` matches the `3.12` cycle.

---

## 9. License Classification

### SPDX identifier validation

The license database contains a curated subset of the **SPDX 3.23 License List**. Validation is case-sensitive (per the SPDX spec). Compound expressions (e.g. `MIT OR Apache-2.0`) are not split — the whole string is tested against the set.

**Known gap:** SPDX license expressions (using `AND`, `OR`, `WITH`) are not parsed. A component with `(MIT OR Apache-2.0)` will score 0 on `comp_has_valid_spdx_license`. Parenthesised expressions are handled without crashing (the tokenizer correctly strips parentheses), but the resulting tokens are each individually validated, so `(MIT OR Apache-2.0)` is tokenised to `["MIT", "OR", "Apache-2.0"]` — `MIT` and `Apache-2.0` pass, but `OR` does not, causing the overall expression to fail.

### Copyleft classification (for risk analysis)

| Category | Examples | Risk points |
|----------|---------|-------------|
| CRITICAL (network copyleft) | AGPL-3.0, AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0 | +30 |
| HIGH (strong copyleft) | GPL-2.0, GPL-2.0-only, GPL-3.0, GPL-3.0-only, GPL-2.0-or-later, GPL-3.0-or-later, GPL-2.0+, GPL-3.0+ | +20 |
| MEDIUM (weak copyleft) | LGPL-2.0/2.1/3.0 (all variants), MPL-1.0/1.1/2.0, EUPL-1.0/1.1/1.2, CDDL-1.0/1.1, EPL-1.0/2.0 | +10 |

**Matching:** Case-insensitive prefix match.

**Notes for SME review:**
- SSPL-1.0 is classified as CRITICAL copyleft, consistent with OSI's position.
- MPL-2.0 is classified as MEDIUM (weak copyleft). Some legal teams treat MPL as effectively permissive for binary distributions.
- Creative Commons licenses are not in the copyleft classification (CC-BY-SA and CC-BY-NC-SA have share-alike requirements — a known gap).
- The deprecated license check does not distinguish between identifiers deprecated for clarity versus genuinely problematic identifiers.

---

## 10. Open Questions & Areas for SME Review

| # | Area | Current choice | Alternative to consider |
|---|------|---------------|------------------------|
| 1 | NTIA "Other Unique Identifiers" | Accepts PURL or CPE only | NTIA text is ambiguous; SWHID, SWID, internal IDs may also qualify |
| 2 | NTIA "Machine-readable Format" | Tag-value scores 0; only JSON/XML pass | SPDX TV is parseable by SPDX-aware tools; may deserve partial credit |
| 3 | BSI `bsi_comp_filename` | Checks `bsi:component:filename` property | Very few tools emit this; check produces near-universal failure on non-BSI tooling |
| 4 | BSI v2.1 SPDX | SPDX 2.x marks all component checks N/A | Some orgs will still use SPDX 2.3 with BSI v2.1 tooling |
| 5 | Quality score: `comp_no_restrictive_license` | Copyleft = lower quality score | Legal risk ≠ quality; consider moving to Risk Analysis only |
| 6 | SPDX license expressions | Not fully parsed; `OR`/`AND` operators fail validation | Implement expression parser per SPDX 2.3 spec Annex D |
| 7 | FSCT relationships completeness | CDX compositions → `is_complete`; SPDX never `is_complete` | SPDX has no equivalent; SPDX SBOMs are structurally disadvantaged on this check |
| 8 | Risk escalation at 30% | Arbitrary threshold | Industry guidance (e.g. CVSS Environmental score) may suggest a different model |
| 9 | Vulnerability name-based lookup | Ecosystem guessing from component_type | Without a PURL, false positives are likely; consider flagging rather than scoring |
| 10 | CVSS vector strings in OSV | Discarded (returns 0.0) | Should extract the base score from the CVSS vector string |
| 11 | Schema validation | Full JSON Schema validation via embedded CycloneDX 1.4/1.5/1.6 and SPDX 2.2/2.3 schemas | Extend to cover SPDX 2.1, CDX 1.3, and SPDX 3.x when official JSON schemas are published |
| 12 | Creative Commons licenses | Not classified for copyleft risk | CC-BY-SA and CC-BY-NC-SA have share-alike requirements |
| 13 | SPDX YAML support | Passed through SPDX JSON parser | YAML SPDX is an official format; consider testing against SPDX reference examples |
| 14 | OCT `files_analyzed` | Explicit declaration required (true or false) | Some tools always omit it; OCT spec may intend `false` as default |
| 15 | BSI `bsi_no_vuln_data` | Flags presence of CycloneDX `vulnerabilities[]` | BSI v2.0 intends separation into VEX; check may be too strict for hybrid SBOM+VEX documents |
| 16 | EOL product slug mapping | ~50 hand-curated entries | Many enterprise / bespoke products will always return `None` (unknown); consider a configurable mapping |
| 17 | OCT delivery/scope checks | `applicable=False` placeholders | These require out-of-band information; current approach avoids false failures but omits scoring entirely |
| 18 | Profile score weight choices | Opinionated weights derived from standard text | Standards do not publish numeric weights; SMEs from the standards bodies should review these |

---

*Document reflects source: `verity/backend/app/core/` — `scorer.py`, `risk_analyzer.py`, `vuln_checker.py`, `eol_checker.py`, `parser.py`, `compliance/ntia.py`, `compliance/bsi.py`, `compliance/oct.py`, `compliance/fsct.py`, `compliance/record.py`, `profiles/`, `licenses/spdx_db.py`.*
