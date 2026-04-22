# Verity SBOM Validator — Validation Logic Reference

This document describes every scoring rule, compliance check, and risk heuristic implemented in Verity. It is intended for subject-matter experts (SMEs) who want to audit the logic, flag errors, or suggest improvements.

---

## Table of Contents

1. [Supported Formats](#1-supported-formats)
2. [Quality Score — Overview](#2-quality-score--overview)
3. [Quality Score — Category Breakdown](#3-quality-score--category-breakdown)
   - 3.1 Structural Validity
   - 3.2 Identity & Traceability
   - 3.3 Provenance
   - 3.4 Integrity
   - 3.5 License Compliance
   - 3.6 Vulnerability Traceability
   - 3.7 Completeness
4. [Compliance Standards](#4-compliance-standards)
   - 4.1 NTIA Minimum Elements
   - 4.2 BSI TR-03183-2
   - 4.3 OpenChain Telco (OCT)
   - 4.4 FSCT v3
5. [Risk Analysis](#5-risk-analysis)
6. [Vulnerability Lookup](#6-vulnerability-lookup)
7. [License Classification](#7-license-classification)
8. [Open Questions & Areas for SME Review](#8-open-questions--areas-for-sme-review)

---

## 1. Supported Formats

| Format | Detection method | Versions recognized |
|--------|-----------------|---------------------|
| CycloneDX JSON | `bomFormat: CycloneDX` key | 1.4, 1.5, 1.6 |
| CycloneDX XML | `<bom xmlns=...cyclonedx...>` root | 1.4, 1.5, 1.6 |
| SPDX JSON | `spdxVersion` key | 2.2, 2.2.1, 2.2.2, 2.3 |
| SPDX Tag-Value | `SPDXVersion:` line | 2.2, 2.2.1, 2.2.2, 2.3 |
| SPDX YAML | `.yaml`/`.yml` extension + `spdxVersion` key | 2.2, 2.2.1, 2.2.2, 2.3 |

SPDX YAML is parsed by loading the YAML into a dict and passing it through the same path as SPDX JSON. The internal `file_format` field is set to `"yaml"` to distinguish it for display and for schema-validation applicability rules.

---

## 2. Quality Score — Overview

The quality score is a **weighted mean across seven categories**, each of which is itself a weighted mean of its features.

```
overall_score = Σ(category_score × category_weight) / Σ(category_weight)
```

Category weights (fixed, sum to 92):

| # | Category | Weight |
|---|----------|--------|
| 1 | Structural Validity | 10 |
| 2 | Identity & Traceability | 15 |
| 3 | Provenance | 12 |
| 4 | Integrity | 12 |
| 5 | License Compliance | 15 |
| 6 | Vulnerability Traceability | 16 |
| 7 | Completeness | 12 |
| — | **Total** | **92** |

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

---

## 3. Quality Score — Category Breakdown

### 3.1 Structural Validity (weight 10)

Checks whether the SBOM file is well-formed and uses a recognized spec version.

| Feature key | Weight | What is checked | Pass condition |
|-------------|--------|-----------------|----------------|
| `spec_detected` | 0.30 | Format auto-detected as CycloneDX or SPDX | True |
| `spec_version_supported` | 0.30 | Spec version is in the known-good set | CDX: 1.4/1.5/1.6; SPDX: 2.2/2.2.1/2.2.2/2.3 |
| `file_format_valid` | 0.20 | Detected format matches declared spec (duplicate of above, intentional weight reinforcement) | True |
| `schema_valid` | 0.20 | JSON required fields present (`bomFormat` + `specVersion` for CDX; `spdxVersion` for SPDX) | True — **N/A** for XML and tag-value |

**Notes for SME review:**
- Schema validation is lightweight (required-fields check), not a full JSON Schema validation against the official CycloneDX/SPDX JSON Schemas. A future improvement would validate against the published schemas at `https://cyclonedx.org/schema/` and `https://spdx.org/schema/`.
- SPDX encodes its version as `"SPDX-2.3"` (with prefix). The parser strips this prefix internally before comparisons; the original string is preserved in `doc.spec_version` for display.

---

### 3.2 Identity & Traceability (weight 15)

Checks whether each component can be uniquely identified.

| Feature key | Weight | What is checked |
|-------------|--------|-----------------|
| `comp_has_name` | 0.25 | Non-empty `name` field |
| `comp_has_version` | 0.25 | Non-empty `version`/`versionInfo` field |
| `comp_has_local_unique_id` | 0.20 | `bom-ref` (CDX) or `SPDXID` is non-empty **and unique** within the document |
| `comp_has_purl` | 0.20 | Non-empty `purl` field |
| `comp_has_cpe` | 0.10 | Non-empty `cpe` field |

**Local unique ID uniqueness:** Duplicated bom-refs are not counted as having a unique ID, because duplicate identifiers break dependency graph resolution.

**Notes for SME review:**
- PURL and CPE syntax validity is checked separately in Category 6 (Vulnerability Traceability). This category only checks presence.
- The `comp_has_cpe` weight (0.10) is lower than PURL (0.20) because PURL is the preferred modern identifier; CPE is legacy and ecosystem-specific.

---

### 3.3 Provenance (weight 12)

Checks document-level attribution — who created the SBOM, when, and with what tool.

| Feature key | Weight | What is checked | Applicable |
|-------------|--------|-----------------|------------|
| `doc_has_creation_timestamp` | 0.25 | Non-empty `created`/`creationInfo.created` field | Always |
| `doc_has_authors` | 0.20 | At least one non-empty author/creator string | Always |
| `doc_has_tool_with_version` | 0.20 | Tool declared with both name and version — **tiered**: 0=no tools, 5=name-only, 10=name+version | Always |
| `doc_has_namespace` | 0.20 | Non-empty `documentNamespace` (SPDX) or `serialNumber` (CDX) | Always |
| `doc_has_supplier` | 0.10 | `metadata.supplier` present (CDX) | CDX only |
| `doc_has_lifecycle` | 0.05 | `metadata.lifecycles` present (CDX 1.5+) | CDX only |

**Tool tier scoring:** `_tiered(0)=0`, `_tiered(1)=5`, `_tiered(2)=10`. The tool is considered fully scored when at least one tool has both a `name` (or `vendor`) and a `version`.

---

### 3.4 Integrity (weight 12)

Checks whether component hashes are present and use strong algorithms, and whether the document is signed.

| Feature key | Weight | What is checked |
|-------------|--------|-----------------|
| `comp_has_any_checksum` | 0.55 | Any hash algorithm present per component |
| `comp_has_strong_checksum` | 0.35 | Hash uses a strong algorithm (SHA-256+) — see list below |
| `doc_has_signature` | 0.10 | Document signature block — **tiered**: 0=none, 5=signature present but no key material, 10=signature with public key or certificate |

**Strong hash algorithms** (based on NIST SP 800-107 / SP 800-208):

SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256/384/512, BLAKE3, STREEBOG-256, STREEBOG-512.

**Weak algorithms** (penalised, not counted as strong): MD5, MD2, MD4, MD6, SHA-1, ADLER-32.

**Notes for SME review:**
- The `comp_has_any_checksum` weight (0.55) is higher than `comp_has_strong_checksum` (0.35) because even a weak checksum is better than none for integrity verification. SMEs may want to invert this or require strong checksums for a full score.
- STREEBOG (GOST R 34.11-2012) is included as a strong algorithm to support SBOM tooling from Russian-standard environments. It may be controversial in some regulatory contexts.
- Document-level signature checking only inspects the structural presence of `publicKey`, `certificate`, or `certificates` fields. Actual signature verification is not performed.

---

### 3.5 License Compliance (weight 15)

Checks whether licenses are declared, use valid SPDX identifiers, and are not deprecated or restrictive.

| Feature key | Weight | What is checked |
|-------------|--------|-----------------|
| `comp_has_license` | 0.25 | Component has at least one non-absent license (not NOASSERTION/NONE) |
| `comp_has_valid_spdx_license` | 0.25 | All licenses are valid SPDX identifiers — **N/A** if no component has a license |
| `comp_has_declared_license` | 0.15 | Separate upstream-declared license field populated (CDX `acknowledgement=declared`; SPDX `PackageLicenseDeclared`) |
| `comp_no_deprecated_license` | 0.15 | No deprecated SPDX identifiers used (e.g. `GPL-2.0+`) |
| `comp_no_restrictive_license` | 0.20 | No strong copyleft licenses (GPL, AGPL, etc.) — see [Section 7](#7-license-classification) |
| `sbom_has_data_license` | 0.10 | SBOM's own data license declared (`dataLicense` in SPDX; `metadata.licenses` in CDX) and not NOASSERTION/NONE |

**NOASSERTION/NONE handling:** These SPDX sentinel values are treated as absent. A component with only `NOASSERTION` is scored the same as one with no license.

**Deprecated license detection:** Checks against a curated list of identifiers that have been deprecated in the SPDX License List (e.g. `GPL-2.0+`, `LGPL-2.1+`, `eCos-2.0`).

**Notes for SME review:**
- `comp_no_restrictive_license` awards 10 points when a component has **no** restrictive licenses. This is intended to highlight risk, but may not reflect actual SBOM quality — a component legitimately using GPL should not penalise quality. SMEs may want this moved to the Risk Analysis dimension instead of the quality score.
- The `comp_has_declared_license` logic differs by format: for CDX, it requires the `acknowledgement=declared` attribute (CDX 1.6+ only); for SPDX, it uses `PackageLicenseDeclared`. Non-CDX-1.6 CDX SBOMs cannot pass this check.
- SPDX license list version in use: **3.23** (curated subset covering >99% of real-world SBOMs, not the full ~700-entry list).

---

### 3.6 Vulnerability Traceability (weight 16)

Checks whether components can be looked up against vulnerability databases — i.e., whether they carry valid machine-readable identifiers.

| Feature key | Weight | What is checked |
|-------------|--------|-----------------|
| `comp_purl_syntax_valid` | 0.45 | PURL matches the pattern `pkg:<type>/<name>[@version]` — **N/A** if no PURLs present |
| `comp_cpe_syntax_valid` | 0.35 | CPE matches CPE 2.3 (`cpe:2.3:...`) or CPE 2.2 (`cpe:/...`) pattern — **N/A** if no CPEs present |
| `comp_has_at_least_one_id` | 0.20 | Component has at least one syntactically valid PURL **or** CPE |

**PURL pattern:** `^pkg:[a-zA-Z][a-zA-Z0-9.+\-]*/[^@\s]+` — validates type and namespace/name. Does not validate type-specific rules (e.g. Maven requires `group/artifact`).

**CPE 2.3 pattern:** `^cpe:2\.3:[aho\*\-](:[^:]*){10}$` — requires exactly 13 colon-separated components. CPE 2.2 pattern: `^cpe:/`.

**Notes for SME review:**
- PURL validation does not verify that the package type is a known/registered type. For example, `pkg:foobar/xyz` passes syntax validation. Tightening this to a whitelist of known PURL types (from https://github.com/package-url/purl-spec) would improve quality.
- CPE 2.2 matching (`^cpe:/`) is permissive — it does not validate the full structure. CPE 2.2 is legacy and many tools generate syntactically malformed CPEs.
- The weight split (PURL 0.45, CPE 0.35, either 0.20) prioritises PURLs as the primary identifier, consistent with OSV.dev and other vulnerability databases.

---

### 3.7 Completeness (weight 12)

Checks whether the SBOM describes its dependency graph and provides full supplier/source context per component.

| Feature key | Weight | What is checked | Applicable |
|-------------|--------|-----------------|------------|
| `doc_has_primary_component` | 0.20 | The top-level component being described is identified | Always |
| `doc_dependency_graph_present` | 0.15 | At least one dependency edge declared | Always |
| `comp_has_dependencies_declared` | 0.10 | How many components appear as a source node in the graph | Always |
| `sbom_completeness_declared` | 0.05 | `compositions` section present (CDX) declaring completeness | CDX only |
| `comp_has_supplier` | 0.20 | Non-empty supplier per component | Always |
| `comp_has_source_url` | 0.15 | VCS or distribution external reference per component | Always |
| `comp_has_purpose` | 0.15 | Non-empty component type/purpose field | Always |

**Dependency graph:** Edges are resolved from CDX `dependencies[].dependsOn` or SPDX `relationships` (type `DEPENDS_ON`). SPDX `DESCRIBES` and `CONTAINS` relationships are used to find the primary component reference, not dependency edges.

**Source URL detection:** Looks for `externalReferences` of type `vcs`, `source-distribution`, or `distribution`.

---

## 4. Compliance Standards

Compliance checks use a three-tier model:

| Tier | Keyword | Included in score | Description |
|------|---------|-------------------|-------------|
| REQUIRED | SHALL | Always | Failure is a non-compliance finding |
| ADDITIONAL | SHOULD | When applicable=True | Best-practice recommendation |
| OPTIONAL | MAY | Never | Advisory; shown for information only |

**Compliance score formula:**

```
compliance_score = mean(score) over all REQUIRED + applicable ADDITIONAL records
```

Each record has a score of 0, 5, or 10 (or 12/15 for FSCT tiered checks).

---

### 4.1 NTIA Minimum Elements

**Source:** "The Minimum Elements For a Software Bill of Materials (SBOM)" — US Department of Commerce / NTIA, July 2021. Public domain.

**Standard elements checked:**

| Element | Tier | Check |
|---------|------|-------|
| Author of SBOM Data | SHALL | At least one author string or tool declared |
| Timestamp | SHALL | Non-empty creation timestamp |
| Dependency Relationships | SHALL | At least one dependency edge in the graph |
| Component Name | SHALL | Every component has a non-empty name |
| Supplier Name | SHALL | Every component has a non-empty supplier **or** manufacturer/originator (fallback) |
| Version of Component | SHALL | Every component has a non-empty version |
| Other Unique Identifiers | SHALL | Every component has a PURL **or** CPE |
| SBOM Generation Tool | SHOULD | At least one tool declared with both name and version |
| Machine-readable Format | SHOULD | File format is JSON or XML (tag-value scores lower) |

**Supplier fallback logic:** The NTIA check accepts `component.supplier` first. If absent, it falls back to `component.manufacturer` (CycloneDX `metadata.component.manufacturer` or CDX component `manufacturer`) or SPDX `PackageOriginator`. This is an implementation interpretation — the NTIA document says "Supplier Name" without specifying how to map this to CDX/SPDX fields.

**Overall compliance:** True only when all nine elements pass. A single missing version on one component makes the whole SBOM non-compliant.

**Notes for SME review:**
- The standard says "Other Unique Identifiers" — the implementation accepts PURL or CPE. Some interpretations also include SWID tags, SWHIDs, or hash-based identifiers. The NTIA document is ambiguous here.
- Machine-readable format: tag-value (`.spdx`) format scores 0 because it is not JSON or XML. This is a direct reading of the NTIA guidance but may be contested — SPDX TV is machine-parseable by compatible tools.

---

### 4.2 BSI TR-03183-2

**Source:** BSI Technical Guideline TR-03183-2, "Cyber Resilience Requirements for Manufacturers and Products — Part 2: Software Bill of Materials (SBOM)". Published by the German Federal Office for Information Security (BSI). Freely downloadable from bsi.bund.de.

**Three versions supported:** v1.1 (Nov 2023), v2.0 (Sep 2024), v2.1 (Aug 2025). Each version inherits from the previous via a call chain: `v2.1 → v2.0 → v1.1`.

#### BSI v1.1 checks (base, inherited by all versions)

| Check key | Tier | Description |
|-----------|------|-------------|
| `bsi_spec_format` | SHALL | Format is CycloneDX or SPDX |
| `bsi_spec_version` | SHALL | CycloneDX ≥ 1.4 or SPDX ≥ 2.2.1 |
| `bsi_sbom_uri` | SHOULD | Document namespace/serialNumber present |
| `bsi_timestamp` | SHALL | Creation timestamp present |
| `bsi_creator` | SHALL | Author or creator tool declared |
| `bsi_comp_name` | SHALL | Every component has a name |
| `bsi_comp_version` | SHALL | Every component has a version |
| `bsi_comp_supplier` | SHALL | Every component has a supplier |
| `bsi_comp_license` | SHALL | Every component has a license |
| `bsi_comp_purl` | SHALL | Every component has a PURL |
| `bsi_comp_hash` | SHOULD | Every component has a hash |
| `bsi_dependency_resolution` | SHOULD (→SHALL in v2.0) | At least one dependency edge |

#### BSI v2.0 additions (on top of v1.1)

| Check key | Tier | Description |
|-----------|------|-------------|
| `bsi_spec_version` | SHALL | Overrides v1.1: CDX ≥ 1.5 or SPDX ≥ 2.2.1 |
| `bsi_no_vuln_data` | SHALL | SBOM must not contain vulnerability data |
| `bsi_bom_links` | SHOULD | External BOM reference (bom-link) present |
| `bsi_signature` | SHOULD | Document signature present |
| `bsi_comp_filename` | SHALL | Every component has a filename property |
| `bsi_comp_type_property` | MAY | `bsi:component:executable`, `:archive`, or `:structured` property present |

#### BSI v2.1 additions (on top of v2.0)

| Check key | Tier | Description |
|-----------|------|-------------|
| `bsi_spec_version` | SHALL | Overrides v2.0: CDX ≥ 1.6 (SPDX 2.x not permitted — must use SPDX 3.0.1+) |
| `bsi_v21_deploy_hash` | SHALL | SHA-512 hash on distribution-type external reference (CDX 1.6 only, N/A if no dist ref) |
| `bsi_v21_declared_license` | SHALL | Declared (upstream) license with `acknowledgement=declared` (CDX 1.6 only) |
| `bsi_v21_effective_license` | MAY | `bsi:component:effectiveLicense` property |
| `bsi_v21_security_txt` | MAY | External reference of type `rfc-9116` (security.txt) |

**SPDX-in-v2.1 behavior:** If the input is SPDX version 2.x (not 3.x), all per-component checks are marked `applicable=False` because BSI v2.1 requires SPDX 3.0.1+ for component-level properties.

**Notes for SME review:**
- `bsi_no_vuln_data` (v2.0 SHALL): the BSI TR-03183-2 v2.0 requires that vulnerability information is NOT included in the SBOM (it should be in a separate VEX document). This is a strict separation requirement. The check flags the presence of any `vulnerabilities[]` array in a CycloneDX document.
- `bsi_comp_filename` uses BSI-specific property `bsi:component:filename`. This is a BSI extension not present in the base CycloneDX schema. It may be absent in SBOMs not generated by BSI-aware tools, causing mass failure on this check.
- `bsi_v21_deploy_hash` is marked applicable only when the component has a distribution-type external reference (`distribution` or `distribution-intake`). Without such a reference, the check is N/A. This is an interpretation — the BSI text may intend all deployable components, not just those with explicit dist refs.

---

### 4.3 OpenChain Telco (OCT)

**Source:** OpenChain Telco SBOM Guide v1.1, May 2024. Published by the OpenChain Project under CC BY 4.0. SPDX-only format.

**Format requirement:** CycloneDX input immediately fails with `spdx_only_fail=True` and a score of 0. All checks apply only to SPDX.

| Check key | Tier | Description |
|-----------|------|-------------|
| `oct_spec_format` | SHALL | SPDX format confirmed |
| `oct_spec_version` | SHALL | Non-empty SPDX version |
| `oct_created_timestamp` | SHALL | Creation timestamp present |
| `oct_namespace` | SHALL | Document namespace URI present |
| `oct_doc_name` | SHALL | Document name present |
| `oct_creator` | SHALL | Organization or tool in creator field |
| `oct_data_license` | SHALL | Data license declared (`dataLicense` field) |
| `oct_machine_format` | SHALL | JSON or tag-value format (not XML, not YAML) |
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

**Notes for SME review:**
- `oct_machine_format`: The OCT guide requires JSON or Tag-Value but not XML. YAML is also excluded. This differs from NTIA (which accepts JSON or XML).
- `oct_pkg_download_url` falls back to `PackageDownloadLocation` in SPDX, and also checks `externalRefs[type=download]` or `[type=distribution]`. NOASSERTION is rejected as "no download location."
- `oct_pkg_declared_license`: if no separate declared license field is found, the check falls back to using the concluded license. This is permissive — OCT guidance strictly requires a separate declared field.
- `oct_pkg_files_analyzed`: A value of `false` passes this check (it was explicitly set, which is the requirement). Only absent/unparsed is a failure.

---

### 4.4 FSCT v3

**Source:** "Framing Software Component Transparency: Establishing a Common Software Bill of Materials (SBOM)" — CISA / Linux Foundation, v3. Freely available public document.

FSCT uses a **minimum / recommended / aspirational** tier model with raw scores of 0/10/12/15, allowing an SBOM to exceed the baseline.

**SBOM-level checks:**

| Check key | Tier | Score | Description |
|-----------|------|-------|-------------|
| `fsct_sbom_author` | SHALL | 0/10 | Author name declared |
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
| `fsct_comp_checksum` | SHALL | 0/10 | Any checksum present (strong preferred, score is binary 0 or 10) |
| `fsct_comp_license` | SHALL | 0/5/10 | 10=valid SPDX ID, 5=license name but not valid SPDX, 0=no license |
| `fsct_comp_copyright` | SHOULD | 0/10 | Copyright text present |

**Alternative unique identifiers (FSCT unique IDs):** In addition to PURL and CPE, FSCT accepts:
- **SWHID** (Software Heritage persistent identifier): detected by the `swh:` URI prefix in any external reference URL
- **SWID** (ISO/IEC 19770-2 Software Identification): detected by external reference type `swid`
- **OmniBOR** (formerly GitOID): detected by external reference type `omnibor` or `gitoid`

**Notes for SME review:**
- `fsct_sbom_relationships` scores 12 when the dependency graph's `is_complete` flag is true. For CycloneDX, this is set when any `compositions[].aggregate == "complete"`. For SPDX, this is never set (SPDX has no equivalent of CycloneDX compositions), so SPDX SBOMs are capped at 10 on this check.
- FSCT checksum scoring (`fsct_comp_checksum`) is binary (0 or 10) despite the documentation saying "12=strong checksum". The rationale is that FSCT checksum strength is already captured in Category 4 (Integrity) of the quality score. Raising this to 12 for strong checksums would require refactoring the FSCT score normalisation.
- FSCT compliance score is computed by the same formula as other standards (mean of REQUIRED + applicable ADDITIONAL records), so scores of 12 or 15 can push the overall compliance score above 10. This is intentional — it signals aspirational compliance.

---

## 5. Risk Analysis

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
2. If more than 30% of components are HIGH or CRITICAL, escalate the overall level by one tier (e.g. HIGH → CRITICAL).
3. The overall risk score is the **maximum** component score (not the mean), to avoid contradictions between a displayed HIGH level and a low numeric score.

**Notes for SME review:**
- The penalty model is additive and linear. Multiple HIGH vulnerabilities can push a component into CRITICAL. There is no cap, so a component with many CVEs may reach 200+ points, but the level is still CRITICAL.
- Copyleft risk is included in component risk score. This conflates security risk with legal risk. Some SMEs may prefer these as separate dimensions.
- The 30% escalation rule is an empirical heuristic. It attempts to capture the idea that a "mostly HIGH" portfolio is a CRITICAL situation even if no single component is CRITICAL. The threshold and fraction are tunable parameters.
- Vulnerability lookup key: PURL is preferred; fallback is `name@version`. If neither yields results, the component is assumed vulnerability-free. Name-based lookup without an ecosystem hint is noisy (may return unrelated packages).

---

## 6. Vulnerability Lookup

### Data sources

| Source | Role | Auth required |
|--------|------|---------------|
| [OSV.dev](https://osv.dev/docs/) `querybatch` API | Primary — covers GitHub, PyPI, npm, Maven, Go, Rust, Ruby, etc. | No |
| [NVD REST API v2](https://nvd.nist.gov/developers/vulnerabilities) | Enrichment — fills in CVSS scores missing from OSV | Yes (`NVD_API_KEY`) |
| [FIRST.org EPSS API](https://api.first.org/data/v1/epss) | EPSS score + percentile per CVE | No |
| [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Known Exploited Vulnerabilities flag | No |

### Lookup strategy

1. **PURL-based:** preferred; uses `{"package": {"purl": purl}}` query. Exact version matching is handled by OSV.
2. **Name-based fallback:** for components without a PURL. Uses `{"package": {"name": name, "ecosystem": guessed}}` + version. Ecosystem is guessed from `component_type` (e.g. "python" → PyPI, "npm" → npm).
3. **Results cached in-process:** component key → vuln list. Cache is not persisted across restarts.

### Retry policy

OSV queries retry with exponential backoff on HTTP 429 and 5xx responses. Delays: 2s, 4s, 8s (3 retries). NVD queries use the same policy.

### EPSS and KEV enrichment

EPSS is fetched in batches of 100 CVE IDs after OSV results are collected. KEV catalog is loaded once at startup and cached for the process lifetime.

**Notes for SME review:**
- OSV batch size is 1000 queries per request. This should handle most SBOMs, but very large SBOMs (>1000 components) will make multiple requests.
- CVSS score extraction from OSV uses `severity[].score` field. When the score string starts with `CVSS:` (a full CVSS vector), it is discarded (returns 0.0). The NVD enrichment step then fills in the numeric score for CVE IDs. This means non-CVE OSV advisories (e.g. GHSA IDs) that only have CVSS vectors and no numeric score will show 0.0 CVSS and be classified as UNKNOWN severity.
- Ecosystem guessing for name-based lookup is a best-effort heuristic. It can produce false positives (wrong package matched by name in the wrong ecosystem) or false negatives (no ecosystem guessed, so OSV may return results from all ecosystems).

---

## 7. License Classification

### SPDX identifier validation

The license database contains a curated subset of the **SPDX 3.23 License List** covering commonly seen identifiers. Validation is case-sensitive (per the SPDX spec). Compound expressions (e.g. `MIT OR Apache-2.0`) are not split — the whole string is tested against the set, so compound expressions will typically fail validation.

**Known gap:** SPDX license expressions (using `AND`, `OR`, `WITH`) are not parsed. A component with `(MIT OR Apache-2.0)` will score 0 on `comp_has_valid_spdx_license`.

### Copyleft classification (for risk analysis)

| Category | Examples | Risk points |
|----------|---------|-------------|
| CRITICAL (network copyleft) | AGPL-3.0, AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0 | +30 |
| HIGH (strong copyleft) | GPL-2.0, GPL-2.0-only, GPL-3.0, GPL-3.0-only, GPL-2.0-or-later, GPL-3.0-or-later, GPL-2.0+, GPL-3.0+ | +20 |
| MEDIUM (weak copyleft) | LGPL-2.0/2.1/3.0 (all variants), MPL-1.0/1.1/2.0, EUPL-1.0/1.1/1.2, CDDL-1.0/1.1, EPL-1.0/2.0 | +10 |

**Matching:** Case-insensitive prefix match. `AGPL-3.0-only` and `agpl-3.0-or-later` both match the CRITICAL category.

**Restrictive licenses (for quality score):** The `comp_no_restrictive_license` quality feature uses the same copyleft classification. Any license in CRITICAL or HIGH category is considered restrictive.

**Notes for SME review:**
- SSPL-1.0 is classified as CRITICAL copyleft. This is consistent with the position of the Open Source Initiative (OSI), which does not consider SSPL open source, and MongoDB's use of it as a business-source-like license.
- MPL-2.0 is classified as MEDIUM (weak copyleft). Some legal teams treat MPL as effectively permissive for binary distributions. The MEDIUM classification may be conservative.
- Creative Commons licenses (CC-BY, CC-BY-SA, CC-BY-NC, etc.) are not in the copyleft classification, though CC-BY-SA and CC-BY-NC-SA have share-alike requirements. This is a known gap.
- The deprecated license check does not distinguish between identifiers deprecated for clarity (e.g. `GPL-2.0+` → `GPL-2.0-or-later`) versus genuinely problematic identifiers. Both are flagged.

---

## 8. Open Questions & Areas for SME Review

The following are areas where the current implementation makes choices that SMEs may want to review or challenge:

| # | Area | Current choice | Alternative to consider |
|---|------|---------------|------------------------|
| 1 | NTIA "Other Unique Identifiers" | Accepts PURL or CPE only | NTIA text is ambiguous; SWHID, SWID, internal IDs may also qualify |
| 2 | NTIA "Machine-readable Format" | Tag-value scores 0; only JSON/XML pass | SPDX TV is parseable by SPDX-aware tools; may deserve partial credit |
| 3 | BSI `bsi_comp_filename` | Checks `bsi:component:filename` property | Very few tools emit this; check produces near-universal failure on non-BSI tooling |
| 4 | BSI v2.1 SPDX | SPDX 2.x marks all component checks N/A | Some orgs will still use SPDX 2.3 with BSI v2.1 tooling |
| 5 | Quality score: `comp_no_restrictive_license` | Copyleft = lower quality score | Legal risk ≠ quality; consider moving to Risk Analysis only |
| 6 | SPDX license expressions | Not parsed; compound expressions fail | Implement expression parser per SPDX 2.3 spec Annex D |
| 7 | FSCT relationships completeness | CDX compositions → `is_complete`; SPDX never `is_complete` | SPDX has no equivalent; SPDX SBOMs are structurally disadvantaged on this check |
| 8 | Risk escalation at 30% | Arbitrary threshold | Industry guidance (e.g. CVSS Environmental score) may suggest a different model |
| 9 | Vulnerability name-based lookup | Ecosystem guessing from component_type | Without a PURL, false positives are likely; consider flagging rather than scoring |
| 10 | CVSS vector strings in OSV | Discarded (returns 0.0) | Should extract the base score from the CVSS vector string |
| 11 | Schema validation | Lightweight required-fields check only | Full JSON Schema validation against CycloneDX/SPDX published schemas |
| 12 | Creative Commons licenses | Not classified for copyleft risk | CC-BY-SA and CC-BY-NC-SA have share-alike requirements |
| 13 | SPDX YAML support | Passed through SPDX JSON parser | YAML SPDX is an official format; consider testing against SPDX reference examples |
| 14 | OCT `files_analyzed` | Explicit declaration required (true or false) | Some tools always omit it; OCT spec may intend `false` as default |
| 15 | BSI `bsi_no_vuln_data` | Flags presence of CycloneDX `vulnerabilities[]` | BSI v2.0 intends separation into VEX; check may be too strict for hybrid SBOM+VEX documents |

---

*Document generated from source: `verity/backend/app/core/` — `scorer.py`, `risk_analyzer.py`, `vuln_checker.py`, `parser.py`, `compliance/ntia.py`, `compliance/bsi.py`, `compliance/oct.py`, `compliance/fsct.py`, `compliance/record.py`, `licenses/spdx_db.py`.*
