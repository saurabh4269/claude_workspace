"""
SBOM validator for Verity.
Checks NTIA minimum elements and format spec compliance.
"""

from dataclasses import dataclass, field
from typing import Optional

from app.core.parser import SBOMDocument, Component


@dataclass
class ValidationIssue:
    severity: str  # ERROR / WARNING / INFO
    code: str      # e.g. NTIA_MISSING_SUPPLIER
    message: str
    component_name: Optional[str] = None


@dataclass
class ComponentValidation:
    component_name: str
    missing_fields: list[str]
    issues: list[ValidationIssue]


@dataclass
class ValidationResult:
    ntia_compliant: bool
    issues: list[ValidationIssue]
    component_results: list[ComponentValidation]


# ---------------------------------------------------------------------------
# NTIA Minimum Elements (2021)
# https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf
# ---------------------------------------------------------------------------

_NTIA_REQUIRED_COMPONENT_FIELDS = [
    "supplier",
    "name",
    "version",
    "identifier",  # PURL or CPE
]


def validate(doc: SBOMDocument) -> ValidationResult:
    """
    Validate an SBOMDocument against NTIA minimum elements and format spec.

    Returns a ValidationResult with:
    - ntia_compliant: True only if all NTIA checks pass.
    - issues: Document-level issues found.
    - component_results: Per-component validation details.
    """
    issues: list[ValidationIssue] = []
    component_results: list[ComponentValidation] = []

    # ------------------------------------------------------------------
    # Document-level NTIA checks
    # ------------------------------------------------------------------

    # NTIA: SBOM author must be present
    if not doc.authors:
        issues.append(
            ValidationIssue(
                severity="ERROR",
                code="NTIA_MISSING_AUTHOR",
                message="No SBOM author information found. NTIA requires at least one author.",
            )
        )

    # NTIA: Timestamp must be present
    if not doc.created:
        issues.append(
            ValidationIssue(
                severity="ERROR",
                code="NTIA_MISSING_TIMESTAMP",
                message="No creation timestamp found. NTIA requires a timestamp for the SBOM.",
            )
        )

    # NTIA: Dependency relationships (best-effort; noted as INFO since not all
    # parsers expose relationship data directly)
    if doc.format == "spdx":
        # SPDX documents with no packages at all cannot have relationships
        if not doc.components:
            issues.append(
                ValidationIssue(
                    severity="INFO",
                    code="NTIA_NO_DEPENDENCY_DATA",
                    message=(
                        "No packages found. NTIA recommends including dependency "
                        "relationship information where known."
                    ),
                )
            )
    elif doc.format == "cyclonedx":
        if not doc.components:
            issues.append(
                ValidationIssue(
                    severity="INFO",
                    code="NTIA_NO_DEPENDENCY_DATA",
                    message=(
                        "No components found. NTIA recommends including dependency "
                        "relationship information where known."
                    ),
                )
            )

    # Format-specific document-level checks
    _check_format_document(doc, issues)

    # ------------------------------------------------------------------
    # Per-component NTIA checks
    # ------------------------------------------------------------------
    for comp in doc.components:
        comp_result = _validate_component(comp)
        component_results.append(comp_result)
        # Escalate component errors to document-level issues list
        for issue in comp_result.issues:
            if issue.severity == "ERROR":
                issues.append(issue)

    # ------------------------------------------------------------------
    # NTIA compliance decision
    # ------------------------------------------------------------------
    # Compliant only when there are no ERROR-severity issues
    ntia_compliant = not any(i.severity == "ERROR" for i in issues)

    return ValidationResult(
        ntia_compliant=ntia_compliant,
        issues=issues,
        component_results=component_results,
    )


def _validate_component(comp: Component) -> ComponentValidation:
    """Run NTIA and format checks on a single component."""
    issues: list[ValidationIssue] = []
    missing_fields: list[str] = []

    # NTIA: Component name (always present since parser requires it, but double-check)
    if not comp.name:
        missing_fields.append("name")
        issues.append(
            ValidationIssue(
                severity="ERROR",
                code="NTIA_MISSING_NAME",
                message="Component is missing a name.",
                component_name=comp.name or "(unknown)",
            )
        )

    # NTIA: Supplier
    if not comp.supplier:
        missing_fields.append("supplier")
        issues.append(
            ValidationIssue(
                severity="ERROR",
                code="NTIA_MISSING_SUPPLIER",
                message=f"Component '{comp.name}' is missing supplier information.",
                component_name=comp.name,
            )
        )

    # NTIA: Version
    if not comp.version:
        missing_fields.append("version")
        issues.append(
            ValidationIssue(
                severity="ERROR",
                code="NTIA_MISSING_VERSION",
                message=f"Component '{comp.name}' is missing version information.",
                component_name=comp.name,
            )
        )

    # NTIA: Unique identifier (PURL or CPE)
    if not comp.purl and not comp.cpe:
        missing_fields.append("identifier")
        issues.append(
            ValidationIssue(
                severity="ERROR",
                code="NTIA_MISSING_IDENTIFIER",
                message=(
                    f"Component '{comp.name}' has no unique identifier "
                    "(PURL or CPE required)."
                ),
                component_name=comp.name,
            )
        )

    # Advisory: License information
    if not comp.licenses:
        missing_fields.append("licenses")
        issues.append(
            ValidationIssue(
                severity="WARNING",
                code="MISSING_LICENSE",
                message=f"Component '{comp.name}' has no license information.",
                component_name=comp.name,
            )
        )

    return ComponentValidation(
        component_name=comp.name,
        missing_fields=missing_fields,
        issues=issues,
    )


def _check_format_document(doc: SBOMDocument, issues: list[ValidationIssue]) -> None:
    """Add format-specific document-level validation issues."""
    if doc.format == "cyclonedx":
        _check_cyclonedx_document(doc, issues)
    elif doc.format == "spdx":
        _check_spdx_document(doc, issues)


def _check_cyclonedx_document(doc: SBOMDocument, issues: list[ValidationIssue]) -> None:
    """Validate CycloneDX-specific required fields."""
    if not doc.spec_version:
        issues.append(
            ValidationIssue(
                severity="WARNING",
                code="CDX_MISSING_SPEC_VERSION",
                message="CycloneDX SBOM is missing specVersion field.",
            )
        )

    if not doc.document_namespace:
        issues.append(
            ValidationIssue(
                severity="WARNING",
                code="CDX_MISSING_SERIAL_NUMBER",
                message="CycloneDX SBOM is missing serialNumber (recommended for uniqueness).",
            )
        )

    if not doc.tools:
        issues.append(
            ValidationIssue(
                severity="INFO",
                code="CDX_MISSING_TOOLS",
                message=(
                    "No tool metadata found. CycloneDX recommends listing the "
                    "tool(s) used to generate the SBOM."
                ),
            )
        )


def _check_spdx_document(doc: SBOMDocument, issues: list[ValidationIssue]) -> None:
    """Validate SPDX-specific required fields."""
    if not doc.spec_version:
        issues.append(
            ValidationIssue(
                severity="ERROR",
                code="SPDX_MISSING_VERSION",
                message="SPDX SBOM is missing spdxVersion field.",
            )
        )

    if not doc.document_namespace:
        issues.append(
            ValidationIssue(
                severity="ERROR",
                code="SPDX_MISSING_NAMESPACE",
                message="SPDX SBOM is missing documentNamespace field (required by spec).",
            )
        )

    if not doc.document_name:
        issues.append(
            ValidationIssue(
                severity="ERROR",
                code="SPDX_MISSING_DOC_NAME",
                message="SPDX SBOM is missing DocumentName field (required by spec).",
            )
        )
