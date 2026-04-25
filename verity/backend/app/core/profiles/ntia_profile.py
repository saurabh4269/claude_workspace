"""
NTIA Minimum Elements scored profile.

Weights derived from the relative importance assigned to each element in
"The Minimum Elements For a Software Bill of Materials (SBOM)",
US Department of Commerce / NTIA, July 2021 (public domain).

The seven required elements map to existing QualityScore features:
  1. Supplier Name            → comp_with_supplier
  2. Component Name           → comp_with_name
  3. Version of Component     → comp_with_version
  4. Other Unique Identifiers → comp_with_valid_purl + comp_with_valid_cpe (split)
  5. Dependency Relationships → comp_with_dependencies
  6. Author of SBOM Data      → sbom_authors
  7. Timestamp                → sbom_creation_timestamp

PURL and CPE are given equal sub-weight (0.10 each) for element 4, reflecting that
both are valid NTIA unique identifiers covering different vulnerability databases.
"""

from app.core.scorer import QualityScore
from app.core.profiles.base import ProfileScore, _score_profile

# Feature weights for the NTIA profile (must sum to 1.0)
_NTIA_WEIGHTS: dict[str, float] = {
    "comp_with_supplier":       0.15,
    "comp_with_name":           0.15,
    "comp_with_version":        0.15,
    "comp_with_valid_purl":     0.10,   # NTIA element 4 — PURL half
    "comp_with_valid_cpe":      0.10,   # NTIA element 4 — CPE half
    "comp_with_dependencies":   0.15,   # NTIA element 5 — dependency relationships
    "sbom_authors":             0.10,
    "sbom_creation_timestamp":  0.10,
}


def score_ntia_profile(qs: QualityScore) -> ProfileScore:
    return _score_profile(qs, "NTIA Minimum Elements", _NTIA_WEIGHTS)
