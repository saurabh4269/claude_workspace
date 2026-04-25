"""
FSCT v3 scored profile.

Weights derived from FSCT (Framing Software Component Transparency),
CISA / Linux Foundation, v3 (freely available public document).

FSCT unique identifiers (PURL, CPE, SWHID, SWID, OmniBOR) map to
comp_with_valid_purl as the primary quality indicator. comp_with_dependencies
replaces the removed sbom_dependency_graph feature.
"""

from app.core.scorer import QualityScore
from app.core.profiles.base import ProfileScore, _score_profile

_FSCT_WEIGHTS: dict[str, float] = {
    "comp_with_name":           0.12,
    "comp_with_version":        0.12,
    "comp_with_supplier":       0.10,
    "comp_with_valid_purl":     0.12,   # FSCT unique identifier — PURL is primary
    "comp_with_checksums":      0.10,
    "comp_has_license":         0.12,
    "sbom_authors":             0.08,
    "sbom_creation_timestamp":  0.08,
    "comp_with_dependencies":   0.08,   # FSCT relationship completeness
    "primary_component":        0.08,
}


def score_fsct_profile(qs: QualityScore) -> ProfileScore:
    return _score_profile(qs, "FSCT v3", _FSCT_WEIGHTS)
