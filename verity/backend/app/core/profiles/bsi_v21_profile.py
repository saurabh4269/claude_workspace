"""
BSI TR-03183-2 v2.1 scored profile.

Weights reflect the SHALL requirements from BSI TR-03183-2, published by the
German Federal Office for Information Security (BSI), August 2025.
"""

from app.core.scorer import QualityScore
from app.core.profiles.base import ProfileScore, _score_profile

_BSI_V21_WEIGHTS: dict[str, float] = {
    # Structural
    "spec_version_supported":   0.05,
    "schema_valid":             0.05,
    # Provenance
    "sbom_creation_timestamp":  0.08,
    "sbom_namespace":           0.07,
    # Integrity
    "comp_with_strong_checksum": 0.15,
    "sbom_signature":           0.05,
    # Identification
    "comp_with_name":           0.08,
    "comp_with_version":        0.08,
    # Completeness
    "comp_with_dependencies":   0.10,
    "primary_component":        0.05,
    # Licensing
    "comp_has_license":         0.10,
    "comp_has_declared_license": 0.07,
    # Vulnerability
    "comp_with_valid_purl":     0.07,
}


def score_bsi_v21_profile(qs: QualityScore) -> ProfileScore:
    return _score_profile(qs, "BSI TR-03183-2 v2.1", _BSI_V21_WEIGHTS)
