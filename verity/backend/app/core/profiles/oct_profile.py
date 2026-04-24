"""
OpenChain Telco v1.1 scored profile (SPDX-only).

Weights derived from the OpenChain Telco SBOM Guide v1.1, published by
the OpenChain Project under CC BY 4.0, May 2024.

For non-SPDX SBOMs, most features will be N/A and the profile score will
reflect only those applicable dimensions.
"""

from app.core.scorer import QualityScore
from app.core.profiles.base import ProfileScore, _score_profile

_OCT_WEIGHTS: dict[str, float] = {
    "sbom_creation_timestamp":  0.10,
    "sbom_namespace":           0.10,
    "sbom_authors":             0.08,
    "sbom_has_data_license":    0.08,
    "comp_with_name":           0.10,
    "comp_with_version":        0.10,
    "comp_with_supplier":       0.10,
    "comp_with_checksums":      0.10,
    "comp_has_license":         0.12,
    "comp_with_valid_purl":     0.12,
}


def score_oct_profile(qs: QualityScore) -> ProfileScore:
    return _score_profile(qs, "OpenChain Telco v1.1", _OCT_WEIGHTS)
