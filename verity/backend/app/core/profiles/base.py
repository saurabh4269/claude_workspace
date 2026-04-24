"""
Scored compliance profiles for Verity.

A profile produces a continuous 0–10 quality score for a specific compliance
standard, using the existing QualityScore feature results as inputs. This is
distinct from the pass/fail compliance checkers in app.core.compliance — it
answers "how well does this SBOM score on what standard X cares about?" rather
than "does it pass standard X?".

Each profile maps feature keys to profile-specific weights. Features absent
from the profile (or not applicable for the SBOM format) are excluded from the
denominator, just like N/A features in the main scorer.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.scorer import QualityScore, FeatureResult, _grade


@dataclass
class ProfileScore:
    profile_name: str
    profile_score: float    # 0.0–10.0
    grade: str              # A/B/C/D/F
    features: list[dict]    # list of {key, score, applicable, weight, detail}

    def to_dict(self) -> dict:
        return {
            "profile_name": self.profile_name,
            "profile_score": self.profile_score,
            "grade": self.grade,
            "features": self.features,
        }


def _score_profile(
    qs: QualityScore,
    profile_name: str,
    feature_weights: dict[str, float],
) -> ProfileScore:
    """
    Derive a profile score from an existing QualityScore.

    feature_weights: {feature_key: weight_in_profile}
    Features not found in the QualityScore (N/A or absent) are excluded.
    """
    # Build a flat lookup of all feature results across all categories
    all_features: dict[str, FeatureResult] = {}
    for cat in qs.categories:
        for feat in cat.features:
            all_features[feat.key] = feat

    scored_features = []
    total_weight = 0.0
    weighted_sum = 0.0

    for key, weight in feature_weights.items():
        feat = all_features.get(key)
        if feat is None or not feat.applicable:
            # Feature absent or N/A — exclude from denominator
            scored_features.append({
                "key": key,
                "score": None,
                "applicable": False,
                "weight": weight,
                "detail": "N/A for this SBOM format or not evaluated",
            })
            continue
        total_weight += weight
        weighted_sum += feat.score * weight
        scored_features.append({
            "key": key,
            "score": feat.score,
            "applicable": True,
            "weight": weight,
            "detail": feat.detail,
        })

    if total_weight <= 0:
        profile_score = 0.0
    else:
        profile_score = round(weighted_sum / total_weight, 2)

    return ProfileScore(
        profile_name=profile_name,
        profile_score=profile_score,
        grade=_grade(profile_score),
        features=scored_features,
    )
