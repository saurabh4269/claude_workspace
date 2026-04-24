"""
Three-tier compliance record model for Verity.

Mirrors the SHALL/SHOULD/MAY structure used in BSI TR-03183-2 and other standards.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class RecordTier(str, Enum):
    REQUIRED = "required"      # SHALL — always in score denominator
    ADDITIONAL = "additional"  # SHOULD — in denominator only if applicable
    OPTIONAL = "optional"      # MAY — never in score denominator


@dataclass
class ComplianceRecord:
    check_key: str
    tier: RecordTier
    score: float          # 0.0, 5.0, or 10.0
    applicable: bool      # False = N/A for this format/version, exclude from denominator
    subject_id: str       # component id or "document"
    found_value: str      # what was found in the SBOM
    expected: str         # what was expected
    detail: str           # human-readable explanation

    def to_dict(self) -> dict:
        return {
            "check_key": self.check_key,
            "tier": self.tier.value,
            "score": self.score,
            "applicable": self.applicable,
            "subject_id": self.subject_id,
            "found_value": self.found_value,
            "expected": self.expected,
            "detail": self.detail,
        }


def raw_compliance_score(records: list[ComplianceRecord]) -> float:
    """
    Arithmetic mean of all scored records — may exceed 10.0 for standards
    (e.g. FSCT) that award aspirational scores above 10.
    """
    scored = [
        r for r in records
        if r.tier != RecordTier.OPTIONAL and r.applicable
    ]
    if not scored:
        return 0.0
    return round(sum(r.score for r in scored) / len(scored), 2)


def compliance_score(records: list[ComplianceRecord]) -> float:
    """
    Compliance score clamped to 0.0–10.0.

    Only REQUIRED records are always included. ADDITIONAL records are included
    only when applicable=True. OPTIONAL records are never included.
    Use raw_compliance_score() to obtain the unclamped value (useful for
    standards that award aspirational scores above 10.0).
    """
    return min(raw_compliance_score(records), 10.0)


def _req(
    check_key: str,
    score: float,
    subject_id: str,
    found_value: str,
    expected: str,
    detail: str,
) -> ComplianceRecord:
    return ComplianceRecord(
        check_key=check_key,
        tier=RecordTier.REQUIRED,
        score=score,
        applicable=True,
        subject_id=subject_id,
        found_value=found_value,
        expected=expected,
        detail=detail,
    )


def _add(
    check_key: str,
    score: float,
    applicable: bool,
    subject_id: str,
    found_value: str,
    expected: str,
    detail: str,
) -> ComplianceRecord:
    return ComplianceRecord(
        check_key=check_key,
        tier=RecordTier.ADDITIONAL,
        score=score,
        applicable=applicable,
        subject_id=subject_id,
        found_value=found_value,
        expected=expected,
        detail=detail,
    )


def _opt(
    check_key: str,
    score: float,
    subject_id: str,
    found_value: str,
    expected: str,
    detail: str,
) -> ComplianceRecord:
    return ComplianceRecord(
        check_key=check_key,
        tier=RecordTier.OPTIONAL,
        score=score,
        applicable=True,
        subject_id=subject_id,
        found_value=found_value,
        expected=expected,
        detail=detail,
    )
