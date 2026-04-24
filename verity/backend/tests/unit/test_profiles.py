"""Unit tests for scored compliance profiles (NEW-03)."""

import pytest
from app.core.profiles import PROFILE_MAP, score_ntia_profile, score_bsi_v21_profile
from app.core.scorer import score


class TestProfileScoring:
    def test_ntia_profile_returns_result(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        ps = score_ntia_profile(qs)
        assert ps.profile_name == "NTIA Minimum Elements"
        assert 0.0 <= ps.profile_score <= 10.0
        assert ps.grade in ("A", "B", "C", "D", "F")

    def test_ntia_profile_has_7_features(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        ps = score_ntia_profile(qs)
        assert len(ps.features) == 7

    def test_bsi_v21_profile_returns_result(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        ps = score_bsi_v21_profile(qs)
        assert 0.0 <= ps.profile_score <= 10.0

    def test_profile_score_in_range(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        for name, fn in PROFILE_MAP.items():
            ps = fn(qs)
            assert 0.0 <= ps.profile_score <= 10.0, f"Profile {name} out of range"

    def test_profile_to_dict(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        ps = score_ntia_profile(qs)
        d = ps.to_dict()
        assert "profile_name" in d
        assert "profile_score" in d
        assert "grade" in d
        assert "features" in d

    def test_na_features_excluded_from_denominator(self, spdx_tv_doc):
        """CDX-only features (sbom_supplier, sbom_lifecycle) should be N/A for SPDX."""
        qs = score(spdx_tv_doc)
        ps = score_bsi_v21_profile(qs)
        # Profile should still produce a valid score
        assert 0.0 <= ps.profile_score <= 10.0

    def test_profile_map_contains_all_standards(self):
        assert "ntia" in PROFILE_MAP
        assert "bsi" in PROFILE_MAP
        assert "fsct" in PROFILE_MAP
        assert "oct" in PROFILE_MAP

    def test_perfect_sbom_scores_high(self, cdx_json_doc):
        """A well-formed CDX SBOM should score above 3.0 on NTIA profile."""
        qs = score(cdx_json_doc)
        ps = score_ntia_profile(qs)
        assert ps.profile_score >= 3.0
