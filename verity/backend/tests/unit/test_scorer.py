"""Unit tests for the quality scoring engine."""

import pytest
from app.core.scorer import score, _grade, _boolean, _per_component, _tiered


class TestHelpers:
    def test_grade_boundaries(self):
        # A: >=9.0, B: [8.0,9.0), C: [7.0,8.0), D: [5.0,7.0), F: <5.0
        assert _grade(9.5) == "A"
        assert _grade(9.0) == "A"
        assert _grade(8.9) == "B"
        assert _grade(8.0) == "B"
        assert _grade(7.9) == "C"
        assert _grade(7.0) == "C"
        assert _grade(6.9) == "D"
        assert _grade(6.0) == "D"
        assert _grade(4.9) == "F"
        assert _grade(0.0) == "F"

    def test_boolean(self):
        assert _boolean(True) == 10.0
        assert _boolean(False) == 0.0

    def test_per_component_all(self):
        assert _per_component(5, 5) == 10.0

    def test_per_component_none(self):
        assert _per_component(0, 5) == 0.0

    def test_per_component_partial(self):
        # 4/5 = 80% → 8.0
        assert _per_component(4, 5) == pytest.approx(8.0, abs=0.01)

    def test_per_component_empty(self):
        assert _per_component(0, 0) == 0.0

    def test_tiered(self):
        assert _tiered(0) == 0.0
        assert _tiered(1) == 5.0
        assert _tiered(2) == 10.0
        assert _tiered(3) == 10.0


class TestScorer:
    def test_score_returns_quality_score(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        assert 0.0 <= qs.overall_score <= 10.0
        assert qs.grade in ("A", "B", "C", "D", "F")
        assert len(qs.categories) > 0

    def test_score_has_seven_categories(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        assert len(qs.categories) == 7

    def test_score_spdx_doc(self, spdx_tv_doc):
        qs = score(spdx_tv_doc)
        assert 0.0 <= qs.overall_score <= 10.0

    def test_categories_have_features(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        for cat in qs.categories:
            assert cat.weight > 0
            assert 0.0 <= cat.score <= 10.0
            assert len(cat.features) > 0

    def test_all_features_are_scored_or_na(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        for cat in qs.categories:
            for feat in cat.features:
                if feat.applicable:
                    assert 0.0 <= feat.score <= 10.0

    def test_well_formed_sbom_scores_above_3(self, cdx_json_doc):
        """A minimal but well-formed SBOM should score above 3."""
        qs = score(cdx_json_doc)
        assert qs.overall_score >= 3.0

    def test_grade_consistent_with_score(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        assert qs.grade == _grade(qs.overall_score)
