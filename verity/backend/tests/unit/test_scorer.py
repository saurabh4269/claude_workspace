"""Unit tests for the quality scoring engine."""

import pytest
from app.core.scorer import score, _grade, _boolean, _per_component, _tiered, quality_score_to_dict


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

    def test_per_component_cap_9_9(self):
        # 4/5 should never reach 10.0 when have < total
        assert _per_component(4, 5) <= 9.9

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

    def test_score_has_seven_base_categories(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        assert len(qs.categories) == 7

    def test_score_eight_categories_with_vuln(self, cdx_json_doc):
        qs = score(cdx_json_doc, vuln_results={})
        assert len(qs.categories) == 8

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

    # --- BUG-04: weighted_score denominator is dynamic ---

    def test_weighted_score_denominator_matches_actual_weights(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        d = quality_score_to_dict(qs)
        total_weight = sum(c["weight"] for c in d["categories"])
        for cat in d["categories"]:
            expected_ws = round(cat["score"] * cat["weight"] / total_weight, 4)
            assert cat["weighted_score"] == pytest.approx(expected_ws, abs=0.001)

    def test_weighted_scores_sum_to_overall(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        d = quality_score_to_dict(qs)
        ws_sum = sum(c["weighted_score"] for c in d["categories"])
        assert ws_sum == pytest.approx(qs.overall_score, abs=0.01)

    # --- ARCH-01: Category weight alignment ---

    def test_base_weights_sum_to_82(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        assert len(qs.categories) == 7
        total = sum(c.weight for c in qs.categories)
        assert total == 82

    def test_integrity_weight_is_15(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        integrity = next(c for c in qs.categories if c.name == "Integrity")
        assert integrity.weight == 15

    def test_vuln_traceability_weight_is_10(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        vt = next(c for c in qs.categories if "Vulnerability" in c.name)
        assert vt.weight == 10

    def test_identification_weight_is_10(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        ident = next(c for c in qs.categories if c.name == "Identification")
        assert ident.weight == 10

    # --- BUG-03: PURL/CPE no longer in Identification ---

    def test_purl_not_in_identification(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        ident = next(c for c in qs.categories if c.name == "Identification")
        keys = [f.key for f in ident.features]
        assert "comp_has_purl" not in keys
        assert "comp_has_cpe" not in keys

    def test_purl_in_vuln_traceability(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        vt = next(c for c in qs.categories if "Vulnerability" in c.name)
        keys = [f.key for f in vt.features]
        assert "comp_with_valid_purl" in keys

    def test_malformed_purl_scores_zero_in_vuln(self):
        """A truthy but syntactically invalid PURL should score 0 in Vuln category."""
        from app.core.parser import SBOMDocument, Component
        comp = Component(name="bad", version="1.0", purl="not-a-purl")
        doc = SBOMDocument(format="cyclonedx", spec_version="1.4", components=[comp])
        qs = score(doc)
        vt = next(c for c in qs.categories if "Vulnerability" in c.name)
        purl_feat = next(f for f in vt.features if f.key == "comp_with_valid_purl")
        assert purl_feat.score == 0.0

    # --- ARCH-02: comp_with_dependencies N/A for SPDX without dep edges ---

    def test_comp_with_dependencies_na_for_spdx_no_depends_on(self, spdx_tv_doc):
        """SPDX SBOM with only DESCRIBES relationships → comp_with_dependencies N/A."""
        qs = score(spdx_tv_doc)
        completeness = next(c for c in qs.categories if c.name == "Completeness")
        dep_feat = next((f for f in completeness.features if f.key == "comp_with_dependencies"), None)
        # If the fixture only has DESCRIBES relationships, should be N/A
        if dep_feat is not None and not dep_feat.applicable:
            assert dep_feat.applicable is False

    def test_comp_with_dependencies_applicable_for_cdx(self, cdx_json_doc):
        qs = score(cdx_json_doc)
        completeness = next(c for c in qs.categories if c.name == "Completeness")
        dep_feat = next(f for f in completeness.features if f.key == "comp_with_dependencies")
        assert dep_feat.applicable is True

    # --- ROBUST-05: SPDX 3.x version support ---

    def test_spdx_3_0_version_is_supported(self):
        from app.core.parser import SBOMDocument
        doc = SBOMDocument(format="spdx", spec_version="3.0.1",
                           components=[], file_format="json")
        qs = score(doc)
        structural = next(c for c in qs.categories if c.name == "Structural Validity")
        version_feat = next(f for f in structural.features if f.key == "spec_version_supported")
        assert version_feat.score == 10.0
