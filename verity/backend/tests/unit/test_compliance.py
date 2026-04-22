"""Unit tests for compliance checking modules."""

import pytest
from app.core.compliance import check_ntia, check_bsi, check_fsct, check_oct
from app.core.compliance.record import compliance_score, RecordTier, _req, _add, _opt


class TestNTIA:
    def test_check_ntia_returns_result(self, cdx_json_doc):
        result = check_ntia(cdx_json_doc)
        assert result is not None
        assert hasattr(result, "overall_compliant")
        assert hasattr(result, "overall_score")
        assert isinstance(result.elements, list)

    def test_ntia_score_in_range(self, cdx_json_doc):
        result = check_ntia(cdx_json_doc)
        assert 0.0 <= result.overall_score <= 10.0

    def test_ntia_well_formed_passes(self, cdx_json_doc):
        """A well-formed CDX doc should score > 0."""
        result = check_ntia(cdx_json_doc)
        assert result.overall_score > 0.0

    def test_ntia_elements_are_7(self, cdx_json_doc):
        result = check_ntia(cdx_json_doc)
        assert len(result.elements) == 7

    def test_ntia_to_dict(self, cdx_json_doc):
        d = check_ntia(cdx_json_doc).to_dict()
        assert "overall_compliant" in d
        assert "overall_score" in d
        assert "elements" in d


class TestBSI:
    def test_check_bsi_returns_result(self, cdx_json_doc):
        result = check_bsi(cdx_json_doc)
        assert result is not None
        assert hasattr(result, "compliant")
        assert hasattr(result, "overall_score")
        assert hasattr(result, "records")

    def test_bsi_score_in_range(self, cdx_json_doc):
        result = check_bsi(cdx_json_doc)
        assert 0.0 <= result.overall_score <= 10.0

    def test_bsi_versions(self, cdx_json_doc):
        for version in ("v1.1", "v2.0", "v2.1"):
            result = check_bsi(cdx_json_doc, version=version)
            assert result.overall_score >= 0.0

    def test_bsi_to_dict_has_records(self, cdx_json_doc):
        d = check_bsi(cdx_json_doc).to_dict()
        assert "records" in d
        assert isinstance(d["records"], list)


class TestFSCT:
    def test_check_fsct_returns_result(self, cdx_json_doc):
        result = check_fsct(cdx_json_doc)
        assert result is not None
        assert hasattr(result, "overall_score")
        assert hasattr(result, "records")

    def test_fsct_cdx_score_in_range(self, cdx_json_doc):
        result = check_fsct(cdx_json_doc)
        assert 0.0 <= result.overall_score <= 10.0

    def test_fsct_spdx(self, spdx_tv_doc):
        result = check_fsct(spdx_tv_doc)
        assert 0.0 <= result.overall_score <= 10.0


class TestOCT:
    def test_oct_fails_on_non_spdx(self, cdx_json_doc):
        result = check_oct(cdx_json_doc)
        assert result.spdx_only_fail is True
        assert result.overall_score == 0.0

    def test_oct_passes_spdx(self, spdx_tv_doc):
        result = check_oct(spdx_tv_doc)
        assert result.spdx_only_fail is False
        assert result.overall_score >= 0.0

    def test_oct_to_dict(self, spdx_tv_doc):
        d = check_oct(spdx_tv_doc).to_dict()
        assert "spdx_only_fail" in d
        assert "records" in d


class TestComplianceRecord:
    def test_compliance_score_all_pass(self):
        r1 = _req("a", 1.0, "A", "", "", "pass")
        r2 = _req("b", 1.0, "B", "", "", "pass")
        assert compliance_score([r1, r2]) == pytest.approx(1.0)

    def test_compliance_score_all_fail(self):
        r1 = _req("a", 0.0, "A", "", "", "fail")
        r2 = _req("b", 0.0, "B", "", "", "fail")
        assert compliance_score([r1, r2]) == pytest.approx(0.0)

    def test_compliance_score_mixed(self):
        r1 = _req("a", 1.0, "A", "", "", "pass")
        r2 = _req("b", 0.0, "B", "", "", "fail")
        assert compliance_score([r1, r2]) == pytest.approx(0.5)

    def test_optional_excluded_from_score(self):
        r1 = _req("a", 1.0, "A", "", "", "pass")
        r2 = _opt("b", 0.0, "B", "", "", "fail")
        assert compliance_score([r1, r2]) == pytest.approx(1.0)
