"""Unit tests for compliance checking modules."""

import pytest
from app.core.compliance import check_ntia, check_bsi, check_fsct, check_oct
from app.core.compliance.record import compliance_score, raw_compliance_score, RecordTier, _req, _add, _opt


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

    def test_ntia_elements_are_9(self, cdx_json_doc):
        result = check_ntia(cdx_json_doc)
        assert len(result.elements) == 9

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

    # --- BUG-01: compliance_score must never exceed 10.0 ---

    def test_compliance_score_clamped_at_10(self):
        """FSCT aspirational scores (12, 15) must not push overall above 10.0."""
        records = [_req(f"r{i}", 10.0, "doc", "", "", "") for i in range(8)]
        records.append(_req("asp1", 15.0, "doc", "", "", "aspirational"))
        records.append(_req("asp2", 12.0, "doc", "", "", "recommended"))
        result = compliance_score(records)
        assert result <= 10.0

    def test_raw_compliance_score_can_exceed_10(self):
        """raw_compliance_score returns the unclamped value."""
        records = [_req("a", 15.0, "doc", "", "", "")]
        assert raw_compliance_score(records) == pytest.approx(15.0)

    def test_compliance_score_is_clamped_raw_is_not(self):
        records = [_req("a", 15.0, "doc", "", "", "")]
        assert compliance_score(records) == pytest.approx(10.0)
        assert raw_compliance_score(records) == pytest.approx(15.0)


class TestFSCTv4:
    # --- BUG-02: FSCT three-tier checksum ---

    def test_fsct_strong_checksum_scores_12(self):
        """Component with SHA-256 hash should produce raw checksum score 12.0."""
        from app.core.parser import SBOMDocument, Component
        comp = Component(
            name="lib", version="1.0",
            hashes={"SHA-256": "abc123"},
            licenses=["MIT"],
        )
        doc = SBOMDocument(
            format="cyclonedx", spec_version="1.4",
            created="2024-01-01T00:00:00Z", authors=["Tool: test"],
            components=[comp],
        )
        result = check_fsct(doc)
        checksum_records = [r for r in result.records if r.check_key == "fsct_comp_checksum"]
        assert len(checksum_records) == 1
        assert checksum_records[0].score == pytest.approx(12.0)

    def test_fsct_weak_checksum_scores_10(self):
        from app.core.parser import SBOMDocument, Component
        comp = Component(
            name="lib", version="1.0",
            hashes={"MD5": "abc123"},
            licenses=["MIT"],
        )
        doc = SBOMDocument(
            format="cyclonedx", spec_version="1.4",
            created="2024-01-01T00:00:00Z", authors=["Tool: test"],
            components=[comp],
        )
        result = check_fsct(doc)
        checksum_records = [r for r in result.records if r.check_key == "fsct_comp_checksum"]
        assert checksum_records[0].score == pytest.approx(10.0)

    def test_fsct_no_checksum_scores_0(self):
        from app.core.parser import SBOMDocument, Component
        comp = Component(name="lib", version="1.0", licenses=["MIT"])
        doc = SBOMDocument(
            format="cyclonedx", spec_version="1.4",
            created="2024-01-01T00:00:00Z", authors=["Tool: test"],
            components=[comp],
        )
        result = check_fsct(doc)
        checksum_records = [r for r in result.records if r.check_key == "fsct_comp_checksum"]
        assert checksum_records[0].score == pytest.approx(0.0)

    def test_fsct_raw_score_exposed(self, cdx_json_doc):
        result = check_fsct(cdx_json_doc)
        assert hasattr(result, "raw_score")
        assert result.raw_score >= 0.0
        assert result.overall_score <= 10.0

    def test_fsct_overall_score_never_exceeds_10(self, cdx_json_doc):
        result = check_fsct(cdx_json_doc)
        assert result.overall_score <= 10.0


class TestOCTv4:
    # --- COMP-01: OCT should now have more checks ---

    def test_oct_has_new_checks(self, spdx_tv_doc):
        result = check_oct(spdx_tv_doc)
        keys = {r.check_key for r in result.records}
        assert "oct_sbom_organization" in keys
        assert "oct_sbom_tool" in keys
        assert "oct_sbom_comment" in keys
        assert "oct_sbom_spdxid" in keys
        assert "oct_human_format" in keys
        assert "oct_delivery_method" in keys
        assert "oct_delivery_timing" in keys
        assert "oct_sbom_scope" in keys

    def test_oct_old_creator_key_gone(self, spdx_tv_doc):
        """oct_creator should no longer appear — replaced by org+tool."""
        result = check_oct(spdx_tv_doc)
        keys = {r.check_key for r in result.records}
        assert "oct_creator" not in keys

    def test_oct_delivery_placeholders_are_additional(self, spdx_tv_doc):
        result = check_oct(spdx_tv_doc)
        for key in ("oct_delivery_method", "oct_delivery_timing", "oct_sbom_scope"):
            rec = next(r for r in result.records if r.check_key == key)
            assert rec.tier == RecordTier.ADDITIONAL
            assert rec.applicable is False

    def test_oct_sha256_detection_normalised(self):
        """Various SHA-256 alias spellings should all be detected."""
        from app.core.parser import SBOMDocument, Component
        for algo in ("SHA-256", "sha256", "SHA_256", "SHA256"):
            comp = Component(name="p", version="1.0", hashes={algo: "abc"})
            doc = SBOMDocument(format="spdx", spec_version="SPDX-2.3",
                               components=[comp], file_format="tv")
            result = check_oct(doc)
            hash_rec = next((r for r in result.records if r.check_key == "oct_pkg_hash"), None)
            if hash_rec:
                assert hash_rec.score == pytest.approx(10.0), f"Failed for algo: {algo}"

    def test_oct_blake3_256_not_accepted_as_sha256(self):
        """BLAKE3-256 must NOT be counted as SHA-256."""
        from app.core.parser import SBOMDocument, Component
        comp = Component(name="p", version="1.0", hashes={"BLAKE3-256": "abc"})
        doc = SBOMDocument(format="spdx", spec_version="SPDX-2.3",
                           components=[comp], file_format="tv")
        result = check_oct(doc)
        hash_rec = next((r for r in result.records if r.check_key == "oct_pkg_hash"), None)
        if hash_rec:
            assert hash_rec.score == pytest.approx(0.0)


class TestBSIv4:
    # --- COMP-03: BSI v1.1 SPDX floor fix ---

    def test_bsi_v11_accepts_spdx_22(self):
        from app.core.parser import SBOMDocument
        doc = SBOMDocument(format="spdx", spec_version="SPDX-2.2",
                           components=[], created="2024-01-01T00:00:00Z")
        result = check_bsi(doc, version="v1.1")
        spec_rec = next(r for r in result.records if r.check_key == "bsi_spec_version")
        assert spec_rec.score == pytest.approx(10.0)

    def test_bsi_v11_accepts_spdx_23(self):
        from app.core.parser import SBOMDocument
        doc = SBOMDocument(format="spdx", spec_version="SPDX-2.3",
                           components=[], created="2024-01-01T00:00:00Z")
        result = check_bsi(doc, version="v1.1")
        spec_rec = next(r for r in result.records if r.check_key == "bsi_spec_version")
        assert spec_rec.score == pytest.approx(10.0)

    # --- ROBUST-04: BSI node set completeness ---

    def test_bsi_dep_resolution_no_false_positives(self):
        """All dep targets should resolve even when graph.nodes is incomplete."""
        from app.core.parser import SBOMDocument, Component
        comp_a = Component(name="a", version="1.0", bom_ref="ref-a")
        comp_b = Component(name="b", version="1.0", bom_ref="ref-b")
        doc = SBOMDocument(
            format="cyclonedx", spec_version="1.4",
            created="2024-01-01T00:00:00Z",
            components=[comp_a, comp_b],
            dependency_graph={
                "nodes": ["ref-a"],   # intentionally incomplete node list
                "edges": [("ref-a", "ref-b", "DEPENDS_ON")],
                "orphans": [], "is_complete": True,
            },
        )
        result = check_bsi(doc, version="v1.1")
        dep_rec = next((r for r in result.records if r.check_key == "bsi_dependency_resolution"), None)
        if dep_rec:
            # ref-b is in components even if not in graph.nodes → no broken edge
            assert dep_rec.score > 0.0, "False positive: ref-b should resolve via components"


class TestNTIAv4:
    # --- ROBUST-06: NTIA completeness fallback ---

    def test_ntia_completeness_declared_satisfies_dependency_check(self):
        """is_complete=True should satisfy NTIA dependency requirement even with 0 edges."""
        from app.core.parser import SBOMDocument, Component
        comp = Component(name="lib", version="1.0", purl="pkg:npm/lib@1.0",
                         supplier="Acme Corp")
        doc = SBOMDocument(
            format="cyclonedx", spec_version="1.4",
            created="2024-01-01T00:00:00Z",
            authors=["Tool: test-tool"],
            components=[comp],
            dependency_graph={"nodes": [], "edges": [], "orphans": [], "is_complete": True},
        )
        result = check_ntia(doc)
        dep_elem = next(e for e in result.elements if e.element_name == "Dependency Relationships")
        assert dep_elem.compliant is True
