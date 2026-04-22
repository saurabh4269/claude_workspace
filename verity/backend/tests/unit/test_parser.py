"""Unit tests for the SBOM parser."""

import pytest
from app.core.parser import parse, ParseError


class TestCDXJsonParsing:
    def test_parse_returns_document(self, cdx_json_doc):
        assert cdx_json_doc is not None

    def test_format_detected(self, cdx_json_doc):
        assert cdx_json_doc.format == "cyclonedx"

    def test_spec_version(self, cdx_json_doc):
        assert cdx_json_doc.spec_version == "1.4"

    def test_components_loaded(self, cdx_json_doc):
        assert len(cdx_json_doc.components) == 2

    def test_component_fields(self, cdx_json_doc):
        lodash = next(c for c in cdx_json_doc.components if c.name == "lodash")
        assert lodash.version == "4.17.21"
        assert lodash.purl == "pkg:npm/lodash@4.17.21"
        assert "MIT" in lodash.licenses
        assert lodash.supplier is not None

    def test_dependency_graph_present(self, cdx_json_doc):
        graph = cdx_json_doc.dependency_graph
        assert graph is not None

    def test_dependency_graph_has_nodes(self, cdx_json_doc):
        graph = cdx_json_doc.dependency_graph
        assert isinstance(graph, dict)
        assert len(graph.get("nodes", [])) > 0

    def test_timestamp_parsed(self, cdx_json_doc):
        assert cdx_json_doc.created is not None

    def test_tools_list(self, cdx_json_doc):
        assert len(cdx_json_doc.tools) > 0


class TestSPDXTagValueParsing:
    def test_parse_spdx_tv(self, spdx_tv_doc):
        assert spdx_tv_doc is not None

    def test_format_detected(self, spdx_tv_doc):
        assert spdx_tv_doc.format == "spdx"

    def test_spec_version_contains_2_3(self, spdx_tv_doc):
        assert "2.3" in spdx_tv_doc.spec_version

    def test_components_loaded(self, spdx_tv_doc):
        assert len(spdx_tv_doc.components) == 2

    def test_component_purl_extracted(self, spdx_tv_doc):
        lodash = next(c for c in spdx_tv_doc.components if c.name == "lodash")
        assert lodash.purl == "pkg:npm/lodash@4.17.21"

    def test_data_license(self, spdx_tv_doc):
        assert spdx_tv_doc.data_license == "CC0-1.0"

    def test_licenses_extracted(self, spdx_tv_doc):
        lodash = next(c for c in spdx_tv_doc.components if c.name == "lodash")
        assert "MIT" in lodash.licenses


class TestParseErrors:
    def test_empty_input_raises(self):
        with pytest.raises(ParseError):
            parse("", filename="test.json")

    def test_garbage_input_raises(self):
        with pytest.raises(ParseError):
            parse("this is not an sbom at all", filename="test.json")

    def test_unknown_extension_handled(self):
        """Unknown extension falls back to JSON parsing attempt."""
        with pytest.raises(ParseError):
            parse("not json", filename="test.unknown")


class TestDependencyGraph:
    def test_graph_nodes_dict(self, cdx_json_doc):
        graph = cdx_json_doc.dependency_graph
        assert isinstance(graph, dict)
        nodes = graph.get("nodes", [])
        assert "pkg:npm/lodash@4.17.21" in nodes

    def test_graph_edges_list(self, cdx_json_doc):
        graph = cdx_json_doc.dependency_graph
        assert "edges" in graph
        assert isinstance(graph["edges"], list)

    def test_graph_has_orphans_key(self, cdx_json_doc):
        graph = cdx_json_doc.dependency_graph
        assert "orphans" in graph

    def test_graph_has_is_complete(self, cdx_json_doc):
        graph = cdx_json_doc.dependency_graph
        assert "is_complete" in graph
