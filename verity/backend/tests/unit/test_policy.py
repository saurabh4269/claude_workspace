"""Unit tests for the policy engine."""

import pytest
from app.core.policy import evaluate_policy, parse_policy, _compare, _get_metric


SAMPLE_POLICY_YAML = """
name: Test Policy
rules:
  - id: no-gpl
    type: license_denylist
    description: No GPL licenses
    action: fail
    licenses: ["GPL-2.0-only", "GPL-3.0-only"]
  - id: quality-threshold
    type: threshold
    description: Quality must be >= 5
    action: warn
    metric: quality_score
    operator: lt
    value: 5.0
  - id: no-log4j
    type: component_denylist
    description: No log4j
    action: fail
    patterns: ["*log4j*"]
"""

SCAN_DATA_CLEAN = {
    "quality_score": 7.5,
    "risk_score": 3.0,
    "risk_level": "MEDIUM",
    "components": [
        {
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "licenses": ["MIT"],
            "vulnerabilities": [],
        }
    ],
}

SCAN_DATA_VIOLATED = {
    "quality_score": 2.0,
    "risk_score": 8.0,
    "risk_level": "HIGH",
    "components": [
        {
            "name": "log4j-core",
            "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "licenses": ["Apache-2.0"],
            "vulnerabilities": [
                {"id": "CVE-2021-44228", "severity": "CRITICAL", "cvss_score": 10.0,
                 "epss_score": 0.97, "in_kev": True}
            ],
        },
        {
            "name": "bad-lib",
            "version": "1.0",
            "purl": "pkg:npm/bad-lib@1.0",
            "licenses": ["GPL-2.0-only"],
            "vulnerabilities": [],
        },
    ],
}


class TestParsePolicy:
    def test_parse_valid_yaml(self):
        rules = parse_policy(SAMPLE_POLICY_YAML)
        assert len(rules) == 3

    def test_parse_empty_rules(self):
        yaml = "name: Empty\nrules: []"
        rules = parse_policy(yaml)
        assert rules == []

    def test_parse_invalid_yaml_returns_empty(self):
        rules = parse_policy("this: is: {broken yaml")
        assert rules == []

    def test_parse_non_dict_returns_empty(self):
        rules = parse_policy("- just a list")
        assert rules == []


class TestEvaluatePolicy:
    def test_pass_when_no_violations(self):
        rules = parse_policy(SAMPLE_POLICY_YAML)
        result = evaluate_policy(rules, SCAN_DATA_CLEAN)
        # quality is 7.5 >= 5 so threshold not triggered; no GPL; no log4j
        assert result.overall == "pass"

    def test_fail_on_denylist(self):
        rules = parse_policy(SAMPLE_POLICY_YAML)
        result = evaluate_policy(rules, SCAN_DATA_VIOLATED)
        assert result.overall == "fail"

    def test_license_denylist_triggered(self):
        rules = parse_policy(SAMPLE_POLICY_YAML)
        result = evaluate_policy(rules, SCAN_DATA_VIOLATED)
        no_gpl = next((o for o in result.outcomes if o.rule_id == "no-gpl"), None)
        assert no_gpl is not None
        assert no_gpl.triggered is True
        assert no_gpl.action == "fail"

    def test_component_denylist_triggered(self):
        rules = parse_policy(SAMPLE_POLICY_YAML)
        result = evaluate_policy(rules, SCAN_DATA_VIOLATED)
        no_log4j = next((o for o in result.outcomes if o.rule_id == "no-log4j"), None)
        assert no_log4j is not None
        assert no_log4j.triggered is True

    def test_threshold_warn_triggered(self):
        rules = parse_policy(SAMPLE_POLICY_YAML)
        result = evaluate_policy(rules, SCAN_DATA_VIOLATED)
        threshold = next((o for o in result.outcomes if o.rule_id == "quality-threshold"), None)
        assert threshold is not None
        assert threshold.triggered is True  # quality_score=2.0 < 5.0

    def test_outcome_count_equals_rule_count(self):
        rules = parse_policy(SAMPLE_POLICY_YAML)
        result = evaluate_policy(rules, SCAN_DATA_CLEAN)
        assert len(result.outcomes) == len(rules)

    def test_empty_rules_always_pass(self):
        result = evaluate_policy([], SCAN_DATA_CLEAN)
        assert result.overall == "pass"
        assert result.outcomes == []

    def test_to_dict(self):
        rules = parse_policy(SAMPLE_POLICY_YAML)
        result = evaluate_policy(rules, SCAN_DATA_CLEAN)
        d = result.to_dict()
        assert "overall" in d
        assert "outcomes" in d
        assert isinstance(d["outcomes"], list)


class TestCompare:
    def test_lt(self):
        assert _compare(3.0, "lt", 5.0) is True
        assert _compare(5.0, "lt", 5.0) is False

    def test_lte(self):
        assert _compare(5.0, "lte", 5.0) is True
        assert _compare(6.0, "lte", 5.0) is False

    def test_gt(self):
        assert _compare(6.0, "gt", 5.0) is True
        assert _compare(4.0, "gt", 5.0) is False

    def test_gte(self):
        assert _compare(5.0, "gte", 5.0) is True
        assert _compare(4.0, "gte", 5.0) is False

    def test_eq(self):
        assert _compare(5.0, "eq", 5.0) is True
        assert _compare(5.1, "eq", 5.0) is False

    def test_unknown_operator(self):
        assert _compare(5.0, "??", 5.0) is False


class TestGetMetric:
    def test_quality_score(self):
        data = {"quality_score": 7.5}
        assert _get_metric("quality_score", data) == 7.5

    def test_risk_score(self):
        data = {"risk_score": 4.2}
        assert _get_metric("risk_score", data) == 4.2

    def test_comp_with_purl_ratio(self):
        data = {
            "components": [
                {"purl": "pkg:npm/a@1.0"},
                {"purl": None},
                {"purl": "pkg:npm/c@1.0"},
            ]
        }
        assert _get_metric("comp_with_purl", data) == pytest.approx(2 / 3)

    def test_unknown_metric_returns_zero(self):
        assert _get_metric("nonexistent_metric", {}) == 0.0
