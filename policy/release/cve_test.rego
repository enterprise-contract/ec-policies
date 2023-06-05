package policy.release.cve

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

test_success if {
	attestations := [lib.att_mock_helper_ref(
		_result_name,
		{"vulnerabilities": {"critical": 0, "high": 0, "medium": 20, "low": 300}},
		"clair-scan",
		_bundle,
	)]
	lib.assert_empty(deny) with input.attestations as attestations
}

test_success_with_rule_data if {
	attestations := [lib.att_mock_helper_ref(
		_result_name,
		{"vulnerabilities": {"critical": 1, "high": 1, "medium": 20, "low": 300}},
		"clair-scan",
		_bundle,
	)]
	lib.assert_empty(deny) with input.attestations as attestations
		with data.rule_data.restrict_cve_security_levels as ["spam"]
}

test_failure if {
	attestations := [lib.att_mock_helper_ref(
		_result_name,
		{"vulnerabilities": {"critical": 1, "high": 10, "medium": 20, "low": 300}},
		"clair-scan",
		_bundle,
	)]
	expected := {
		{
			"code": "cve.cve_blockers",
			"term": "critical",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Found 1 CVE vulnerabilities of critical security level",
		},
		{
			"code": "cve.cve_blockers",
			"term": "high",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Found 10 CVE vulnerabilities of high security level",
		},
	}
	lib.assert_equal(deny, expected) with input.attestations as attestations
}

test_failure_with_rule_data if {
	attestations := [lib.att_mock_helper_ref(
		_result_name,
		{"vulnerabilities": {"spam": 1, "bacon": 2, "eggs": 3}},
		"clair-scan",
		_bundle,
	)]
	expected := {
		{
			"code": "cve.cve_blockers",
			"term": "spam",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Found 1 CVE vulnerabilities of spam security level",
		},
		{
			"code": "cve.cve_blockers",
			"term": "bacon",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Found 2 CVE vulnerabilities of bacon security level",
		},
	}
	lib.assert_equal(deny, expected) with input.attestations as attestations
		with data.rule_data.restrict_cve_security_levels as ["spam", "bacon"]
}

test_warn if {
	attestations := [lib.att_mock_helper_ref(
		_result_name,
		{"vulnerabilities": {"critical": 1, "high": 10, "medium": 20, "low": 300}},
		"clair-scan",
		_bundle,
	)]
	lib.assert_empty(warn) with input.attestations as attestations
}

test_warn_with_rule_data if {
	attestations := [lib.att_mock_helper_ref(
		_result_name,
		{"vulnerabilities": {"critical": 1, "high": 10, "medium": 20, "low": 300}},
		"clair-scan",
		_bundle,
	)]
	expected := {
		{
			"code": "cve.cve_warnings",
			"term": "medium",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Found 20 non-blocking CVE vulnerabilities of medium security level",
		},
		{
			"code": "cve.cve_warnings",
			"term": "low",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Found 300 non-blocking CVE vulnerabilities of low security level",
		},
	}
	lib.assert_equal(warn, expected) with input.attestations as attestations
		with data.rule_data.warn_cve_security_levels as ["medium", "low"]
}

test_missing_cve_scan_result if {
	attestations := [lib.att_mock_helper_ref(
		"WRONG_RESULT_NAME",
		{"vulnerabilities": {"critical": 1, "high": 1, "medium": 20, "low": 300}},
		"clair-scan",
		_bundle,
	)]
	expected := {{
		"code": "cve.cve_results_found",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Clair CVE scan results were not found",
	}}
	lib.assert_equal(deny, expected) with input.attestations as attestations
}

test_missing_cve_scan_vulnerabilities if {
	attestations := [lib.att_mock_helper_ref(
		_result_name,
		{"seitilibarenluv": {"critical": 1, "high": 1, "medium": 20, "low": 300}},
		"clair-scan",
		_bundle,
	)]
	expected := {{
		"code": "cve.cve_results_found",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Clair CVE scan results were not found",
	}}
	lib.assert_equal(deny, expected) with input.attestations as attestations
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
