package policy.release.cve_test

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.tkn_test
import data.lib_test
import data.policy.release.cve

test_success if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._result_name,
			"type": "string",
			"value": {
				"vulnerabilities": _dummy_counts_zero_high,
				"unpatched_vulnerabilities": _dummy_counts_zero_high,
			},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{
				"vulnerabilities": _dummy_counts_zero_high,
				"unpatched_vulnerabilities": _dummy_counts_zero_high,
			},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	lib.assert_empty(cve.deny | cve.warn) with input.attestations as attestations
}

test_success_deprecated_name if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._deprecated_result_name,
			"type": "string",
			"value": {"vulnerabilities": _dummy_counts_zero_high},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{"vulnerabilities": _dummy_counts_zero_high},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	lib.assert_empty(cve.deny) with input.attestations as attestations
}

test_success_with_rule_data if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._result_name,
			"type": "string",
			"value": {
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	lib.assert_empty(cve.deny | cve.warn) with input.attestations as attestations
		with data.rule_data.restrict_cve_security_levels as ["spam"]
		with data.rule_data.warn_unpatched_cve_security_levels as ["spam"]
}

test_success_with_rule_data_deprecated_name if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._deprecated_result_name,
			"type": "string",
			"value": {"vulnerabilities": _dummy_counts},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{"vulnerabilities": _dummy_counts},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	lib.assert_empty(cve.deny) with input.attestations as attestations
		with data.rule_data.restrict_cve_security_levels as ["spam"]
}

test_failure if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._result_name,
			"type": "string",
			"value": {
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected_deny := {
		{
			"code": "cve.cve_blockers",
			"term": "critical",
			"msg": "Found 1 CVE vulnerabilities of critical security level",
		},
		{
			"code": "cve.cve_blockers",
			"term": "high",
			"msg": "Found 10 CVE vulnerabilities of high security level",
		},
	}
	lib.assert_equal_results(cve.deny, expected_deny) with input.attestations as attestations
}

test_failure_deprecated_name if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._deprecated_result_name,
			"type": "string",
			"value": {
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._deprecated_result_name,
			{
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected_deny := {
		{
			"code": "cve.cve_blockers",
			"term": "critical",
			"msg": "Found 1 CVE vulnerabilities of critical security level",
		},
		{
			"code": "cve.cve_blockers",
			"term": "high",
			"msg": "Found 10 CVE vulnerabilities of high security level",
		},
	}
	lib.assert_equal_results(cve.deny, expected_deny) with input.attestations as attestations
}

test_failure_with_rule_data if {
	_custom_counts := {"spam": 1, "bacon": 2, "eggs": 3}
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._result_name,
			"type": "string",
			"value": {
				"vulnerabilities": _custom_counts,
				"unpatched_vulnerabilities": _custom_counts,
			},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{
				"vulnerabilities": _custom_counts,
				"unpatched_vulnerabilities": _custom_counts,
			},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected := {
		{
			"code": "cve.cve_blockers",
			"term": "spam",
			"msg": "Found 1 CVE vulnerabilities of spam security level",
		},
		{
			"code": "cve.cve_blockers",
			"term": "bacon",
			"msg": "Found 2 CVE vulnerabilities of bacon security level",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"term": "spam",
			"msg": "Found 1 unpatched CVE vulnerabilities of spam security level",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"term": "bacon",
			"msg": "Found 2 unpatched CVE vulnerabilities of bacon security level",
		},
	}
	lib.assert_equal_results(cve.deny, expected) with input.attestations as attestations
		with data.rule_data.restrict_cve_security_levels as ["spam", "bacon"]
		with data.rule_data.restrict_unpatched_cve_security_levels as ["spam", "bacon"]
}

test_warn if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._result_name,
			"type": "string",
			"value": {
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected := {
		{
			"code": "cve.unpatched_cve_warnings",
			"term": "critical",
			"msg": "Found 1 non-blocking unpatched CVE vulnerabilities of critical security level",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"term": "high",
			"msg": "Found 10 non-blocking unpatched CVE vulnerabilities of high security level",
		},
	}
	lib.assert_equal_results(cve.warn, expected) with input.attestations as attestations
}

test_warn_deprecated_name if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._deprecated_result_name,
			"type": "string",
			"value": {
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected := {
		{
			"code": "cve.deprecated_cve_result_name",
			"collections": ["minimal", "redhat"],
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "CVE scan uses deprecated result name",
		},
		{
			"code": "cve.deprecated_unpatched_cve_result_name",
			"msg": "CVE scan uses deprecated result name",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found 1 non-blocking unpatched CVE vulnerabilities of critical security level",
			"term": "critical",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"term": "high",
			"msg": "Found 10 non-blocking unpatched CVE vulnerabilities of high security level",
		},
	}
	lib.assert_equal_results(cve.warn, expected) with input.attestations as attestations
}

test_warn_with_rule_data if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._result_name,
			"type": "string",
			"value": {
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{
				"vulnerabilities": _dummy_counts,
				"unpatched_vulnerabilities": _dummy_counts,
			},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected := {
		{
			"code": "cve.cve_warnings",
			"term": "medium",
			"msg": "Found 20 non-blocking CVE vulnerabilities of medium security level",
		},
		{
			"code": "cve.cve_warnings",
			"term": "low",
			"msg": "Found 300 non-blocking CVE vulnerabilities of low security level",
		},
		{
			"code": "cve.cve_warnings",
			"term": "unknown",
			"msg": "Found 2 non-blocking CVE vulnerabilities of unknown security level",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"term": "medium",
			"msg": "Found 20 non-blocking unpatched CVE vulnerabilities of medium security level",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"term": "low",
			"msg": "Found 300 non-blocking unpatched CVE vulnerabilities of low security level",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"term": "unknown",
			"msg": "Found 2 non-blocking unpatched CVE vulnerabilities of unknown security level",
		},
	}
	lib.assert_equal_results(cve.warn, expected) with input.attestations as attestations
		with data.rule_data.warn_cve_security_levels as ["medium", "low", "unknown"]
		with data.rule_data.warn_unpatched_cve_security_levels as ["medium", "low", "unknown"]
}

test_missing_cve_scan_result if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": "WRONG_RESULT_NAME",
			"type": "string",
			"value": {"vulnerabilities": _dummy_counts},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			"WRONG_RESULT_NAME",
			{"vulnerabilities": _dummy_counts},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected := {{
		"code": "cve.cve_results_found",
		"msg": "Clair CVE scan results were not found",
	}}
	lib.assert_equal_results(cve.deny, expected) with input.attestations as attestations
}

test_missing_cve_scan_vulnerabilities if {
	slsav1_task_with_result := tkn_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._result_name,
			"type": "string",
			"value": {"seitilibarenluv": _dummy_counts},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{"seitilibarenluv": _dummy_counts},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected := {{
		"code": "cve.cve_results_found",
		"msg": "Clair CVE scan results were not found",
	}}
	lib.assert_equal_results(cve.deny, expected) with input.attestations as attestations
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_dummy_counts := {"critical": 1, "high": 10, "medium": 20, "low": 300, "unknown": 2}

_dummy_counts_zero_high := {"critical": 0, "high": 0, "medium": 20, "low": 300, "unknown": 2}
