package release.cve_test

import rego.v1

import data.lib
import data.lib.tekton_test
import data.lib.time as lib_time
import data.lib_test
import data.release.cve

test_success if {
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
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
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	lib.assert_empty(cve.deny | cve.warn) with input.attestations as attestations
}

test_success_deprecated_name if {
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
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
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	lib.assert_empty(cve.deny) with input.attestations as attestations
}

test_success_with_rule_data if {
	counts := json.remove(_dummy_counts, ["/unknown"])
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._result_name,
			"type": "string",
			"value": {
				"vulnerabilities": counts,
				"unpatched_vulnerabilities": counts,
			},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{
				"vulnerabilities": counts,
				"unpatched_vulnerabilities": counts,
			},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	lib.assert_empty(cve.deny | cve.warn) with input.attestations as attestations
		with data.rule_data.restrict_cve_security_levels as ["unknown"]
		with data.rule_data.warn_unpatched_cve_security_levels as ["unknown"]
}

test_success_with_rule_data_deprecated_name if {
	counts := json.remove(_dummy_counts, ["/unknown"])
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._deprecated_result_name,
			"type": "string",
			"value": {"vulnerabilities": counts},
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._result_name,
			{"vulnerabilities": counts},
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	lib.assert_empty(cve.deny) with input.attestations as attestations
		with data.rule_data.restrict_cve_security_levels as ["unknown"]
	lib.assert_empty(cve.warn) with input.attestations as attestations
}

test_failure if {
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
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
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
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
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
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
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
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

	expected_warn := {
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found 1 non-blocking unpatched CVE vulnerabilities of critical security level",
			"term": "critical",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found 10 non-blocking unpatched CVE vulnerabilities of high security level",
			"term": "high",
		},
		{
			"code": "cve.deprecated_cve_result_name",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "CVE scan uses deprecated result name",
		},
	}
	lib.assert_equal_results(cve.warn, expected_warn) with input.attestations as attestations
}

test_failure_with_rule_data if {
	_custom_counts := {"unknown": 1, "low": 2, "medium": 3}
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
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
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected := {
		{
			"code": "cve.cve_blockers",
			"term": "unknown",
			"msg": "Found 1 CVE vulnerabilities of unknown security level",
		},
		{
			"code": "cve.cve_blockers",
			"term": "low",
			"msg": "Found 2 CVE vulnerabilities of low security level",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"term": "unknown",
			"msg": "Found 1 unpatched CVE vulnerabilities of unknown security level",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"term": "low",
			"msg": "Found 2 unpatched CVE vulnerabilities of low security level",
		},
	}
	lib.assert_equal_results(cve.deny, expected) with input.attestations as attestations
		with data.rule_data.restrict_cve_security_levels as ["unknown", "low"]
		with data.rule_data.restrict_unpatched_cve_security_levels as ["unknown", "low"]
}

test_warn if {
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
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
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
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

test_no_warn_deprecated_name_with_new_name_present if {
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
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
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected := {
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
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
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
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
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
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
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
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected := {{
		"code": "cve.cve_results_found",
		"msg": "Clair CVE scan results were not found",
	}}
	lib.assert_equal_results(cve.deny, expected) with input.attestations as attestations
}

test_missing_cve_scan_vulnerabilities if {
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
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
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected := {{
		"code": "cve.cve_results_found",
		"msg": "Clair CVE scan results were not found",
	}}
	lib.assert_equal_results(cve.deny, expected) with input.attestations as attestations
}

test_rule_data_provided if {
	d := {
		"restrict_cve_security_levels": [
			# Wrong type
			1,
			# Duplicated items
			"high",
			"high",
		],
		# We don't need to check the different errors for each key as they are processed the same
		# way. But we do want to, at least, verify a single error.
		"warn_cve_security_levels": [1],
		"restrict_unpatched_cve_security_levels": [1],
		"warn_unpatched_cve_security_levels": [1],
	}

	expected := {
		{
			"code": "cve.rule_data_provided",
			"msg": "Rule data restrict_cve_security_levels has unexpected format: (Root): array items[1,2] must be unique",
		},
		{
			"code": "cve.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data restrict_cve_security_levels has unexpected format: 0: 0 must be one of the following: \"critical\", \"high\", \"medium\", \"low\", \"unknown\"",
		},
		{
			"code": "cve.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data restrict_unpatched_cve_security_levels has unexpected format: 0: 0 must be one of the following: \"critical\", \"high\", \"medium\", \"low\", \"unknown\"",
		},
		{
			"code": "cve.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data warn_cve_security_levels has unexpected format: 0: 0 must be one of the following: \"critical\", \"high\", \"medium\", \"low\", \"unknown\"",
		},
		{
			"code": "cve.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data warn_unpatched_cve_security_levels has unexpected format: 0: 0 must be one of the following: \"critical\", \"high\", \"medium\", \"low\", \"unknown\"",
		},
	}

	attestations := [lib_test.att_mock_helper_ref(
		cve._result_name,
		{
			"vulnerabilities": _dummy_counts_zero_high,
			"unpatched_vulnerabilities": _dummy_counts_zero_high,
		},
		"clair-scan",
		_bundle,
	)]
	lib.assert_equal_results(cve.deny, expected) with input.attestations as attestations
		with data.rule_data as d
}

test_clair_report if {
	report := {"sha256:image_digest": "sha256:report_digest"}

	attestations := [lib_test.att_mock_helper_ref(
		cve._reports_result_name,
		report,
		"clair-scan",
		_bundle,
	)]

	got := cve._clair_report with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob

	lib.assert_equal(_clair_report, got)
}

test_clair_report_fetch_manifest_failure if {
	report := {"sha256:image_digest": "sha256:report_digest"}

	attestations := [lib_test.att_mock_helper_ref(
		cve._reports_result_name,
		report,
		"clair-scan",
		_bundle,
	)]

	not cve._clair_report with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as null
		with ec.oci.blob as _mock_blob
}

test_clair_report_fetch_blob_failure if {
	report := {"sha256:image_digest": "sha256:report_digest"}

	attestations := [lib_test.att_mock_helper_ref(
		cve._reports_result_name,
		report,
		"clair-scan",
		_bundle,
	)]

	not cve._clair_report with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as null
}

test_clair_vulnerabilities if {
	expected := {
		"vulnerabilities": {
			"critical": 1,
			"high": 2,
			"medium": 3,
			"low": 4,
			"unknown": 5,
		},
		"unpatched_vulnerabilities": {
			"critical": 6,
			"high": 7,
			"medium": 8,
			"low": 9,
			"unknown": 10,
		},
	}

	p := {
		"start": 0,
		"end": lib_time.effective_current_time_ns,
	}

	period := {
		"critical": p,
		"high": p,
		"medium": p,
		"low": p,
		"unknown": p,
	}

	got := cve._clair_vulnerabilities(period) with cve._clair_report as _clair_report

	lib.assert_equal(expected, got)
}

test_success_with_full_report if {
	reports := {"sha256:image_digest": "sha256:no_vulnerabilities_report_digest"}

	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._reports_result_name,
			"type": "string",
			"value": reports,
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._reports_result_name,
			reports,
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	lib.assert_empty(cve.deny | cve.warn) with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
}

test_failure_with_full_report if {
	reports := {"sha256:image_digest": "sha256:report_digest"}

	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._reports_result_name,
			"type": "string",
			"value": reports,
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._reports_result_name,
			reports,
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
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
			"msg": "Found 2 CVE vulnerabilities of high security level",
		},
	}

	# regal ignore:line-length
	lib.assert_equal_results(cve.deny, expected_deny) with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob

	expected_warn := {
		{
			"code": "cve.unpatched_cve_warnings",
			"term": "critical",
			"msg": "Found 6 non-blocking unpatched CVE vulnerabilities of critical security level",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"term": "high",
			"msg": "Found 7 non-blocking unpatched CVE vulnerabilities of high security level",
		},
	}

	# regal ignore:line-length
	lib.assert_equal_results(cve.warn, expected_warn) with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
}

test_full_report_fetch_issue if {
	reports := {"sha256:image_digest": "sha256:no_vulnerabilities_report_digest"}

	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._reports_result_name,
			"type": "string",
			"value": reports,
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._reports_result_name,
			reports,
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]

	expected := {{
		"code": "cve.cve_results_found",
		"msg": "Clair CVE scan results were not found",
	}}

	lib.assert_equal_results(cve.deny, expected) with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as null
	lib.assert_equal_results(cve.deny, expected) with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as null

	lib.assert_empty(cve.warn) with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as null
	lib.assert_empty(cve.warn) with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as null
}

test_warning_leeway_with_full_report if {
	reports := {"sha256:image_digest": "sha256:report_digest"}

	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
		"clair-scan",
		[{
			"name": cve._reports_result_name,
			"type": "string",
			"value": reports,
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref(
			cve._reports_result_name,
			reports,
			"clair-scan",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
	expected_deny := {
		{
			"code": "cve.cve_blockers",
			"effective_on": lib_time.default_effective_on,
			"msg": "Found 1 CVE vulnerabilities of critical security level",
			"term": "critical",
		},
		{
			"code": "cve.cve_blockers",
			"effective_on": "2022-03-26T00:00:00Z", # 2022-03-26 + 10 days = 2022-04-05
			"msg": "Found 2 CVE vulnerabilities of high security level",
			"term": "high",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"effective_on": lib_time.default_effective_on,
			"msg": "Found 6 unpatched CVE vulnerabilities of critical security level",
			"term": "critical",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"effective_on": "2022-03-26T00:00:00Z", # 2022-03-26 + 10 days = 2022-04-05
			"msg": "Found 7 unpatched CVE vulnerabilities of high security level",
			"term": "high",
		},
	}

	# regal ignore:line-length
	lib.assert_equal_results_no_collections(cve.deny, expected_deny) with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data.cve_leeway as {"critical": 9, "high": 10}
		with data.rule_data.restrict_unpatched_cve_security_levels as ["critical", "high"]
		with data.rule_data.warn_unpatched_cve_security_levels as []
		with lib_time.effective_current_time_ns as time.parse_rfc3339_ns("2022-04-05T00:00:00Z")

	lib.assert_empty(cve.warn) with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with input.attestations as attestations
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data.cve_leeway as {"critical": 9, "high": 10}
		with data.rule_data.restrict_unpatched_cve_security_levels as ["critical", "high"]
		with data.rule_data.warn_unpatched_cve_security_levels as []
		with lib_time.effective_current_time_ns as time.parse_rfc3339_ns("2022-04-05T00:00:00Z")
}

test_leeway_rule_data_check if {
	d := {"cve_leeway": {
		# wrong key
		"blooper": 1,
		# wrong type
		"critical": "one",
		# negative number
		"high": -10,
		# all good
		"medium": 10,
	}}

	expected := {
		{
			"code": "cve.rule_data_provided",
			"msg": "Rule data cve_leeway has unexpected format: (Root): Additional property blooper is not allowed",
		},
		{
			"code": "cve.rule_data_provided",
			"msg": "Rule data cve_leeway has unexpected format: critical: Invalid type. Expected: integer, given: string",
		},
		{
			"code": "cve.rule_data_provided",
			"msg": "Rule data cve_leeway has unexpected format: high: Must be greater than or equal to 0",
		},
	}

	attestations := [lib_test.att_mock_helper_ref(
		cve._result_name,
		{
			"vulnerabilities": _dummy_counts_zero_high,
			"unpatched_vulnerabilities": _dummy_counts_zero_high,
		},
		"clair-scan",
		_bundle,
	)]
	lib.assert_equal_results(cve.deny, expected) with input.attestations as attestations
		with data.rule_data as d
}

_fingerprints(a, b) := [v | some n in numbers.range(a, b); v := sprintf("%d", [n])]

_vulns(fingerprits, template) := {v |
	some fingerprint in fingerprits
	v := {fingerprint: template}
}

_vuln(severity, fixed_in, issued) := {
	"fixed_in_version": fixed_in,
	"normalized_severity": severity,
	"issued": issued,
}

# `opa fmt` is causing this
# regal ignore:line-length
vulnerabilities := object.union_n(lib.to_array(((((_vulns(_fingerprints(1, 1), _vuln("Critical", "1.0", "2022-03-26T00:00:00Z")) | _vulns(_fingerprints(2, 3), _vuln("High", "1.0", "2022-03-26T00:00:00Z"))) | _vulns(_fingerprints(4, 6), _vuln("Medium", "1.0", "2022-03-26T00:00:00Z"))) | _vulns(_fingerprints(7, 10), _vuln("Low", "1.0", "2022-03-26T00:00:00Z"))) | _vulns(_fingerprints(11, 15), _vuln("Unknown", "1.0", "2022-03-26T00:00:00Z")))))

# `opa fmt` is causing this
# regal ignore:line-length
unpatched_vulnerabilities := object.union_n(lib.to_array(((((_vulns(_fingerprints(16, 21), _vuln("Critical", "", "2022-03-26T00:00:00Z")) | _vulns(_fingerprints(22, 28), _vuln("High", "", "2022-03-26T00:00:00Z"))) | _vulns(_fingerprints(29, 36), _vuln("Medium", "", "2022-03-26T00:00:00Z"))) | _vulns(_fingerprints(37, 45), _vuln("Low", "", "2022-03-26T00:00:00Z"))) | _vulns(_fingerprints(46, 55), _vuln("Unknown", "", "2022-03-26T00:00:00Z")))))

_clair_report := {"vulnerabilities": object.union(vulnerabilities, unpatched_vulnerabilities)}

_manifests := {
	"registry.io/repository/image@sha256:report_digest": {"layers": [{
		"mediaType": cve._report_oci_mime_type,
		"digest": "sha256:report_blob_digest",
	}]},
	"registry.io/repository/image@sha256:no_vulnerabilities_report_digest": {"layers": [{
		"mediaType": cve._report_oci_mime_type,
		"digest": "sha256:no_vulnerabilities_report_blob_digest",
	}]},
}

_blobs := {
	"registry.io/repository/image@sha256:report_blob_digest": json.marshal(_clair_report),
	"registry.io/repository/image@sha256:no_vulnerabilities_report_blob_digest": json.marshal({"vulnerabilities": {}}),
}

_mock_image_manifest(ref) := _manifests[ref]

_mock_blob(ref) := _blobs[ref]

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_dummy_counts := {"critical": 1, "high": 10, "medium": 20, "low": 300, "unknown": 2}

_dummy_counts_zero_high := {"critical": 0, "high": 0, "medium": 20, "low": 300, "unknown": 2}
