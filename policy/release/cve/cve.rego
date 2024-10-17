#
# METADATA
# title: CVE checks
# description: >-
#   This package is responsible for verifying a CVE scan was performed during
#   the build pipeline, and that the image under test does not contain CVEs
#   of certain security levels.
#
package release.cve

import rego.v1

import data.lib
import data.lib.image
import data.lib.time as lib_time

# METADATA
# title: Non-blocking CVE check
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs that have a known fix
#   and meet a certain security level have not been detected. If detected, this policy rule will
#   raise a warning. By default, the list of CVE security levels used by this policy is empty.
#   However, this is configurable by the rule data key `warn_cve_security_levels`. The available
#   levels are critical, high, medium, low, and unknown.
# custom:
#   short_name: cve_warnings
#   failure_msg: Found %d non-blocking CVE vulnerabilities of %s security level
#   solution: >-
#     Make sure to address any CVE's related to the image. The CVEs are detected
#     by the task that runs a Clair scan and emits a result named `SCAN_OUTPUT`.
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - cve.cve_results_found
#
warn contains result if {
	some level, amount in _non_zero_vulnerabilities("warn_cve_security_levels", _zero_period)
	result := lib.result_helper_with_term(rego.metadata.chain(), [amount, level], level)
}

# METADATA
# title: Non-blocking unpatched CVE check
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs that do NOT have a
#   known fix and meet a certain security level have not been detected. If detected, this policy
#   rule will raise a warning. By default, only CVEs of critical and high security level cause a
#   warning. This is configurable by the rule data key `warn_unpatched_cve_security_levels`. The
#   available levels are critical, high, medium, low, and unknown.
# custom:
#   short_name: unpatched_cve_warnings
#   failure_msg: Found %d non-blocking unpatched CVE vulnerabilities of %s security level
#   solution: >-
#     CVEs without a known fix can only be remediated by either removing the impacted dependency, or
#     by waiting for a fix to be available. The CVEs are detected by the task that emits a result
#     named `SCAN_OUTPUT`.
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - cve.cve_results_found
#
warn contains result if {
	some level, amount in _non_zero_unpatched("warn_unpatched_cve_security_levels", _zero_period)
	result := lib.result_helper_with_term(rego.metadata.chain(), [amount, level], level)
}

# METADATA
# title: Deprecated CVE result name
# description: >-
#   The `CLAIR_SCAN_RESULT` result name has been deprecated, and has been
#   replaced with `SCAN_OUTPUT`. If any task results with the old name are
#   found, this rule will raise a warning.
# custom:
#   short_name: deprecated_cve_result_name
#   failure_msg: CVE scan uses deprecated result name
#   solution: >-
#     Use the newer `SCAN_OUTPUT` result name.
#   depends_on:
#   - attestation_type.known_attestation_type
#
warn contains result if {
	# NOTE: This policy rule is purposely not added to any collection because the new result name
	# has not been widely adopted yet. See https://issues.redhat.com/browse/STONEINTG-660
	count(lib.results_named(_result_name)) == 0
	count(lib.results_named(_deprecated_result_name)) > 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Blocking CVE check
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs that have a known fix
#   and meet a certain security level have not been detected. If detected, this policy rule will
#   fail. By default, only CVEs of critical and high security level cause a failure. This is
#   configurable by the rule data key `restrict_cve_security_levels`. The available levels are
#   critical, high, medium, low, and unknown. In addition to that leeway can be granted per severity
#   using the `cve_leeway` rule data key containing days of allowed leeway, measured as time between
#   found vulnerability's public disclosure date and current effective time, per severity level.
# custom:
#   short_name: cve_blockers
#   failure_msg: Found %d CVE vulnerabilities of %s security level
#   solution: >-
#     Make sure to address any CVE's related to the image. The CVEs are detected
#     by the task that runs a Clair scan and emits a result named `SCAN_OUTPUT`.
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - cve.cve_results_found
#
deny contains result if {
	enforced_results := {result |
		some level, amount in _non_zero_vulnerabilities("restrict_cve_security_levels", _configured_period)
		result := lib.result_helper_with_term(rego.metadata.chain(), [amount, level], level)
	}

	leewayed_results := {result |
		some level, amount in _leewayed_vulnerabilities("restrict_cve_security_levels")

		result := _with_effective_on(
			lib.result_helper_with_term(rego.metadata.chain(), [amount, level], level),
			_configured_period[level].end,
		)
	}

	some result in (enforced_results | leewayed_results)
}

# METADATA
# title: Blocking unpatched CVE check
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs that do NOT have a
#   known fix and meet a certain security level have not been detected. If detected, this policy
#   rule will fail. By default, the list of security levels used by this policy is empty. This is
#   configurable by the rule data key `restrict_unpatched_cve_security_levels`. The available levels
#   are critical, high, medium, low, and unknown. In addition to that leeway can be granted per
#   severity using the `cve_leeway` rule data key containing days of allowed leeway, measured as
#   time between found vulnerability's public disclosure date and current effective time, per
#   severity level.
# custom:
#   short_name: unpatched_cve_blockers
#   failure_msg: Found %d unpatched CVE vulnerabilities of %s security level
#   solution: >-
#     CVEs without a known fix can only be remediated by either removing the impacted dependency, or
#     by waiting for a fix to be available. The CVEs are detected by the task that emits a result
#     named `SCAN_OUTPUT`.
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - cve.cve_results_found
#
deny contains result if {
	enforced_results := {result |
		some level, amount in _non_zero_unpatched("restrict_unpatched_cve_security_levels", _configured_period)
		result := lib.result_helper_with_term(rego.metadata.chain(), [amount, level], level)
	}

	leewayed_results := {result |
		some level, amount in _leewayed_unpatched_vulnerabilities("restrict_unpatched_cve_security_levels")

		result := _with_effective_on(
			lib.result_helper_with_term(rego.metadata.chain(), [amount, level], level),
			_configured_period[level].end,
		)
	}

	some result in (enforced_results | leewayed_results)
}

# METADATA
# title: CVE scan results found
# description: >-
#   Confirm that clair-scan task results are present in the SLSA Provenance
#   attestation of the build pipeline.
# custom:
#   short_name: cve_results_found
#   failure_msg: Clair CVE scan results were not found
#   solution: >-
#     Make sure there is a successful task in the build pipeline that runs a
#     Clair scan and creates a task result called `SCAN_OUTPUT`.
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	# NOTE: unpatched vulnerabilities are defined as an optional attribute. The lack of them should
	# not be considered a violation nor a warning. See details in:
	# https://github.com/konflux-ci/architecture/blob/main/ADR/0030-tekton-results-naming-convention.md
	not _vulnerabilities(_configured_period)
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format. The keys are
#   `restrict_cve_security_levels`,	`warn_cve_security_levels`,
#   `restrict_unpatched_cve_security_levels`, and `warn_unpatched_cve_security_levels`.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - minimal
#   - redhat
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

# extracts the clair report attached to the image
_clair_report := report if {
	input_image := image.parse(input.image.ref)

	some reports in lib.results_named(_reports_result_name)
	report_image := object.union(input_image, {"digest": reports.value[input_image.digest]})
	report_ref := image.str(report_image)
	report_manifest := ec.oci.image_manifest(report_ref)

	some layer in report_manifest.layers
	layer.mediaType == _report_oci_mime_type
	report_blob := object.union(input_image, {"digest": layer.digest})
	report_blob_ref := image.str(report_blob)

	report := json.unmarshal(ec.oci.blob(report_blob_ref))
}

# maps vulnerabilities and reports the counts by category (patched/unpatched)
# and severity
_clair_vulnerabilities(period) := vulns if {
	reported_vulnerabilities := _clair_report.vulnerabilities

	patched_vulnerabilities := [v |
		some v in reported_vulnerabilities
		v.fixed_in_version != ""
	]

	unpatched_vulnerabilities := [v |
		some v in reported_vulnerabilities
		v.fixed_in_version == ""
	]

	vulns := {
		"vulnerabilities": {
			"critical": _count_by_severity_with_period(patched_vulnerabilities, "critical", period),
			"high": _count_by_severity_with_period(patched_vulnerabilities, "high", period),
			"medium": _count_by_severity_with_period(patched_vulnerabilities, "medium", period),
			"low": _count_by_severity_with_period(patched_vulnerabilities, "low", period),
			"unknown": _count_by_severity_with_period(patched_vulnerabilities, "unknown", period),
		},
		"unpatched_vulnerabilities": {
			"critical": _count_by_severity_with_period(unpatched_vulnerabilities, "critical", period),
			"high": _count_by_severity_with_period(unpatched_vulnerabilities, "high", period),
			"medium": _count_by_severity_with_period(unpatched_vulnerabilities, "medium", period),
			"low": _count_by_severity_with_period(unpatched_vulnerabilities, "low", period),
			"unknown": _count_by_severity_with_period(unpatched_vulnerabilities, "unknown", period),
		},
	}
}

# counts the vulnerabilities with the given severity excluding vulnerabilities
# within the given period
_count_by_severity_with_period(vulnerabilities, severity, period) := count([v |
	some v in vulnerabilities
	lower(v.normalized_severity) == severity
	p := period[severity]
	time.parse_rfc3339_ns(v.issued) >= p.start
	time.parse_rfc3339_ns(v.issued) < p.end
])

_vulnerabilities(period) := vulnerabilities if {
	vulnerabilities := _clair_vulnerabilities(period).vulnerabilities
} else := vulnerabilities if {
	some result in lib.results_named(_result_name)
	vulnerabilities := result.value.vulnerabilities
} else := _vulnerabilities_deprecated

_unpatched_vulnerabilities(period) := vulnerabilities if {
	vulnerabilities := _clair_vulnerabilities(period).unpatched_vulnerabilities
} else := vulnerabilities if {
	some result in lib.results_named(_result_name)
	vulnerabilities := result.value.unpatched_vulnerabilities
} else := _unpatched_vulnerabilities_deprecated

_vulnerabilities_deprecated := vulnerabilities if {
	some result in lib.results_named(_deprecated_result_name)
	vulnerabilities := result.value.vulnerabilities
}

_unpatched_vulnerabilities_deprecated := vulnerabilities if {
	some result in lib.results_named(_deprecated_result_name)
	vulnerabilities := result.value.unpatched_vulnerabilities
}

_result_name := "SCAN_OUTPUT"

_deprecated_result_name := "CLAIR_SCAN_RESULT"

_reports_result_name := "REPORTS"

_report_oci_mime_type := "application/vnd.redhat.clair-report+json"

_non_zero_vulnerabilities(key, period) := _non_zero_levels(key, _vulnerabilities(period))

_leewayed_vulnerabilities(key) := {l1: amount |
	some l1, amount_with_leeway in _count_vulnerabilities(key, _configured_period)
	some l2, amount_without_leeway in _count_vulnerabilities(key, _zero_period)
	l1 == l2
	amount := amount_without_leeway - amount_with_leeway
	amount > 0
}

_non_zero_unpatched(key, period) := _non_zero_levels(key, _unpatched_vulnerabilities(period))

_leewayed_unpatched_vulnerabilities(key) := {l1: amount |
	some l1, amount_with_leeway in _count_unpatched_vulnerabilities(key, _configured_period)
	some l2, amount_without_leeway in _count_unpatched_vulnerabilities(key, _zero_period)
	l1 == l2
	amount := amount_without_leeway - amount_with_leeway
	amount > 0
}

_count_vulnerabilities(key, period) := _count_levels(key, _vulnerabilities(period))

_count_unpatched_vulnerabilities(key, period) := _count_levels(key, _unpatched_vulnerabilities(period))

_count_levels(key, vulnerabilities) := {level: amount |
	some level in {a | some a in lib.rule_data(key)}
	amount := vulnerabilities[level]
}

_non_zero_levels(key, vulnerabilities) := {level: amount |
	some level, amount in _count_levels(key, vulnerabilities)
	amount > 0
}

_configured_period[severity] := period if {
	leeway := lib.rule_data("cve_leeway")

	some severity in {"critical", "high", "medium", "low", "unknown"}
	period := {
		"start": 0,
		"end": time.add_date(lib_time.effective_current_time_ns, 0, 0, leeway[severity] * -1),
	}
}

_zero_period[severity] := period if {
	some severity in {"critical", "high", "medium", "low", "unknown"}
	period := {
		"start": 0,
		"end": lib_time.effective_current_time_ns,
	}
}

_with_effective_on(result, effective_on) := object.union(
	result,
	{"effective_on": time.format([effective_on, "UTC", "2006-01-02T15:04:05Z07:00"])},
)

_rule_data_errors contains msg if {
	keys := [
		"restrict_cve_security_levels",
		"warn_cve_security_levels",
		"restrict_unpatched_cve_security_levels",
		"warn_unpatched_cve_security_levels",
	]
	some key in keys

	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"enum": ["critical", "high", "medium", "low", "unknown"]},
			"uniqueItems": true,
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [key, violation.error])
}

_rule_data_errors contains msg if {
	value := lib.rule_data("cve_leeway")
	leeway_days := {
		"type": "integer",
		"minimum": 0,
	}
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"properties": {
				"critical": leeway_days,
				"high": leeway_days,
				"medium": leeway_days,
				"low": leeway_days,
				"unknown": leeway_days,
			},
			"additionalProperties": false,
		},
	)[1]
	msg := sprintf("Rule data cve_leeway has unexpected format: %s", [violation.error])
}
