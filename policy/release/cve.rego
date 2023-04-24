#
# METADATA
# title: CVE checks
# description: >-
#   This package is responsible for verifying a CVE scan was performed during
#   the build pipeline, and that the image under test does not contain CVEs
#   of certain security levels.
#
package policy.release.cve

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Blocking CVE check
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs
#   of certain security levels have not been detected. If detected, this policy
#   rule will fail. By default, only CVEs of critical and high security level
#   cause a failure. This is configurable by the rule data key
#   "restrict_cve_security_levels". The available levels are critical, high,
#    medium, and low.
# custom:
#   short_name: cve_blockers
#   failure_msg: Found %d CVE vulnerabilities of %s security level
#   solution: >-
#     Make sure to address any CVE's related to the image. The CVEs are detected
#     by the task that runs a Clair scan and emits a result named `CLAIR_SCAN_RESULT`.
#   collections:
#   - minimal
#
deny contains result if {
	some level, amount in _non_zero_levels("restrict_cve_security_levels")
	result := lib.result_helper_with_term(rego.metadata.chain(), [amount, level], level)
}

# METADATA
# title: Non-blocking CVE check
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs
#   of certain security levels have not been detected. If detected, this policy
#   rule will raise a warning. By default, the list of CVE security levels used
#   by this policy is empty. However, this is configurable by the rule data key
#   "warn_cve_security_levels". The available levels are critical, high,
#    medium, and low.
# custom:
#   short_name: cve_warnings
#   failure_msg: Found %d non-blocking CVE vulnerabilities of %s security level
#   solution: >-
#     Make sure to address any CVE's related to the image. The CVEs are detected
#     by the task that runs a Clair scan and emits a result named `CLAIR_SCAN_RESULT`.   
#   collections:
#   - minimal
#
warn contains result if {
	some level, amount in _non_zero_levels("warn_cve_security_levels")
	result := lib.result_helper_with_term(rego.metadata.chain(), [amount, level], level)
}

# METADATA
# title: CVE scan results found
# description: >-
#   The clair-scan task results have not been found in the SLSA Provenance
#   attestation of the build pipeline.
# custom:
#   short_name: cve_results_found
#   failure_msg: Clair CVE scan results were not found
#   solution: >-
#     Make sure there is a successful task in the build pipeline that runs a
#     Clair scan and creates a task result called `CLAIR_SCAN_RESULT`.
#   collections:
#   - minimal
#
deny contains result if {
	not _vulnerabilities
	result := lib.result_helper(rego.metadata.chain(), [])
}

_vulnerabilities := vulnerabilities if {
	some result in lib.results_named(_result_name)
	vulnerabilities := result.value.vulnerabilities
}

_result_name := "CLAIR_SCAN_RESULT"

_non_zero_levels(key) := d if {
	d := {level: amount |
		some level in {a | some a in lib.rule_data(key)}
		amount := _vulnerabilities[level]
		amount > 0
	}
}
