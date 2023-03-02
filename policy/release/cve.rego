#
# METADATA
# title: CVE checks
# description: >-
#   This package is responsible for verifying a CVE scan was performed during
#   the build pipeline, and that the image under test does not contain CVEs
#   of certain security levels.
package policy.release.cve

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Found CVE vulnerabilities
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs
#   of certain security levels have not been detected. If detected, this policy
#   rule will fail. By default, only CVEs of critical and high security level
#   cause a failure. This is configurable by the rule data key
#   "restrict_cve_security_levels". The available levels are critical, high,
#    medium, and low.
# custom:
#   short_name: found_cve_vulnerabilities
#   failure_msg: Found %d CVE vulnerabilities of %s security level
#   collections:
#   - minimal
deny contains result if {
	some level, amount in _non_zero_levels("restrict_cve_security_levels")
	result := lib.result_helper_with_term(rego.metadata.chain(), [amount, level], level)
}

# METADATA
# title: Found non-blocking CVE vulnerabilities
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs
#   of certain security levels have not been detected. If detected, this policy
#   rule will raise a warning. By default, the list of CVE security levels used
#   by this policy is empty. However, this is configurable by the rule data key
#   "warn_cve_security_levels". The available levels are critical, high,
#    medium, and low.
# custom:
#   short_name: found_non_blocking_cve_vulnerabilities
#   failure_msg: Found %d non-blocking CVE vulnerabilities of %s security level
#   collections:
#   - minimal
warn contains result if {
	some level, amount in _non_zero_levels("warn_cve_security_levels")
	result := lib.result_helper_with_term(rego.metadata.chain(), [amount, level], level)
}

# METADATA
# title: Missing CVE scan results
# description: >-
#   The clair-scan task results have not been found in the SLSA Provenance
#   attestation of the build pipeline.
# custom:
#   short_name: missing_cve_scan_results
#   failure_msg: CVE scan results not found
#   collections:
#   - minimal
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
