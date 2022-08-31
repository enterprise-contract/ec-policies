package policy.release.not_useful

import data.lib

# METADATA
# title: A dummy rule that always fails
# description: |-
#   It's expected this rule will be skipped by policy configuration.
#   This rule is for demonstration and test purposes and should be deleted soon.
# custom:
#   failure_msg: It just feels like a bad day to do a release
#   effective_on: 2022-01-01T00:00:00Z
#
deny_bad_day[result] {
	true
	result := lib.result_helper(rego.metadata.chain(), [])
}
