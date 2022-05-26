package policies.not_useful

import data.lib

# METADATA
# title: A dummy rule that always fails
# description: |-
#   It's expected this rule will be skipped by policy configuration.
#   This rule is for demonstration and test purposes and should be deleted soon.
# custom:
#   short_name: bad_day
#   failure_msg: It just feels like a bad day to do a release
#
deny[result] {
	true
	result := lib.result_helper(rego.metadata.rule(), [])
}
