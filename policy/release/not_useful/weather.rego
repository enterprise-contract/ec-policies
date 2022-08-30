package policy.release.not_useful.weather

import data.lib

# METADATA
# title: Snow day
# description: |-
#   It's expected this rule will be skipped by policy configuration.
#   This rule is for demonstration and test purposes.
# custom:
#   short_name: snow
#   failure_msg: It's snowing, no releases today
#
deny[result] {
	true
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Too hot to release
# description: |-
#   It's expected this rule will be skipped by policy configuration.
#   This rule is for demonstration and test purposes.
# custom:
#   short_name: heatwave
#   failure_msg: It's too hot, no releases today
#
deny[result] {
	true
	result := lib.result_helper(rego.metadata.chain(), [])
}
