#
# METADATA
# description: |-
#   A package containing a bogus test useful for early testing and demos.
#
#   TODO: Delete me
#
# custom:
#   effective_on: 2022-01-01T00:00:00Z
#
package release

import data.lib

# METADATA
# title: A dummy rule that always fails
# description: |-
#   It's expected this rule will be skipped by policy configuration.
#   This rule is for demonstration and test purposes and should be deleted soon.
# custom:
#   short_name: bad_day
#   failure_msg: It just feels like a bad day to do a release
#   # TODO: Move this to the future to test time-based policy
#   effective_on: 2023-01-01T00:00:00Z
#
deny_bad_day[result] {
	true
	result := lib.result_helper(rego.metadata.chain(), [])
}
