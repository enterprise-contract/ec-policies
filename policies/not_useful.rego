package policies.not_useful

import data.lib

# This is demoing the concept of being able to conveniently exclude
# pieces of the EC policy without modifying the rego files.
#
# It's expected this will be skipped due to
# data.config.policy.non_blocking_checks being set to ["not_useful"].
# See main.rego to understand how it works.
#
# Todo soon probably: Delete this.

# METADATA
# title: A dummy rule that always fails
# custom:
#   short_name: bad_day
#   failure_msg: It just feels like a bad day to do a release
#
deny[result] {
	true
	result := lib.result_helper(rego.metadata.rule(), [])
}
