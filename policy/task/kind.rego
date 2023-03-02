#
# METADATA
# title: Task definition kind checks
# description: |-
#   Task definition kind check
#
package policy.task.kind

import future.keywords.contains
import future.keywords.if

import data.lib

expected_kind := "Task"

# METADATA
# title: Input data has unexpected kind
# description: |-
#   Check to confirm the input data has the kind "Task"
# custom:
#   short_name: unexpected_kind
#   failure_msg: Unexpected kind '%s'
#
deny contains result if {
	input.kind
	expected_kind != input.kind
	result := lib.result_helper(rego.metadata.chain(), [input.kind])
}

# METADATA
# title: Input data has kind defined
# description: |-
#   Check to confirm the input data has the kind field
# custom:
#   short_name: kind_not_found
#   failure_msg: Required field 'kind' not found
#
deny contains result if {
	not input.kind
	result := lib.result_helper(rego.metadata.chain(), [])
}
