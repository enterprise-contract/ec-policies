#
# METADATA
# title: Release Plan sanity checks
# description: >-
#   Policies to confirm the Release Plan file has the expected kind.
#
package policy.release_plan.basic

import future.keywords.contains
import future.keywords.if

import data.lib

expected_kind := "ReleasePlanAdmission"
expected_namespace := "rhtap-releng-tenant"

# METADATA
# title: Release Plan has expected kind
# description: >-
#   Confirm that the release plan has the kind "ReleasePlanAdmission".
# custom:
#   short_name: expected_kind
#   failure_msg: Unexpected kind '%s' for release plan admission
#
deny contains result if {
	expected_kind != input.kind
	result := lib.result_helper(rego.metadata.chain(), [input.kind])
}

# METADATA
# title: Release Plan has expected namespace
# description: >-
#   Confirm that the release plan has a namespace of "rhtap-releng-tenant".
# custom:
#   short_name: expected_namespace
#   failure_msg: Unexpected namespace '%s' for release plan admission
#
deny contains result if {
	expected_namespace != input.metadata.namespace
	result := lib.result_helper(rego.metadata.chain(), [input.metadata.namespace])
}

# METADATA
# title: Release Plan has cpe field
# description: >-
#   Confirm that the release plan has a cpe field.
# custom:
#   short_name: has_cpe
#   failure_msg: Release plan '%s' doesn't have cpe field
#
warn contains result if {
    not input.cpe
    result := lib.result_helper(rego.metadata.chain(), [input.metadata.name])
}

# METADATA
# title: Release Plan has non-null cpe value
# description: >-
#   Confirm that the release plan has a cpe field and a non-empty value
# custom:
#   short_name: has_non_null_cpe_value
#   failure_msg: Release plan '%s' doesn't have cpe field
#
warn contains result if {
    input.cpe == null
    result := lib.result_helper(rego.metadata.chain(), [input.metadata.name])
}

# METADATA
# title: Release Plan has non-empty string cpe value
# description: >-
#   Confirm that the release plan has a cpe field and the value isn't empty
# custom:
#   short_name: has_non_empty_cpe_value
#   failure_msg: Release plan '%s' doesn't have cpe field
#
warn contains result if {
    input.cpe == ""
    result := lib.result_helper(rego.metadata.chain(), [input.metadata.name])
}
