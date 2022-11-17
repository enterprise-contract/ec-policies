#
# METADATA
# title: SLSA - Build - Build Service
# description: |-
#   The SLSA requirement states the following:
#
#   "All build steps ran using some build service, not on a
#   developer’s workstation."
#
#   This package verifies the requirement by asserting the image was
#   built by Tekton Pipelines.
#
package policy.release.slsa_build_build_service

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Builder ID exists
# description: |-
#   The attestation attribute predicate.builder.id is set.
# custom:
#   short_name: missing_builder_id
#   failure_msg: Builder ID not set in attestation
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	not att.predicate.builder.id
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Build service used
# description: |-
#   The attestation attribute predicate.builder.id is set to one
#   of the values in data.rule_data.allowed_builder_ids, e.g.
#   "https://tekton.dev/chains/v2".
# custom:
#   short_name: unexpected_builder_id
#   failure_msg: Builder ID %q is unexpected
#
deny contains result if {
	allowed_builder_ids := data.rule_data.allowed_builder_ids
	some att in lib.pipelinerun_attestations
	builder_id := att.predicate.builder.id
	not builder_id in allowed_builder_ids
	result := lib.result_helper(rego.metadata.chain(), [builder_id])
}
