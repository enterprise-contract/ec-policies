#
# METADATA
# title: SLSA - Build - Build Service
# description: >-
#   The SLSA requirement states the following:
#
#   "All build steps ran using some build service, not on a
#   developer’s workstation."
#
#   This package verifies the requirement by asserting the image was
#   built by Tekton Pipelines.
#
package policy.release.slsa_build_build_service

import rego.v1

import data.lib

# METADATA
# title: SLSA Builder ID found
# description: >-
#   Verify that the attestation attribute predicate.builder.id is set.
# custom:
#   short_name: slsa_builder_id_found
#   failure_msg: Builder ID not set in attestation
#   solution: >-
#     The builder id in the attestation is missing. Make sure the build system
#     is setting the build id when generating an attestation.
#   collections:
#   - slsa3
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	not att.statement.predicate.builder.id
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: SLSA Builder ID is known and accepted
# description: >-
#   Verify that the attestation attribute predicate.builder.id is set to one
#   of the values in the `allowed_builder_ids` rule data, e.g.
#   "https://tekton.dev/chains/v2".
# custom:
#   short_name: slsa_builder_id_accepted
#   failure_msg: Builder ID %q is unexpected
#   solution: >-
#     Make sure the build id is set to an expected value. The expected values
#     are set in the xref:ec-cli:ROOT:configuration.adoc#_data_sources[data sources].
#   collections:
#   - slsa3
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	allowed_builder_ids := lib.rule_data(_rule_data_key)
	some att in lib.pipelinerun_attestations
	builder_id := att.statement.predicate.builder.id
	not builder_id in allowed_builder_ids
	result := lib.result_helper(rego.metadata.chain(), [builder_id])
}

# METADATA
# title: Allowed builder IDs provided
# description: >-
#   Confirm the `allowed_builder_ids` rule data was provided, since it is required by the policy
#   rules in this package.
# custom:
#   short_name: allowed_builder_ids_provided
#   failure_msg: "%s"
#   collections:
#   - slsa3
#   - redhat
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

# Verify allowed_builder_ids is a non-empty list of strings
_rule_data_errors contains msg if {
	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(_rule_data_key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
			"minItems": 1,
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, violation.error])
}

_rule_data_key := "allowed_builder_ids"
