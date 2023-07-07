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

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: SLSA Builder ID found
# description: >-
#   The attestation attribute predicate.builder.id is set.
# custom:
#   short_name: slsa_builder_id_found
#   failure_msg: Builder ID not set in attestation
#   solution: >-
#     The builder id in the attestation is missing. Make sure the build system
#     is setting the build id when generating an attestation.
#   collections:
#   - slsa2
#   - slsa3
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	not att.predicate.builder.id
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: SLSA Builder ID is known and accepted
# description: >-
#   The attestation attribute predicate.builder.id is set to one
#   of the values in the allowed_builder_ids rule data, e.g.
#   "https://tekton.dev/chains/v2".
# custom:
#   short_name: slsa_builder_id_accepted
#   failure_msg: Builder ID %q is unexpected
#   solution: >-
#     Make sure the build id is set to an expected value. The expected values
#     are set in the xref:ec-cli:ROOT:configuration.adoc#_data_sources[data sources].
#   collections:
#   - slsa2
#   - slsa3
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	allowed_builder_ids := lib.rule_data("allowed_builder_ids")
	some att in lib.pipelinerun_attestations
	builder_id := att.predicate.builder.id
	not builder_id in allowed_builder_ids
	result := lib.result_helper(rego.metadata.chain(), [builder_id])
}
