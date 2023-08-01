#
# METADATA
# description: >-
#   Sanity checks related to the format of the image build's attestation.
#
package policy.release.attestation_type

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Known attestation type found
# description: >-
#   A sanity check to confirm the attestation found for the image has a known
#   attestation type.
# custom:
#   short_name: known_attestation_type
#   failure_msg: Unknown attestation type '%s'
#   solution: >-
#     Make sure the "_type" field in the attestation is supported. Supported types are configured
#     in xref:ec-cli:ROOT:configuration.adoc#_data_sources[data sources].
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - attestation_type.pipelinerun_attestation_found
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	att_type := att._type
	not att_type in lib.rule_data("known_attestation_types")
	result := lib.result_helper(rego.metadata.chain(), [att_type])
}

# METADATA
# title: PipelineRun attestation found
# description: >-
#   At least one PipelineRun attestation must be present.
# custom:
#   short_name: pipelinerun_attestation_found
#   failure_msg: Missing pipelinerun attestation
#   solution: >-
#     Make sure the attestation being verified was generated from a Tekton pipelineRun.
#   collections:
#   - minimal
#   - redhat
#
deny contains result if {
	count(lib.pipelinerun_attestations) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Deprecated policy attestation format
# description: >-
#   The Enterprise Contract CLI now places the attestation data in a different location.
#   This check fails if the expected new format is not found.
# custom:
#   short_name: deprecated_policy_attestation_format
#   failure_msg: Deprecated policy attestation format found
#   solution: Use a newer version of the Enterprise Contract CLI.
#   collections:
#   - minimal
#   - redhat
#   effective_on: 2023-08-31T00:00:00Z
deny contains result if {
	# Use input.attestations directly so we can detect the actual format in use.
	some att in input.attestations
	not att.statement
	result := lib.result_helper(rego.metadata.chain(), [])
}
