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
#   collections:
#   - minimal
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
#   collections:
#   - minimal
#
deny contains result if {
	count(lib.pipelinerun_attestations) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}
