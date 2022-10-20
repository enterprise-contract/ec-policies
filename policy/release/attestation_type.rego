#
# METADATA
# description: |-
#   Sanity checks related to the format of the image build's attestation.
#
package policy.release.attestation_type

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Unknown attestation type found
# description: |-
#   A sanity check to confirm the attestation found for the image has a known
#   attestation type.
# custom:
#   short_name: unknown_att_type
#   failure_msg: Unknown attestation type '%s'
#   rule_data:
#     known_attestation_types:
#     - https://in-toto.io/Statement/v0.1
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	known_attestation_types := lib.rule_data(rego.metadata.rule(), "known_attestation_types")
	att_type := att._type
	not att_type in known_attestation_types
	result := lib.result_helper(rego.metadata.chain(), [att_type])
}
