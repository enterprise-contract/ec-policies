package policy.release.attestation_type

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
deny[result] {
	att := lib.pipelinerun_attestations[_]
	att_type := att._type
	not lib.included_in(att_type, rego.metadata.rule().custom.rule_data.known_attestation_types)
	result := lib.result_helper(rego.metadata.chain(), [att_type])
}
