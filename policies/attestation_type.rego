package policies.attestation_type

import data.lib

# Currently this is the only type we know about
known_types := ["https://in-toto.io/Statement/v0.1"]

# METADATA
# title: An unknown attestation type was found
# description: |-
#   A sanity check that the attestation found for the image has the expected
#   attestation type. Currently there type is only one attestation type supported,
#   `https://in-toto.io/Statement/v0.1`.
# custom:
#   short_name: unknown_att_type
#   failure_msg: Unknown attestation type '%s'
#
deny[result] {
	att := input.attestations[_]
	att_type := att._type
	not known_att_type(att_type)
	result := lib.result_helper(rego.metadata.rule(), [att_type])
}

known_att_type(att_type) {
	lib.item_in_list(att_type, known_types)
}
