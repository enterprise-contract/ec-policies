package policies.attestation_type

import data.lib

#
# Using attestations, confirm they all have the expected attestation type
#
deny[{"msg": msg}] {
	att := input.attestations[_]
	att_data_type := att._type

	# Deny if we can see an invalid type
	not attestation_type_valid(att_data_type)

	msg := sprintf(
		"Unexpected attestation type. Expecting %s but found %s",
		[lib.quoted_values_string(lib.config.expected_attestation_types), att_data_type],
	)
}

attestation_type_valid(attestation_type) {
	lib.item_in_list(attestation_type, lib.config.expected_attestation_types)
}
