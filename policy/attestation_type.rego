package policy.attestation_type

import data.expected_attestation_types
import data.lib

#
# Using attestations, confirm they all have the expected attestation type
#
deny[msg] {
	# Deny if we can see an invalid type
	not attestation_type_valid(input._type)

	msg := sprintf(
		"Unexpected attestation type. Expecting %s but found %s",
		[lib.quoted_values_string(expected_attestation_types), input._type],
	)
}

attestation_type_valid(attestation_type) {
	lib.item_in_list(attestation_type, expected_attestation_types)
}
