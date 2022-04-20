package hacbs.contract.attestation_type

import data.lib

#
# Using attestations extracted from rekor transparency log entries,
# confirm they all have the expected attestation type
#
deny[{"msg": msg}] {
	att := lib.all_rekor_attestations[_]
	att_data_type := att.data._type

	# Deny if we can see an invalid type
	not attestation_type_valid(att_data_type)

	msg := sprintf(
		"Unexpected attestation type in transparency log entry %s on %s. Expecting %s but found %s",
		[att.log_index, att.rekor_host, lib.quoted_values_string(lib.config.expected_attestation_types), att_data_type],
	)
}

attestation_type_valid(attestation_type) {
	lib.item_in_list(attestation_type, lib.config.expected_attestation_types)
}
