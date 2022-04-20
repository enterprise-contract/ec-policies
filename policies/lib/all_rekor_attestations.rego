package lib

#
# A list of all attestations from rekor data
#
# The result is a list of hashes with three keys,
# "rekor_host", "log_index", and "data".
#
all_rekor_attestations = attestations {
	attestations := [attestation |
		rekor_hosts := data.rekor[rekor_host]
		log_entry := rekor_hosts.index[log_index].entry
		attestation := {
			"rekor_host": rekor_host,
			"log_index": log_index,
			"data": decode_attestation(log_entry.Attestation),
		}
	]
}

#
# Extract an attestation from a transparency log entry
#
decode_attestation(encoded_attestation) = result {
	result := json.unmarshal(base64.decode(encoded_attestation))
}
