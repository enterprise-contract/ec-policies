package examples.attestation_checks

# This is a fragment of an attestation
# (I can't figure out how use the real file in a test...)
#
mock_data := {
	"_type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"builder": {"id": "https://tekton.dev/chains/v2"},
		"buildType": "https://tekton.dev/attestations/chains@v2",
	},
}

# Test the lower level function
test_attestation_type_ok {
	attestation_type_ok("https://in-toto.io/Statement/v0.1")
	not attestation_type_ok("http://in-toto.io/Statement/v0.1")
	not attestation_type_ok("foo")
}

# Test the deny rule
test_attestation_type_validation {
	# To begin with the attestation is valid so it should not deny
	not deny with data.attestation as mock_data

	# With a bad type value it should deny
	expected_msg := "Invalid value in attestation _type field: 'badtype'. Expecting one of the following: 'https://in-toto.io/Statement/v0.1'"
	deny == {"msg": expected_msg} with data.attestation as object.union(mock_data, {"_type": "badtype"})
}
