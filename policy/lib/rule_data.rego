package lib

# Will define built-in default values here.
# They can be overridden if required.
#
rule_data_defaults := {
	#
	# Used in release/attestation_type
	"known_attestation_types": ["https://in-toto.io/Statement/v0.1"],
	#
	# Used in release/slsa_provenance_available
	"allowed_predicate_types": ["https://slsa.dev/provenance/v0.2"],
	#
	# Used in release/slsa_build_build_service
	"allowed_builder_ids": ["https://tekton.dev/chains/v2"],
	#
	# Used in release/test.rego
	"supported_tests_results": [
		"SUCCESS",
		"FAILURE",
		"ERROR",
		"SKIPPED",
		"WARNING",
	],
}

# Returns the "first found" of the following:
#   data.rule_data_custom[key_name]
#   data.rule_data[key_name]
#   rule_data_defaults[key_name]
#
# And falls back to an empty list if the key is not found anywhere.
#
rule_data(key_name) := value {
	value := data.rule_data_custom[key_name]
} else := value {
	value := data.rule_data[key_name]
} else := value {
	value := rule_data_defaults[key_name]
} else := value {
	value := []
}
