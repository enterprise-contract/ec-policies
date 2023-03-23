package lib

# Values in data.rule_data_custom or data.rule_data
# will take precedence over these defaults.
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
	"failed_tests_results": [
		"FAILURE",
		"ERROR",
	],
	"skipped_tests_results": ["SKIPPED"],
	"warned_tests_results": ["WARNING"],
	#
	# Used in release/cve.go
	# Valid levels: "critical", "high", "medium", and "low"
	"restrict_cve_security_levels": ["critical", "high"],
	"warn_cve_security_levels": [],
}

# Returns the "first found" of the following:
#   data.rule_data__configuration__[key_name]
#   data.rule_data_custom[key_name]
#   data.rule_data[key_name]
#   rule_data_defaults[key_name]
#
# And falls back to an empty list if the key is not found anywhere.
#
rule_data(key_name) := value {
	# Expected to be defined under `configuration.rule_data` in the
	# ECP configuration data being used when EC is run.
	value := data.rule_data__configuration__[key_name]
} else := value {
	# Expected to be defined in a users custom data source accessed
	# via an oci bundle or (more likely) a git url.
	value := data.rule_data_custom[key_name]
} else := value {
	# Expected to be defined in a default data source accessed via
	# an oci bundle or a maybe a git url. See data/rule_data.yml.
	value := data.rule_data[key_name]
} else := value {
	# Default values defined in this file. See above.
	value := rule_data_defaults[key_name]
} else := value {
	# If the key is not found, default to an empty list
	value := []
}
