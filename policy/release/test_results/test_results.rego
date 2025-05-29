#
# METADATA
# title: Test Results Attestation
# description: >-
#   Rules that verify the test results attestations associated with the image being verified.
#
package test_results

import rego.v1

import data.lib
import data.lib.json as j

# METADATA
# title: Test Results Attestation
# description: >-
#   Verify that the image has at least one valid test results attestation with a passing result.
#   By default the same sigstore options used to verify the image are also used to verify the test
#   results attestations. Any test results attestations signed with a different key, or identity,
#   will be ignored. Use the `test_result_sigstore_opts` rule_data to configure alternate sigstore
#   options for the test results attestations.
# custom:
#   short_name: valid
#   failure_msg: "%s"
#
deny contains result if {
	some error in _errors
	result := object.union(
		lib.result_helper(rego.metadata.chain(), [error.message]),
		{"severity": error.severity},
	)
}

_errors contains error if {
	some raw_error in _verification_result.errors
	error := {
		"message": sprintf("Attestation verification failed: %s", [raw_error]),
		"severity": "failure",
	}
}

_errors contains error if {
	count(_test_results) == 0
	error := {
		"message": "No test result attestations found",
		"severity": "failure",
	}
}

_errors contains error if {
	some test_result in _test_results
	some e in j.validate_schema(test_result, _test_result_predicate_schema)
	error := {
		"message": sprintf("Test result has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

_errors contains error if {
	some test_result in _test_results
	test_result.result == "FAILED"
	error := {
		"message": "Test result is FAILED",
		"severity": "failure",
	}
}

_errors contains error if {
	some test_result in _test_results
	test_result.result == "WARNED"
	error := {
		"message": "Test result is WARNED",
		"severity": "warning",
	}
}

_verification_result := ec.sigstore.verify_attestation(input.image.ref, _test_result_sigstore_opts)

_test_result_sigstore_opts := opts if {
	opts := lib.rule_data("test_result_sigstore_opts")

	# Ignore the default rule_data value.
	opts != []
} else := lib.sigstore_opts

_test_results contains test_result if {
	some att in _verification_result.attestations
	att.statement.predicateType == _test_result_predicate_type
	test_result := att.statement.predicate
}

_test_result_predicate_type := "https://in-toto.io/attestation/test-result/v0.1"

_test_result_predicate_schema := {
	"type": "object",
	"required": ["result"],
	"properties": {
		"result": {
			"type": "string",
			"enum": ["PASSED", "WARNED", "FAILED"],
		},
		# Configuration is a ResourceDescriptor. See full definition at
		# https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
		"configuration": {
			"type": "array",
			"items": {"type": "object"},
		},
		"url": {
			"type": "string",
			"format": "uri",
		},
		"passedTests": {
			"type": "array",
			"items": {"type": "string"},
		},
		"failedTests": {
			"type": "array",
			"items": {"type": "string"},
		},
		"warnedTests": {
			"type": "array",
			"items": {"type": "string"},
		},
	},
}
