package test_results_test

import rego.v1

import data.lib
import data.test_results

test_success if {
	lib.assert_empty(test_results.deny) with input as mock_input
		with ec.sigstore.verify_attestation as {"attestations": [mock_valid_attestation]}
}

test_failing_verification if {
	mock_verification_result := {
		"errors": ["invalid signature"],
		"attestations": [],
	}

	# TODO: Remove duplicated error?
	expected := {
		{
			"code": "test_results.valid",
			"msg": "Attestation verification failed: invalid signature",
			"severity": "failure",
		},
		{
			"code": "test_results.valid",
			"msg": "No test result attestations found",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(expected, test_results.deny) with input as mock_input
		with ec.sigstore.verify_attestation as mock_verification_result
}

test_no_test_results if {
	expected := {{
		"code": "test_results.valid",
		"msg": "No test result attestations found",
		"severity": "failure",
	}}

	lib.assert_equal_results(expected, test_results.deny) with input as mock_input
		with ec.sigstore.verify_attestation as {"attestations": []}
}

test_invalid_schema if {
	expected := {{
		"code": "test_results.valid",
		# regal ignore:line-length
		"msg": `Test result has unexpected format: result: result must be one of the following: "PASSED", "WARNED", "FAILED"`,
		"severity": "failure",
	}}

	lib.assert_equal_results(expected, test_results.deny) with input as mock_input
		with ec.sigstore.verify_attestation as {"attestations": [mock_invalid_schema_attestation]}
}

test_failed_result if {
	expected := {{
		"code": "test_results.valid",
		"msg": "Test result is FAILED",
		"severity": "failure",
	}}

	lib.assert_equal_results(expected, test_results.deny) with input as mock_input
		with ec.sigstore.verify_attestation as {"attestations": [mock_failed_attestation]}
}

test_warning_result if {
	expected := {{
		"code": "test_results.valid",
		"msg": "Test result is WARNED",
		"severity": "warning",
	}}

	lib.assert_equal_results(expected, test_results.deny) with input as mock_input
		with ec.sigstore.verify_attestation as {"attestations": [mock_warned_attestation]}
}

test_default_sigstore_opts if {
	expected := {{
		"code": "test_results.valid",
		"msg": sprintf("Attestation verification failed: opts: %v", [lib.sigstore_opts]),
		"severity": "failure",
	}}
	lib.assert_equal_results(expected, test_results.deny) with input as mock_input
		with ec.sigstore.verify_attestation as mock_sigstore_opts
}

test_custom_sigstore_opts if {
	expected := {{
		"code": "test_results.valid",
		"msg": sprintf("Attestation verification failed: opts: %v", [custom_sigstore_opts]),
		"severity": "failure",
	}}
	lib.assert_equal_results(expected, test_results.deny) with input as mock_input
		with ec.sigstore.verify_attestation as mock_sigstore_opts
		with data.rule_data.test_result_sigstore_opts as custom_sigstore_opts
}

# The mock function always produces an error which includes the opts used. It can be used to verify
# the expected opts are used. It also produces a valid attestation to avoid duplicated errors.
mock_sigstore_opts(_, opts) := {
	"errors": [sprintf("opts: %v", [opts])],
	"attestations": [mock_valid_attestation],
}

custom_sigstore_opts := {
	"certificate_identity": "custom-certificate-identity",
	"certificate_identity_regexp": "custom-certificate-identity-regexp",
	"certificate_oidc_issuer": "custom-oidc-issuer",
	"certificate_oidc_issuer_regexp": "custom-oidc-issuer-regexp",
	"ignore_rekor": true,
	"public_key": "custom-public-key",
	"rekor_url": "custom-rekor-url",
}

mock_input := {"image": {"ref": "example.com/image:tag"}}

mock_valid_attestation := {"statement": {
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"predicate": {
		"result": "PASSED",
		"url": "https://example.com/test-results",
		"passedTests": ["test1", "test2"],
		"failedTests": [],
		"warnedTests": [],
	},
}}

mock_failed_attestation := {"statement": {
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"predicate": {
		"result": "FAILED",
		"url": "https://example.com/test-results",
		"passedTests": ["test1"],
		"failedTests": ["test2"],
		"warnedTests": [],
	},
}}

mock_warned_attestation := {"statement": {
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"predicate": {
		"result": "WARNED",
		"url": "https://example.com/test-results",
		"passedTests": ["test1"],
		"failedTests": [],
		"warnedTests": ["test2"],
	},
}}

mock_invalid_schema_attestation := {"statement": {
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"predicate": {
		"result": "UNKNOWN", # Invalid enum value
		"url": "https://example.com/test-results",
	},
}}
