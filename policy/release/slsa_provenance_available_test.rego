package policy.release.slsa_provenance_available_test

import future.keywords.in

import data.lib
import data.policy.release.slsa_provenance_available

test_expected_predicate_type {
	attestations := _mock_attestations(["https://slsa.dev/provenance/v0.2"])
	lib.assert_empty(slsa_provenance_available.deny) with input.attestations as attestations
}

test_att_predicate_type {
	attestations := _mock_attestations(["spam"])
	expected_deny := {{
		"code": "slsa_provenance_available.attestation_predicate_type_accepted",
		"msg": "Attestation predicate type \"spam\" is not an expected type (https://slsa.dev/provenance/v0.2)",
	}}
	lib.assert_equal_results(slsa_provenance_available.deny, expected_deny) with input.attestations as attestations
}

_mock_attestations(types) := [attestation |
	some type in types
	attestation := {"statement": {
		"predicateType": type,
		"predicate": {"buildType": lib.tekton_pipeline_run},
	}}
]
