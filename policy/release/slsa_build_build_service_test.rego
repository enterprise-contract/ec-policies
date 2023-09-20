package policy.release.slsa_build_build_service_test

import future.keywords.if

import data.lib
import data.policy.release.slsa_build_build_service

test_all_good if {
	builder_id := lib.rule_data("allowed_builder_ids")[0]
	lib.assert_empty(slsa_build_build_service.deny) with input.attestations as [_mock_attestation(builder_id)]
}

test_slsa_builder_id_found if {
	attestations := [
		# Missing predicate.builder.id
		{"statement": {"predicate": {
			"builder": {},
			"buildType": lib.tekton_pipeline_run,
		}}},
		# Missing predicate.builder
		{"statement": {"predicate": {"buildType": lib.tekton_pipeline_run}}},
	]

	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_found",
		"msg": "Builder ID not set in attestation",
	}}

	lib.assert_equal_results(expected, slsa_build_build_service.deny) with input.attestations as attestations
}

test_accepted_slsa_builder_id if {
	builder_id := "https://notket.ved/sniahc/2v"
	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_accepted",
		"msg": "Builder ID \"https://notket.ved/sniahc/2v\" is unexpected",
	}}
	lib.assert_equal_results(
		expected,
		slsa_build_build_service.deny,
	) with input.attestations as [_mock_attestation(builder_id)]
}

_mock_attestation(builder_id) := {"statement": {"predicate": {
	"builder": {"id": builder_id},
	"buildType": lib.tekton_pipeline_run,
}}}
