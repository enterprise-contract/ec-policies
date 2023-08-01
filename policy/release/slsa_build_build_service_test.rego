package policy.release.slsa_build_build_service

import future.keywords.if

import data.lib

test_all_good if {
	builder_id := lib.rule_data("allowed_builder_ids")[0]
	lib.assert_empty(deny) with input.attestations as [_mock_attestation(builder_id)]
}

test_slsa_builder_id_found if {
	attestations := [
		# Missing predicate.builder.id
		{"statement": {"predicate": {
			"builder": {},
			"buildType": lib.pipelinerun_att_build_types[0],
		}}},
		# Missing predicate.builder
		{"statement": {"predicate": {"buildType": lib.pipelinerun_att_build_types[0]}}},
	]

	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_found",
		"msg": "Builder ID not set in attestation",
	}}

	lib.assert_equal_results(expected, deny) with input.attestations as attestations
}

test_accepted_slsa_builder_id if {
	builder_id := "https://notket.ved/sniahc/2v"
	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_accepted",
		"msg": "Builder ID \"https://notket.ved/sniahc/2v\" is unexpected",
	}}
	lib.assert_equal_results(expected, deny) with input.attestations as [_mock_attestation(builder_id)]
}

_mock_attestation(builder_id) = d if {
	d := {"statement": {"predicate": {
		"builder": {"id": builder_id},
		"buildType": lib.pipelinerun_att_build_types[0],
	}}}
}
