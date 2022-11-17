package policy.release.slsa_build_build_service

import future.keywords.if

import data.lib

test_all_good if {
	# NOTE: _allowed_builder_ids[_] does not work as expected here because it only reports
	# a test failure if *all* cases fail.
	lib.assert_empty(deny) with data.rule_data.allowed_builder_ids as _allowed_builder_ids
		with input.attestations as [_mock_attestation(_allowed_builder_ids[0])]

	lib.assert_empty(deny) with data.rule_data.allowed_builder_ids as _allowed_builder_ids
		with input.attestations as [_mock_attestation(_allowed_builder_ids[1])]
}

test_missing_builder_id if {
	attestations := [
		# Missing predicate.builder.id
		{"predicate": {
			"builder": {},
			"buildType": lib.pipelinerun_att_build_types[0],
		}},
		# Missing predicate.builder
		{"predicate": {"buildType": lib.pipelinerun_att_build_types[0]}},
	]

	expected := {{
		"code": "missing_builder_id",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Builder ID not set in attestation",
	}}

	lib.assert_equal(expected, deny) with data.rule_data.allowed_builder_ids as _allowed_builder_ids
		with input.attestations as attestations
}

test_unexpected_builder_id if {
	builder_id := "https://notket.ved/sniahc/2v"
	expected := {{
		"code": "unexpected_builder_id",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Builder ID \"https://notket.ved/sniahc/2v\" is unexpected",
	}}
	lib.assert_equal(expected, deny) with data.rule_data.allowed_builder_ids as _allowed_builder_ids
		with input.attestations as [_mock_attestation(builder_id)]
}

_mock_attestation(builder_id) = d if {
	d := {"predicate": {
		"builder": {"id": builder_id},
		"buildType": lib.pipelinerun_att_build_types[0],
	}}
}

_allowed_builder_ids := ["https://tekton.dev/chains/v2", "https://something/else/v99"]
