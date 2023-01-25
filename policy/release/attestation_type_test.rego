package policy.release.attestation_type

import data.lib

good_type := "https://in-toto.io/Statement/v0.1"

bad_type := "https://in-toto.io/Statement/v0.0.9999999"

mock_data(att_type) = d {
	d := [{"_type": att_type, "predicate": {"buildType": lib.pipelinerun_att_build_types[0]}}]
}

test_allow_when_permitted {
	lib.assert_empty(deny) with input.attestations as mock_data(good_type)
}

test_deny_when_not_permitted {
	expected_msg := sprintf("Unknown attestation type '%s'", [bad_type])
	lib.assert_equal(deny, {{
		"code": "attestation_type.unknown_att_type",
		"collections": ["minimal"],
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as mock_data(bad_type)
}

test_deny_when_missing_pipelinerun_attestations {
	expected := {{
		"code": "attestation_type.missing_pipelinerun_attestation",
		"collections": ["minimal"],
		"msg": "Missing pipelinerun attestation",
		"effective_on": "2022-01-01T00:00:00Z",
	}}
	attestations := [
		{
			"_type": good_type,
			"predicate": {"buildType": "tekton.dev/v1beta1/TaskRun"},
		},
		{
			"_type": good_type,
			"predicate": {"buildType": "spam/spam/eggs/spam"},
		},
	]
	lib.assert_equal(deny, expected) with input.attestations as attestations
}
