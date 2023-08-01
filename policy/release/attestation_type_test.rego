package policy.release.attestation_type

import data.lib

good_type := "https://in-toto.io/Statement/v0.1"

bad_type := "https://in-toto.io/Statement/v0.0.9999999"

mock_data(att_type) = d {
	d := [{
		"_type": att_type,
		"predicate": {"buildType": lib.pipelinerun_att_build_types[0]},
		"statement": {"_type": att_type, "predicate": {"buildType": lib.pipelinerun_att_build_types[0]}},
	}]
}

test_allow_when_permitted {
	lib.assert_empty(deny) with input.attestations as mock_data(good_type)
}

test_deny_when_not_permitted {
	expected_msg := sprintf("Unknown attestation type '%s'", [bad_type])
	lib.assert_equal_results(deny, {{
		"code": "attestation_type.known_attestation_type",
		"msg": expected_msg,
	}}) with input.attestations as mock_data(bad_type)
}

test_deny_when_pipelinerun_attestation_founds {
	expected := {{
		"code": "attestation_type.pipelinerun_attestation_found",
		"msg": "Missing pipelinerun attestation",
	}}
	attestations := [
		{
			"_type": good_type,
			"predicate": {"buildType": "tekton.dev/v1beta1/TaskRun"},
			"statement": {
				"_type": good_type,
				"predicate": {"buildType": "tekton.dev/v1beta1/TaskRun"},
			},
		},
		{
			"_type": good_type,
			"predicate": {"buildType": "spam/spam/eggs/spam"},
			"statement": {
				"_type": good_type,
				"predicate": {"buildType": "spam/spam/eggs/spam"},
			},
		},
	]
	lib.assert_equal_results(deny, expected) with input.attestations as attestations
}

test_deny_deprecated_policy_attestation_format {
	expected := {{
		"code": "attestation_type.deprecated_policy_attestation_format",
		"msg": "Deprecated policy attestation format found",
	}}
	attestations := [{
		"_type": good_type,
		"predicate": {"buildType": lib.pipelinerun_att_build_types[0]},
	}]
	lib.assert_equal_results(deny, expected) with input.attestations as attestations
}
