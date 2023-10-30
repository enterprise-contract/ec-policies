package policy.release.attestation_type_test

import data.lib
import data.policy.release.attestation_type

good_type := "https://in-toto.io/Statement/v0.1"

bad_type := "https://in-toto.io/Statement/v0.0.9999999"

mock_data(att_type) := [{"statement": {
	"_type": att_type,
	"predicate": {"buildType": lib.tekton_pipeline_run},
}}]

test_allow_when_permitted {
	lib.assert_empty(attestation_type.deny) with input.attestations as mock_data(good_type)
}

test_deny_when_not_permitted {
	expected_msg := sprintf("Unknown attestation type '%s'", [bad_type])
	lib.assert_equal_results(attestation_type.deny, {{
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
		{"statement": {
			"_type": good_type,
			"predicate": {"buildType": "tekton.dev/v1beta1/TaskRun"},
		}},
		{"statement": {
			"_type": good_type,
			"predicate": {"buildType": "spam/spam/eggs/spam"},
		}},
	]
	lib.assert_equal_results(attestation_type.deny, expected) with input.attestations as attestations
}

test_deny_deprecated_policy_attestation_format {
	expected := {
		{
			"code": "attestation_type.deprecated_policy_attestation_format",
			"msg": "Deprecated policy attestation format found",
		},
		{
			"code": "attestation_type.pipelinerun_attestation_found",
			"msg": "Missing pipelinerun attestation",
		},
	}
	attestations := [{
		"_type": good_type,
		"predicate": {"buildType": lib.tekton_pipeline_run},
	}]
	lib.assert_equal_results(attestation_type.deny, expected) with input.attestations as attestations
}
