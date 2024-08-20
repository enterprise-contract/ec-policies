package policy.release.rhtap_jenkins_test

import rego.v1

import data.lib
import data.policy.release.rhtap_jenkins

test_jenkins_atts_happy_path if {
	lib.assert_empty(rhtap_jenkins.deny) with input.attestations as [good_att]
	lib.assert_empty(rhtap_jenkins.deny) with input.attestations as [bad_att, good_att]
}

test_jenkins_atts_missing if {
	# Note we don't get the "invocation_id_required" deny when there are no attestations found
	expected := {
		"code": "rhtap_jenkins.attestation_found",
		# regal ignore:line-length
		"msg": "The expected SLSA v1.0 provenance with build type https://redhat.com/rhtap/slsa-build-types/jenkins-build/v1 was not found.",
	}

	lib.assert_equal_results({expected}, rhtap_jenkins.deny) with input.attestations as []
	lib.assert_equal_results({expected}, rhtap_jenkins.deny) with input.attestations as [bad_att]
}

test_invocation_id_missing if {
	expected := {
		"code": "rhtap_jenkins.invocation_id_found",
		"msg": "The build provenance metadata did not contain an invocation id.",
	}
	lib.assert_equal_results({expected}, rhtap_jenkins.deny) with input.attestations as [bad_invocation_1]
	lib.assert_equal_results({expected}, rhtap_jenkins.deny) with input.attestations as [bad_invocation_2]
}

good_build_type := "https://redhat.com/rhtap/slsa-build-types/jenkins-build/v1"

good_att := mock_att(good_build_type, {"metadata": {"invocationID": "hello"}})

bad_att := mock_att("https://bogus/build/type/v1", {})

bad_invocation_1 := mock_att(good_build_type, {"metadata": {}})

bad_invocation_2 := mock_att(good_build_type, {"metadata": {"invocationID": " "}})

mock_att(build_type, run_details) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {"buildType": build_type},
		"runDetails": run_details,
	},
}}
