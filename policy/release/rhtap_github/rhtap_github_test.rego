package rhtap_github_test

import rego.v1

import data.lib
import data.rhtap_github

test_github_atts_happy_path if {
	lib.assert_empty(rhtap_github.deny) with input.attestations as [good_att]
	lib.assert_empty(rhtap_github.deny) with input.attestations as [bad_att, good_att]
}

test_github_atts_missing if {
	expected := {
		"code": "rhtap_github.attestation_found",
		# regal ignore:line-length
		"msg": "The expected SLSA v1.0 provenance with build type https://redhat.com/rhtap/slsa-build-types/github-build/v1 was not found.",
	}

	lib.assert_equal_results({expected}, rhtap_github.deny) with input.attestations as []
	lib.assert_equal_results({expected}, rhtap_github.deny) with input.attestations as [bad_att]
}

good_build_type := "https://redhat.com/rhtap/slsa-build-types/github-build/v1"

good_att := mock_att(good_build_type, {})

bad_att := mock_att("https://bogus/build/type/v1", {})

mock_att(build_type, run_details) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {"buildType": build_type},
		"runDetails": run_details,
	},
}}
