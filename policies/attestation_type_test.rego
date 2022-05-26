package policies.attestation_type

import data.lib

good_type := "https://in-toto.io/Statement/v0.1"

bad_type := "https://in-toto.io/Statement/v0.0.9999999"

mock_data(att_type) = d {
	d := [{"_type": att_type, "predicate": {"buildType": lib.pipelinerun_att_build_type}}]
}

test_known_att_type {
	known_att_type(good_type)
	not known_att_type(bad_type)
	not known_att_type("asdf")
}

test_allow_when_permitted {
	lib.assert_empty(deny) with input.attestations as mock_data(good_type)
}

test_deny_when_not_permitted {
	expected_msg := sprintf("Unknown attestation type '%s'", [bad_type])
	lib.assert_equal(deny, {{"code": "unknown_att_type", "msg": expected_msg}}) with input.attestations as mock_data(bad_type)
}
