package release

import data.lib

good_type := "https://in-toto.io/Statement/v0.1"

bad_type := "https://in-toto.io/Statement/v0.0.9999999"

two_mock_data(att_type) = d {
	d := [{"_type": att_type, "predicate": {"buildType": lib.pipelinerun_att_build_type}}]
}

test_allow_when_permitted {
	lib.assert_empty(deny_unknown_att_type) with input.attestations as two_mock_data(good_type)
}

test_deny_when_not_permitted {
	expected_msg := sprintf("Unknown attestation type '%s'", [bad_type])
	lib.assert_equal(deny_unknown_att_type, {{
		"code": "unknown_att_type",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as two_mock_data(bad_type)
}
