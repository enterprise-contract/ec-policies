package lib_test

import rego.v1

import data.lib

test_result_helper if {
	expected_result := {
		"code": "oh.Hey",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Bad thing foo",
	}

	rule_annotations := {"custom": {
		"short_name": "Hey",
		"failure_msg": "Bad thing %s",
	}}

	chain := [
		{"annotations": rule_annotations, "path": []},
		{"annotations": {}, "path": ["ignored", "oh"]},
	]

	lib.assert_equal(expected_result, lib.result_helper(chain, ["foo"]))
}

test_result_helper_with_collections if {
	expected := {
		"code": "oh.Hey",
		"collections": ["spam"],
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Bad thing foo",
	}

	rule_annotations := {"custom": {
		"collections": ["spam"],
		"short_name": "Hey",
		"failure_msg": "Bad thing %s",
	}}

	chain := [
		{"annotations": rule_annotations, "path": []},
		{"annotations": {}, "path": ["ignored", "oh"]},
	]

	lib.assert_equal(expected, lib.result_helper(chain, ["foo"]))
}

test_result_helper_with_term if {
	expected := {
		"code": "oh.Hey",
		"term": "ola",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Bad thing foo",
	}

	rule_annotations := {"custom": {
		"short_name": "Hey",
		"failure_msg": "Bad thing %s",
	}}

	chain := [
		{"annotations": rule_annotations, "path": []},
		{"annotations": {}, "path": ["ignored", "oh"]},
	]

	lib.assert_equal(expected, lib.result_helper_with_term(chain, ["foo"], "ola"))
}
