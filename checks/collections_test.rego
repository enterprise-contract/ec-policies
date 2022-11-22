package checks

import data.lib

test_valid_collection {
	lib.assert_empty(violation) with input as {"namespaces": {
		"data.policy.release.rule1": [],
		"data.policy.release.rule2": [],
		"data.policy.release.rule3": [],
	}}
		with data.rule_collections as {"collection": {
			"include": ["rule1", "rule3"],
			"exclude": ["rule2"],
		}}
}

test_invalid_collection {
	lib.assert_equal({"ERROR: The collection `collection` references non-existant package(s): rule1, rule2"}, violation) with input as {"namespaces": {
		"data.policy.release.rule3": [],
		"data.policy.release.rule4": [],
	}}
		with data.rule_collections as {"collection": {
			"include": ["rule1"],
			"exclude": ["rule2"],
		}}
}
