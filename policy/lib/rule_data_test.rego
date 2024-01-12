package lib_test

import rego.v1

import data.lib

test_rule_data if {
	lib.assert_equal(
		[
			40, # key0 value comes from data.rule_data__configuration__
			30, # key1 value comes from data.rule_data_custom
			20, # key2 value comes from data.rule_data
			10, # key3 value comes from lib.rule_data_defaults
			[], # key4 value is not defined
		],
		[
			lib.rule_data("key0"),
			lib.rule_data("key1"),
			lib.rule_data("key2"),
			lib.rule_data("key3"),
			lib.rule_data("key4"),
		],
	) with data.rule_data__configuration__ as {"key0": 40}
		with data.rule_data_custom as {"key0": 30, "key1": 30}
		with data.rule_data as {"key0": 20, "key1": 20, "key2": 20}
		with lib.rule_data_defaults as {"key3": 10}
}

test_rule_data_append_effective_on if {
	lib.assert_equal(
		[
			{
				"value": 10,
				"effective_on": lib.time.default_effective_on,
			},
			{
				"value": 20,
				"effective_on": "2024-01-01T00:00:00Z",
			},
			{
				"value": 30,
				"effective_on": "9999-01-01T00:00:00Z",
			},
		],
		[
			lib.rule_data_append_effective_on("key0"),
			lib.rule_data_append_effective_on("key1"),
			lib.rule_data_append_effective_on("key2"),
		],
	) with data.rule_data as {
			"key0": 10,
			"key1": {
				"value": 20,
				"effective_on": "2024-01-01T00:00:00Z",
			},
			"key2": {
				"value": 30,
				"effective_on": "9999-01-01T00:00:00Z",
			},
		}
}

# Need this for 100% coverage
test_rule_data_defaults if {
	lib.assert_not_empty(lib.rule_data_defaults)
}
