package lib_test

import data.lib

test_rule_data {
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

test_appending_custom_rule_data {
	lib.assert_equal(
		[
			["a", "b", "c", "d"],
			["a", "d"],
			["e"],
			"zap",
		],
		[
			# Test a few scenarios
			lib.rule_data("foo"),
			lib.rule_data("bar"),
			lib.rule_data("baz"),
			# Can't append to a non-array
			lib.rule_data("zip"),
		],
	) with data.rule_data as {"foo": ["a", "b"], "bar": ["a"], "zip": "zap"}
		with data.append_rule_data_custom as {"foo": ["c"], "baz": ["e"], "zip": ["zup"]}
		with data.append_rule_data__configuration__ as {"foo": ["d"], "bar": ["d"]}
}

# Need this for 100% coverage
test_rule_data_defaults {
	lib.assert_not_empty(lib.rule_data_defaults)
}
