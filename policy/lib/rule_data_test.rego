package lib

import data.lib

test_rule_data {
	lib.assert_equal(
		[
			30, # key1 value comes from data.rule_data_custom
			20, # key2 value comes from data.rule_data
			10, # key3 value comes from lib.rule_data_defaults
			[], # key4 value is not defined
		],
		[
			lib.rule_data("key1"),
			lib.rule_data("key2"),
			lib.rule_data("key3"),
			lib.rule_data("key4"),
		],
	) with data.rule_data_custom as {"key1": 30}
		with data.rule_data as {"key1": 20, "key2": 20}
		with lib.rule_data_defaults as {"key3": 10}
}

# Need this for 100% coverage
test_rule_data_defaults {
	lib.assert_empty(lib.rule_data_defaults)
}
