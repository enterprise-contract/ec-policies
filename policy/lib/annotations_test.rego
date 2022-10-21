package lib

import data.lib

test_rule_data {
	metadata := {"custom": {"rule_data": {"breakfast": [
		"spam",
		"bacon",
		"eggs",
	]}}}
	expected_breakfast := ["spam", "bacon", "eggs"]
	lib.assert_equal(expected_breakfast, rule_data(metadata, "breakfast"))

	not rule_data(metadata, "lunch")
}
