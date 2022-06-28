# METADATA
# custom:
#   effective_on: 2001-02-03T00:00:00Z
#   scope: package
package lib.time

import data.lib

future_timestamp := time.add_date(time.now_ns(), 0, 0, 1)

# METADATA
# custom:
#   effective_on: 2004-05-06T00:00:00Z
test_when_rule_precedence {
	when(rego.metadata.chain()) == "2004-05-06T00:00:00Z"
}

test_when_package_precedence {
	when(rego.metadata.chain()) == "2001-02-03T00:00:00Z"
}

test_effective_current_time_ns {
	lib.assert_equal(effective_current_time_ns, time.now_ns()) # with no config at all
	lib.assert_equal(effective_current_time_ns, time.now_ns()) with data.config as {} # no config.policy
	lib.assert_equal(effective_current_time_ns, time.now_ns()) with data.config.policy as {} # no config.policy.when_ns
	lib.assert_equal(effective_current_time_ns, lib.time.future_timestamp) with data.config.policy.when_ns as lib.time.future_timestamp
}

test_most_current {
	# Ignore future item
	items := [
		{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
		{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
		{"name": "ancient", "effective_on": "1985-01-01T00:00:00Z"},
	]

	lib.assert_equal(most_current(items), items[1])

	# Empty list of items yiels no value
	not most_current([])

	# Empty list of *current* items yields no value
	future_items = [
		{"name": "supernova", "effective_on": "2299-01-01T00:00:00Z"},
		{"name": "visionary", "effective_on": "2199-01-01T00:00:00Z"},
		{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
	]

	not most_current(future_items)

	# Items without an effective_on value are ignored
	incomplete_items := [
		{"name": "incomplete"},
		{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
	]

	lib.assert_equal(most_current(incomplete_items), incomplete_items[1])
}
