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
	lib.assert_equal(
		most_current([
			{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
			{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
			{"name": "ancient", "effective_on": "1985-01-01T00:00:00Z"},
		]),
		{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
	)

	# Produce no value when input is an empty list
	not most_current([])

	# Produce no value if there are no current items
	not most_current([
		{"name": "supernova", "effective_on": "2262-04-11T00:00:00Z"},
		{"name": "visionary", "effective_on": "2199-01-01T00:00:00Z"},
		{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
	])

	# Ignore items without effective_on
	lib.assert_equal(
		most_current([
			{"name": "incomplete"},
			{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
			{"name": "lacking"},
		]),
		{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
	)
}

test_future_items {
	# Ignore items in the past
	lib.assert_equal(
		future_items([
			{"name": "supernova", "effective_on": "2262-04-11T00:00:00Z"},
			{"name": "visionary", "effective_on": "2199-01-01T00:00:00Z"},
			{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
			{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
			{"name": "ancient", "effective_on": "1985-01-01T00:00:00Z"},
		]),
		[
			{"name": "supernova", "effective_on": "2262-04-11T00:00:00Z"},
			{"name": "visionary", "effective_on": "2199-01-01T00:00:00Z"},
			{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
		],
	)

	# Return empty list when input is an empty list
	lib.assert_equal(future_items([]), [])

	# Return empty list when all items are in the past
	lib.assert_equal(
		future_items([
			{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
			{"name": "ancient", "effective_on": "1985-01-01T00:00:00Z"},
			{"name": "dino", "effective_on": "1965-01-01T00:00:00Z"},
		]),
		[],
	)

	# Ignore items without effective_on
	lib.assert_equal(
		future_items([
			{"name": "incomplete"},
			{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
			{"name": "lacking"},
		]),
		[{"name": "future", "effective_on": "2099-01-01T00:00:00Z"}],
	)
}

test_acceptable_items {
	# Include future items and most current
	lib.assert_equal(
		acceptable_items([
			{"name": "supernova", "effective_on": "2262-04-11T00:00:00Z"},
			{"name": "visionary", "effective_on": "2199-01-01T00:00:00Z"},
			{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
			{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
			{"name": "ancient", "effective_on": "1985-01-01T00:00:00Z"},
		]),
		[
			{"name": "supernova", "effective_on": "2262-04-11T00:00:00Z"},
			{"name": "visionary", "effective_on": "2199-01-01T00:00:00Z"},
			{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
			{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
		],
	)

	# Most current item is optional
	lib.assert_equal(
		acceptable_items([
			{"name": "supernova", "effective_on": "2262-04-11T00:00:00Z"},
			{"name": "visionary", "effective_on": "2199-01-01T00:00:00Z"},
			{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
		]),
		[
			{"name": "supernova", "effective_on": "2262-04-11T00:00:00Z"},
			{"name": "visionary", "effective_on": "2199-01-01T00:00:00Z"},
			{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
		],
	)

	# Return empty list when input is an empty list
	lib.assert_equal(future_items([]), [])
}
