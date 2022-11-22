# The package name is different than the package under test, "_test" suffix.
# This is to avoid the recursive rule error since the test must reference the
# package under test by name in these particular tests.
package examples.release.time_based_test

import data.lib

in_the_future := {"msg": "Roads?", "effective_on": "2099-05-02T00:00:00Z"}

no_effective_date := {"msg": "no effective date"}

in_the_past := {"msg": "from the past", "effective_on": "1970-01-01T01:00:00Z"}

y2k := {"msg": "Y2K", "effective_on": "2000-01-01T00:00:00Z"}

test_not_effective_by_default {
	# The time based filtering happens automatically on the real polices. Replace
	# those with our example policy.
	# time_based policy has effective_on far into the future, if you're reading
	# this then bump it for another 100 years
	lib.assert_equal({no_effective_date, in_the_past, y2k}, data.release.main.deny) with data.policy.release as {data.examples.release.time_based}
		with data.config.policy.exclude as []
}

test_effective_with_time_travel {
	# Set the date/time to the future where the example policy becomes effective.
	policy_config := {"exclude": [], "when_ns": time.parse_rfc3339_ns("2099-05-02T00:00:00Z")}

	# The time based filtering happens automatically on the real polices. Replace
	# those with our example policy.
	lib.assert_equal({in_the_future, no_effective_date, in_the_past, y2k}, data.release.main.deny) with data.policy.release as {data.examples.release.time_based}
		with data.config.policy as policy_config
}

test_y2k_not_failing_before_2000 {
	# Set the date/time to the future where the example policy becomes effective.
	policy_config := {"exclude": [], "when_ns": time.parse_rfc3339_ns("1999-01-01T00:00:00Z")}

	# The time based filtering happens automatically on the real polices. Replace
	# those with our example policy.
	lib.assert_equal({no_effective_date, in_the_past}, data.release.main.deny) with data.policy.release as {data.examples.release.time_based}
		with data.config.policy as policy_config
}
