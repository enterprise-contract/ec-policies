# The package name is different than the package under test, "_test" suffix.
# This is to avoid the recursive rule error since the test must reference the
# package under test by name in these particular tests.
package examples.time_based_test

in_the_future := {"msg": "Roads?", "effective_on": "2099-05-02T00:00:00Z"}

no_effective_date := {"msg": "no effective date"}

in_the_past := {"msg": "from the past", "effective_on": "1970-01-01T01:00:00Z"}

test_not_effective_by_default {
	# The time based filtering happens automatically on the real polices. Replace
	# those with our example policy.
	# time_based policy has effective_on far into the future, if you're reading
	# this then bump it for another 100 years
	{no_effective_date, in_the_past} == data.main.deny with data.policies as {data.examples.time_based}
		with data.config.policy.non_blocking_checks as []
}

test_effective_with_time_travel {
	# Set the date/time to the future where the example policy becomes effective.
	policy_config := {"non_blocking_checks": [], "when_ns": time.parse_rfc3339_ns("2099-05-02T00:00:00Z")}

	# The time based filtering happens automatically on the real polices. Replace
	# those with our example policy.
	{in_the_future, no_effective_date, in_the_past} == data.main.deny with data.policies as {data.examples.time_based}
		with data.config.policy as policy_config
}
