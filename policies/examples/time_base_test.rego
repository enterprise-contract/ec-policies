# The package name is different than the package under test, "_test" suffix.
# This is to avoid the recursive rule error since the test must reference the
# package under test by name in these particular tests.
package examples.time_based_test

test_not_effective_by_default {
	# The time based filtering happens automatically on the real polices. Replace
	# those with our example policy.
	set() == data.main.deny with data.policies as {data.examples.time_based}
		with data.config.policy.non_blocking_checks as []
}

test_effective_with_time_travel {
	# Set the date/time to the future where the example policy becomes effective.
	policy_config := {"non_blocking_checks": [], "when_ns": data.examples.time_based.effective_on}

	# The time based filtering happens automatically on the real polices. Replace
	# those with our example policy.
	{{"msg": "Roads?"}} == data.main.deny with data.policies as {data.examples.time_based}
		with data.config.policy as policy_config
}
