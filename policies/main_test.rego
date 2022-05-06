package main

all_tests := {p | data.policies[policy]; p := policy}

test_main {
	deny with data.attestation_type.deny as {{"msg": "foo"}}
	deny with data.step_image_registries.deny as {{"msg": "foo"}}
	deny with data.not_useful.deny as {{"msg": "foo"}} with data.config.policy.non_blocking_checks as []
}

test_failing_without_skipping {
	# Let's make sure that the contract remains the same by checking what `deny` is set to
	# this makes this test a bit more fragile, but the assertion is better as we know that
	# the output hasn't changed it's shape
	{{"msg": "It just feels like a bad day to do a release"}, {"msg": "No test data provided"}} == deny with data.config.policy as {"non_blocking_checks": {}}
}

test_succeeding_when_skipping_all {
	count(deny) == 0 with data.config.policy as {"non_blocking_checks": all_tests}
}

test_test_can_be_skipped {
	{{"msg": "No test data provided"}} == deny with data.config.policy as {"non_blocking_checks": all_tests - {"test"}}
}

test_test_succeeds {
	count(deny) == 0 with data.test as [{"result": "SUCCESS"}] with data.config.policy as {"non_blocking_checks": all_tests - {"test"}}
}

test_test_fails {
	{{"msg": "All tests did not end with SUCCESS"}} == deny with data.test as [{"result": "FAILURE"}] with data.config.policy as {"non_blocking_checks": all_tests - {"test"}}
}

test_policy_ignored_when_not_yet_effective {
	future_denial := {"msg": "fails in the distant future", "effective_on": "2099-05-02T00:00:00Z"}
	set() == deny with denials as {future_denial}
		with data.config.policy as {"non_blocking_checks": all_tests - {"test", "not_useful"}}

	{future_denial} == future_deny with denials as {future_denial}
		with data.config.policy as {"non_blocking_checks": all_tests - {"test", "not_useful"}}
}

format_rfc3339_ns(ns) = fmt {
	date := time.date(ns)
	clock := time.clock(ns)
	fmt := sprintf("%0.2d-%0.2d-%0.2dT%0.2d:%0.2d:%0.2dZ", array.concat(date, clock))
}

test_policy_not_ignored_when_effective_with_time_travel {
	# On the policy, change effective_on date to tomorrow so it should become ignored, but
	# also change the policy config to a future date (time travel) so it is no longer ignored
	future := time.add_date(time.now_ns(), 0, 0, 1)
	policy_config := {"when_ns": future}
	expected_error := {{"msg": "should fail", "effective_on": format_rfc3339_ns(future)}}

	{expected_error} == deny with denials as {expected_error}
		with data.config.policy as policy_config

	set() == future_deny with denials as {expected_error}
		with data.config.policy as policy_config
}

test_policy_not_ignored_when_effective_missing {
	policy_config := {}
	expected_error := {{"msg": "should fail"}}

	# Verify that the policy is enforced by default
	{expected_error} == deny with denials as {expected_error}
		with data.config.policy as policy_config
}

test_future_denial {
	future := time.add_date(time.now_ns(), 0, 0, 1)
	expected_error := {"msg": "should not fail", "effective_on": format_rfc3339_ns(future)}

	set() == deny with denials as {expected_error}
		with data.config as {}

	{expected_error} == future_deny with denials as {expected_error}
		with data.config as {}
}

test_in_future {
	denial := {"msg": "should fail", "effective_on": "2099-05-02T00:00:00Z"}
	true == in_future(denial) with data.config as {}
}
