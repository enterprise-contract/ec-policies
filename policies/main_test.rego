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
	# Change effective_on date to tomorrow to verify it becomes ignored
	future := time.add_date(time.now_ns(), 0, 0, 1)
	set() == deny with data.config.policy as {"non_blocking_checks": all_tests - {"not_useful"}}
		with data.policies.not_useful.effective_on as future
}

test_policy_not_ignored_when_effective_with_time_travel {
	# On the policy, change effective_on date to tomorrow so it should become ignored, but
	# also change the policy config to a future date (time travel) so it is no longer ignored
	future := time.add_date(time.now_ns(), 0, 0, 1)
	policy_config := {"non_blocking_checks": all_tests - {"not_useful"}, "when_ns": future}
	expected_error := {{"msg": "It just feels like a bad day to do a release"}}
	expected_error == deny with data.config.policy as policy_config
		with data.policies.not_useful.effective_on as future
}

test_policy_not_ignored_when_effective_missing {
	# Verify the assumption that effective_on is not set on the policy
	object.get(data.policies.not_useful, ["effective_on"], "<undefined>") == "<undefined>"

	policy_config := {"non_blocking_checks": all_tests - {"not_useful"}}
	expected_error := {{"msg": "It just feels like a bad day to do a release"}}

	# Verify that the policy is enforced by default
	expected_error == deny with data.config.policy as policy_config
}
