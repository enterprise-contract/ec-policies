package release.main

import data.lib
import data.lib.bundles

# Todo: Some of this might be better placed in policy/lib/main_denies_test

all_tests := {p | data.policy.release[policy]; p := policy}

nonblocking_except(except_tests) = d {
	d := {"exclude": all_tests - except_tests}
}

nonblocking_only(only_tests) = d {
	d := {"exclude": only_tests}
}

test_main {
	deny with data.attestation_type.deny as {{"msg": "foo"}}
	deny with data.step_image_registries.deny as {{"msg": "foo"}}
	deny with data.not_useful.deny as {{"msg": "foo"}} with data.config.policy as nonblocking_only(set())
}

test_failing_without_skipping {
	# Let's make sure that the contract remains the same by checking what `deny` is set to
	# this makes this test a bit more fragile, but the assertion is better as we know that
	# the output hasn't changed it's shape
	lib.assert_equal(deny, {
		{
			"code": "bad_day",
			"msg": "It just feels like a bad day to do a release",
			"effective_on": "2022-01-01T00:00:00Z",
		},
		{
			"code": "test_data_missing",
			"msg": "No test data found",
			"effective_on": "2022-01-01T00:00:00Z",
		},
	}) with data.config.policy as nonblocking_only(set())
}

test_skipping_individual_rules {
	lib.assert_equal(deny, {{
		"code": "test_data_missing",
		"msg": "No test data found",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data.config.policy.exclude as ["not_useful.bad_day"]

	lib.assert_equal(deny, {{
		"code": "bad_day",
		"msg": "It just feels like a bad day to do a release",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data.config.policy.exclude as ["test.test_data_missing"]

	lib.assert_empty(deny) with data.config.policy.exclude as ["test.test_data_missing", "not_useful.bad_day"]
}

test_succeeding_when_skipping_all {
	lib.assert_empty(deny) with data.config.policy as nonblocking_except(set())
}

test_test_can_be_skipped {
	lib.assert_equal(deny, {{
		"code": "test_data_missing",
		"msg": "No test data found",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data.config.policy as nonblocking_except({"test"})
}

test_test_succeeds {
	lib.assert_empty(deny) with input.attestations as [lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SUCCESS"}, "mytask", bundles.acceptable_bundle_ref)]
		with data["task-bundles"] as bundles.bundle_data
		with data.config.policy as nonblocking_except({"test"})
}

test_test_fails {
	lib.assert_equal(deny, {{
		"code": "test_result_failures",
		"msg": "The following tests did not complete successfully: test1",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as [lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "FAILURE"}, "test1", bundles.acceptable_bundle_ref)]
		with data["task-bundles"] as bundles.bundle_data
		with data.config.policy as nonblocking_except({"test"})
}

test_policy_ignored_when_not_yet_effective {
	future_denial := {"msg": "fails in the distant future", "effective_on": "2099-05-02T00:00:00Z"}
	lib.assert_empty(deny) with all_denies as {future_denial}
		with data.config.policy as nonblocking_except({"test", "not_useful"})

	lib.assert_equal({future_denial}, warn) with all_denies as {future_denial}
		with data.config.policy as nonblocking_except({"test", "not_useful"})
}

format_rfc3339_ns(ns) = fmt {
	date := time.date(ns)
	clock := time.clock(ns)
	fmt := sprintf("%0.2d-%0.2d-%0.2dT%0.2d:%0.2d:%0.2dZ", array.concat(date, clock))
}

test_policy_not_ignored_when_effective_with_time_travel {
	# On the policy, change effective_on date to tomorrow so it should become ignored, but
	# also change the policy config to a future date (time travel) so it is no longer ignored
	future := lib.time.future_timestamp
	policy_config := {"when_ns": future}
	expected_error := {{"msg": "should fail", "effective_on": format_rfc3339_ns(future)}}

	lib.assert_equal({expected_error}, deny) with all_denies as {expected_error}
		with data.config.policy as policy_config

	lib.assert_empty(warn) with all_denies as {expected_error}
		with data.config.policy as policy_config
}

test_policy_not_ignored_when_effective_missing {
	policy_config := {}
	expected_error := {{"msg": "should fail"}}

	# Verify that the policy is enforced by default
	lib.assert_equal({expected_error}, deny) with all_denies as {expected_error}
		with data.config.policy as policy_config
}

test_future_denial {
	future := lib.time.future_timestamp
	expected_error := {"msg": "should not fail", "effective_on": format_rfc3339_ns(future)}

	lib.assert_empty(deny) with all_denies as {expected_error}

	lib.assert_equal({expected_error}, warn) with all_denies as {expected_error}
}

test_warnings {
	future := lib.time.future_timestamp
	future_warn := {"msg": "future warn", "effective_on": format_rfc3339_ns(future)}
	current_warn := {"msg": "current warn", "effective_on": format_rfc3339_ns(time.now_ns())}
	future_deny := {"msg": "future deny", "effective_on": format_rfc3339_ns(future)}

	# Future warnings are ignored entirely
	lib.assert_empty(warn) with all_warns as {future_warn}

	# Current warnings are not ignored
	lib.assert_equal({current_warn}, warn) with all_warns as {current_warn}

	# A current warning and a future deny becomes two warnings
	lib.assert_equal({current_warn, future_deny}, warn) with all_warns as {current_warn} with all_denies as {future_deny}
}
