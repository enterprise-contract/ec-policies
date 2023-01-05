package policy.release.test

import data.lib
import data.lib.bundles

# Because HACBS_TEST_OUTPUT isn't in the task results, the lib.results_from_tests will be empty
mock_empty_data := [lib.att_mock_helper_ref("NOT_HACBS_TEST_OUTPUT", {}, "task1", bundles.acceptable_bundle_ref)]

test_needs_non_empty_data {
	lib.assert_equal(deny, {{
		"code": "test.test_data_missing",
		"msg": "No test data found",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as mock_empty_data
}

# There is a test result, but the data inside it doesn't include the "result" key
mock_without_results_data := [lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"rezult": "SUCCESS"}, "task1", bundles.acceptable_bundle_ref)]

test_needs_tests_with_results {
	lib.assert_equal(deny, {{
		"code": "test.test_results_missing",
		"msg": "Found tests without results",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as mock_without_results_data
}

mock_without_results_data_mixed := [
	lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SUCCESS"}, "task1", bundles.acceptable_bundle_ref),
	lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"rezult": "SUCCESS"}, "task2", bundles.acceptable_bundle_ref),
]

test_needs_tests_with_results_mixed {
	lib.assert_equal(deny, {{
		"code": "test.test_results_missing",
		"msg": "Found tests without results",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as mock_without_results_data_mixed
}

mock_a_passing_test := [lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SUCCESS"}, "task1", bundles.acceptable_bundle_ref)]

test_success_data {
	lib.assert_empty(deny) with input.attestations as mock_a_passing_test
		with data["task-bundles"] as bundles.bundle_data
		with data.config.policy as {"exclude": []}
}

mock_a_failing_test := [lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "FAILURE"}, "failed_1", bundles.acceptable_bundle_ref)]

test_failure_data {
	lib.assert_equal(deny, {{
		"code": "test.test_result_failures",
		"msg": "The following tests did not complete successfully: failed_1",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as mock_a_failing_test
		with data.config.policy as {"exclude": []}
}

mock_an_errored_test := [lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "ERROR"}, "errored_1", bundles.acceptable_bundle_ref)]

test_error_data {
	lib.assert_equal(deny, {{
		"code": "test.test_result_failures",
		"msg": "The following tests did not complete successfully: errored_1",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as mock_an_errored_test
		with data.config.policy as {"exclude": []}
}

mock_mixed_data := array.concat(mock_a_failing_test, mock_an_errored_test)

test_mix_data {
	lib.assert_equal(deny, {{
		"code": "test.test_result_failures",
		"msg": "The following tests did not complete successfully: errored_1, failed_1",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as mock_mixed_data
		with data.config.policy as {"exclude": []}
}

test_can_skip_by_name {
	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as mock_mixed_data
		with data.config.policy as {"non_blocking_checks": ["test:errored_1", "test:failed_1"]}

	# exclude works the same as non_blocking_checks
	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as mock_mixed_data
		with data.config.policy as {"exclude": ["test:errored_1", "test:failed_1"]}

	# It's an unlikely edge case, but you can use them both if you want
	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as mock_mixed_data
		with data.config.policy as {"exclude": ["test:errored_1"], "non_blocking_checks": ["test:failed_1"]}

	lib.assert_equal(deny, {{
		"code": "test.test_result_failures",
		"msg": "The following tests did not complete successfully: errored_1",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as mock_mixed_data
		with data.config.policy as {"non_blocking_checks": ["test:failed_1"]}

	# exclude works the same as non_blocking_checks
	lib.assert_equal(deny, {{
		"code": "test.test_result_failures",
		"msg": "The following tests did not complete successfully: errored_1",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as mock_mixed_data
		with data.config.policy as {"exclude": ["test:failed_1"]}
}

test_skipped_is_not_deny {
	skipped_test := [lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SKIPPED"}, "skipped_1", bundles.acceptable_bundle_ref)]
	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as skipped_test
}

test_skipped_is_warning {
	skipped_test := [lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SKIPPED"}, "skipped_1", bundles.acceptable_bundle_ref)]
	lib.assert_equal(warn, {{
		"code": "test.test_result_skipped",
		"msg": "The following tests were skipped: skipped_1",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as skipped_test
}

test_mixed_statuses {
	test_results := [
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "ERROR"}, "error_1", bundles.acceptable_bundle_ref),
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SUCCESS"}, "success_1", bundles.acceptable_bundle_ref),
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "FAILURE"}, "failure_1", bundles.acceptable_bundle_ref),
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SKIPPED"}, "skipped_1", bundles.acceptable_bundle_ref),
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "FAILURE"}, "failure_2", bundles.acceptable_bundle_ref),
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SKIPPED"}, "skipped_2", bundles.acceptable_bundle_ref),
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "ERROR"}, "error_2", bundles.acceptable_bundle_ref),
	]

	lib.assert_equal(deny, {{
		"code": "test.test_result_failures",
		"msg": "The following tests did not complete successfully: error_1, error_2, failure_1, failure_2",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as test_results

	lib.assert_equal(warn, {{
		"code": "test.test_result_skipped",
		"msg": "The following tests were skipped: skipped_1, skipped_2",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as test_results
}

test_unsupported_test_result {
	test_results := [
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "EROR"}, "error_1", bundles.acceptable_bundle_ref),
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SUCESS"}, "success_1", bundles.acceptable_bundle_ref),
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "FAIL"}, "failure_1", bundles.acceptable_bundle_ref),
		lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SKIPED"}, "skipped_1", bundles.acceptable_bundle_ref),
	]

	lib.assert_equal(deny, {
		{"code": "test.test_result_unsupported", "msg": "Test 'error_1' has unsupported result 'EROR'", "effective_on": "2022-01-01T00:00:00Z"},
		{"code": "test.test_result_unsupported", "msg": "Test 'failure_1' has unsupported result 'FAIL'", "effective_on": "2022-01-01T00:00:00Z"},
		{"code": "test.test_result_unsupported", "msg": "Test 'skipped_1' has unsupported result 'SKIPED'", "effective_on": "2022-01-01T00:00:00Z"},
		{"code": "test.test_result_unsupported", "msg": "Test 'success_1' has unsupported result 'SUCESS'", "effective_on": "2022-01-01T00:00:00Z"},
	}) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as test_results
}

test_unacceptable_bundle_results {
	lib.assert_equal(deny, {{
		"code": "test.test_data_missing",
		"msg": "No test data found",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as [lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "SUCCESS"}, "task1", "registry.img/unacceptable@sha256:digest")]
		with data["task-bundles"] as bundles.bundle_data
		with data.config.policy as {"exclude": []}
}

test_missing_wrong_attestation_type {
	pr := lib.att_mock_helper_ref("some-result", {"result": "value"}, "task1", bundles.acceptable_bundle_ref)
	tr := object.union(pr, {"predicate": {"buildType": lib.taskrun_att_build_types[0]}})
	lib.assert_empty(deny) with input.attestations as [tr]
		with data["task-bundles"] as bundles.bundle_data
		with data.config.policy as {"exclude": []}
}

test_wrong_attestation_type {
	pr := lib.att_mock_helper_ref(lib.hacbs_test_task_result_name, {"result": "ERROR"}, "errored_1", bundles.acceptable_bundle_ref)
	tr := object.union(pr, {"predicate": {"buildType": lib.taskrun_att_build_types[0]}})
	lib.assert_empty(deny) with input.attestations as [tr]
		with data["task-bundles"] as bundles.bundle_data
		with data.config.policy as {"exclude": []}
}
