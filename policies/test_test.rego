package policies.test

import data.lib

# Because HACBS_TEST_OUTPUT isn't in the task results, the lib.results_from_tests will be empty
mock_empty_data := [json.patch(lib.att_mock_helper({}, "task1"), [{
	"op": "replace",
	"path": "/predicate/buildConfig/tasks/0/results/0/name",
	"value": "NOT_HACBS_TEST_OUTPUT",
}])]

test_needs_non_empty_data {
	lib.assert_equal(deny, {{"code": "test_data_missing", "msg": "No test data found"}}) with input.attestations as mock_empty_data
}

# There is a test result, but the data inside it doesn't include the "result" key
mock_without_results_data := [lib.att_mock_helper({"rezult": "SUCCESS"}, "task1")]

test_needs_tests_with_results {
	lib.assert_equal(deny, {{"code": "test_results_missing", "msg": "Found tests without results"}}) with input.attestations as mock_without_results_data
}

mock_without_results_data_mixed := [lib.att_mock_helper({"result": "SUCCESS"}, "task1"), lib.att_mock_helper({"rezult": "SUCCESS"}, "task2")]

test_needs_tests_with_results_mixed {
	lib.assert_equal(deny, {{"code": "test_results_missing", "msg": "Found tests without results"}}) with input.attestations as mock_without_results_data_mixed
}

mock_a_passing_test := [lib.att_mock_helper({"result": "SUCCESS"}, "task1")]

test_success_data {
	lib.assert_empty(deny) with input.attestations as mock_a_passing_test
		with data.config.policy as {"non_blocking_checks": []}
}

mock_a_failing_test := [lib.att_mock_helper({"result": "FAILURE"}, "failed_1")]

test_failure_data {
	lib.assert_equal(deny, {{"code": "test_result_failures", "msg": "The following tests did not complete successfully: failed_1"}}) with input.attestations as mock_a_failing_test
		with data.config.policy as {"non_blocking_checks": []}
}

mock_an_errored_test := [lib.att_mock_helper({"result": "ERROR"}, "errored_1")]

test_error_data {
	lib.assert_equal(deny, {{"code": "test_result_failures", "msg": "The following tests did not complete successfully: errored_1"}}) with input.attestations as mock_an_errored_test
		with data.config.policy as {"non_blocking_checks": []}
}

mock_mixed_data := array.concat(mock_a_failing_test, mock_an_errored_test)

test_mix_data {
	lib.assert_equal(deny, {{"code": "test_result_failures", "msg": "The following tests did not complete successfully: errored_1, failed_1"}}) with input.attestations as mock_mixed_data
		with data.config.policy as {"non_blocking_checks": []}
}

test_can_skip_by_name {
	lib.assert_empty(deny) with input.attestations as mock_mixed_data
		with data.config.policy as {"non_blocking_checks": ["test:errored_1", "test:failed_1"]}

	lib.assert_equal(deny, {{"code": "test_result_failures", "msg": "The following tests did not complete successfully: errored_1"}}) with input.attestations as mock_mixed_data
		with data.config.policy as {"non_blocking_checks": ["test:failed_1"]}
}
