package policies.test

import data.lib

test_needs_to_have_data {
	lib.assert_equal(deny, {{"code": "test_data_missing", "msg": "No test data provided"}})
}

test_needs_non_empty_data {
	lib.assert_equal(deny, {{"code": "test_data_empty", "msg": "Empty test data provided"}}) with data.test as []
}

test_needs_tests_with_results {
	lib.assert_equal(deny, {{"code": "test_results_missing", "msg": "Found tests without results"}}) with data.test as [{}]
}

test_needs_tests_with_results_mixed {
	lib.assert_equal(deny, {{"code": "test_results_missing", "msg": "Found tests without results"}}) with data.test as [{}, {"test1": {"result": "SUCCESS"}}]
}

test_success_data {
	lib.assert_empty(deny) with data.test.test1 as {"result": "SUCCESS"}
		with data.config.policy as {"non_blocking_checks": []}
}

test_failure_data {
	lib.assert_equal(deny, {{"code": "test_result_failures", "msg": "The following tests failed: test1"}}) with data.test.test1 as {"result": "FAILURE"}
		with data.config.policy as {"non_blocking_checks": []}
}

test_error_data {
	lib.assert_equal(deny, {{"code": "test_result_failures", "msg": "The following tests failed: test1"}}) with data.test.test1 as {"result": "ERROR"}
		with data.config.policy as {"non_blocking_checks": []}
}

test_mix_data {
	lib.assert_equal(deny, {{"code": "test_result_failures", "msg": "The following tests failed: errored, failed"}}) with data.test.successfull as {"result": "SUCCESS"}
		with data.test.failed as {"result": "FAILURE"}
		with data.test.errored as {"result": "ERROR"}
		with data.config.policy as {"non_blocking_checks": []}
}

test_can_skip_by_name {
	lib.assert_empty(deny) with data.test.test1 as {"result": "FAILURE"}
		with data.config.policy as {"non_blocking_checks": ["test:test1"]}
}
