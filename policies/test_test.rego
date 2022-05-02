package policies.test

test_needs_to_have_data {
	deny == {{"msg": "No test data provided"}}
}

test_needs_non_empty_data {
	deny == {{"msg": "Empty test data provided"}} with data.test as []
}

test_needs_tests_with_results {
	deny == {{"msg": "Found tests without results"}} with data.test as [{}]
}

test_needs_tests_with_results_mixed {
	deny == {{"msg": "Found tests without results"}} with data.test as [{}, {"test1": {"result": "SUCCESS"}}]
}

test_success_data {
	count(deny) == 0 with data.test.test1 as {"result": "SUCCESS"}
		 with data.config.policy as {"non_blocking_checks": []}
}

test_failure_data {
	deny == {{"msg": "All tests did not end with SUCCESS"}} with data.test.test1 as {"result": "FAILURE"}
		 with data.config.policy as {"non_blocking_checks": []}
}

test_error_data {
	deny == {{"msg": "All tests did not end with SUCCESS"}} with data.test.test1 as {"result": "ERROR"}
		 with data.config.policy as {"non_blocking_checks": []}
}

test_mix_data {
	deny == {{"msg": "All tests did not end with SUCCESS"}} with data.test.successfull as {"result": "SUCCESS"}
		 with data.test.failed as {"result": "FAILURE"}
		 with data.test.errored as {"result": "ERROR"}
		 with data.config.policy as {"non_blocking_checks": []}
}

test_can_skip_by_name {
	count(deny) == 0 with data.test.test1 as {"result": "FAILURE"}
		 with data.config.policy as {"non_blocking_checks": ["test:test1"]}
}
