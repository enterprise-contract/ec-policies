package hacbs.contract.test

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
	deny == {{"msg": "Found tests without results"}} with data.test as [{}, {"result": "SUCCESS"}]
}

test_success_data {
	count(deny) == 0 with data.test as [{"result": "SUCCESS"}]
}

test_failure_data {
	deny == {{"msg": "All tests did not end with SUCCESS"}} with data.test as [{"result": "FAILURE"}]
}

test_error_data {
	deny == {{"msg": "All tests did not end with SUCCESS"}} with data.test as [{"result": "ERROR"}]
}

test_mix_data {
	deny == {{"msg": "All tests did not end with SUCCESS"}} with data.test as [{"result": "SUCCESS"}, {"result": "FAILURE"}, {"result": "ERROR"}]
}
