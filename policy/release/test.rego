# METADATA
# custom:
#   effective_on: 2022-01-01T00:00:00Z
package policy.release.test

import data.lib

# METADATA
# title: No test data found
# description: |-
#   None of the tasks in the pipeline included a HACBS_TEST_OUTPUT
#   task result, which is where Enterprise Contract expects to find
#   test result data.
# custom:
#   short_name: test_data_missing
#   failure_msg: No test data found
#
deny[result] {
	count(lib.results_from_tests) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Test data is missing the results key
# description: |-
#   Each test result is expected to have a 'results' key. In at least
#   one of the HACBS_TEST_OUTPUT task results this key was not present.
# custom:
#   short_name: test_results_missing
#   failure_msg: Found tests without results
#
deny[result] {
	with_results := [result | result := lib.results_from_tests[_].result]
	count(with_results) != count(lib.results_from_tests)
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Some tests did not pass
# description: |-
#   Enterprise Contract requires that all the tests in the
#   test results have a result of 'SUCCESS'. This will fail if any
#   of the tests failed and the failure message will list the names
#   of the failing tests.
# custom:
#   short_name: test_result_failures
#   failure_msg: "The following tests did not complete successfully: %s"
#
deny[result] {
	# Collect all failed tests and convert their name to "test:<name>" format
	all_failed := {failure |
		result := lib.results_from_tests[_]
		result.result != "SUCCESS"
		failure := sprintf("test:%s", [result.__task_name])
	}

	# For the complement operation below (subtraction) we need
	# non_blocking_checks as set and this creates that from the array
	non_blocking_set = {x | x := data.config.policy.non_blocking_checks[_]}

	# Failed tests are those that don't have their result equal to "SUCCESS"
	# and are not on the list of non_blocking_checks
	failed_blocking := all_failed - non_blocking_set

	# Fail if there are any
	count(failed_blocking) > 0

	short_failed_blocking := [f | f := split(failed_blocking[_], ":")[1]]
	result := lib.result_helper(
		rego.metadata.chain(),
		[concat(", ", short_failed_blocking)],
	)
}
