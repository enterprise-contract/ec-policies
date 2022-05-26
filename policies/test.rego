package policies.test

import data.lib

# METADATA
# title: No test data was found
# description: |-
#   No test data was found in the data directory.
# custom:
#   short_name: test_data_missing
#   failure_msg: No test data provided
#
deny[result] {
	not data.test
	result := lib.result_helper(rego.metadata.rule(), [])
}

# METADATA
# title: Test data is empty
# description: |-
#   The top level key was found for test data but it contained no
#   test results.
# custom:
#   short_name: test_data_empty
#   failure_msg: Empty test data provided
#
deny[result] {
	count(data.test) == 0
	result := lib.result_helper(rego.metadata.rule(), [])
}

# METADATA
# title: Test data is missing results
# description: |-
#   Each test result is expected to have 'results' key. In
#   at least one of the test results this key was missing.
# custom:
#   short_name: test_results_missing
#   failure_msg: Found tests without results
#
deny[result] {
	with_results := [result | result := data.test[_].result]
	count(with_results) != count(data.test)
	result := lib.result_helper(rego.metadata.rule(), [])
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
#   failure_msg: "The following tests failed: %s"
#
deny[result] {
	# Collect all failed tests and convert their name to "test:<name>" format
	# Reminder: the tests reside in $DATA_DIR/test.json
	all_failed := {failure | data.test[name].result != "SUCCESS"; failure := sprintf("test:%s", [name])}

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
		rego.metadata.rule(),
		[concat(", ", short_failed_blocking)],
	)
}
