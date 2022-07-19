package policy.release.test

import data.lib
import future.keywords.in

# METADATA
# title: No test data found
# description: |-
#   None of the tasks in the pipeline included a HACBS_TEST_OUTPUT
#   task result, which is where Enterprise Contract expects to find
#   test result data.
# custom:
#   short_name: test_data_missing
#   failure_msg: No test data found
deny[result] {
	count(lib.pipelinerun_attestations) > 0
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
# title: Unsupported result in test data
# description: |-
#   This policy expects a set of known/supported results in the test data
#   It is a failure if we encounter a result that is not supported.
# custom:
#   short_name: test_result_unsupported
#   failure_msg: Test '%s' has unsupported result '%s'
#   rule_data:
#     supported_results:
#     - SUCCESS
#     - FAILURE
#     - ERROR
#     - SKIPPED
#
deny[result] {
	all_unsupported := [u |
		test := lib.results_from_tests[_]
		not test.result in rego.metadata.rule().custom.rule_data.supported_results
		u := {"task": test.__task_name, "result": test.result}
	]

	count(all_unsupported) > 0
	unsupported = all_unsupported[_]
	result := lib.result_helper(rego.metadata.chain(), [unsupported.task, unsupported.result])
}

# METADATA
# title: Test result is FAILURE or ERROR
# description: |-
#   Enterprise Contract requires that all the tests in the test results
#   have a successful result. A successful result is one that isn't a
#   "FAILURE" or "ERROR". This will fail if any of the tests failed and
#   the failure message will list the names of the failing tests.
# custom:
#   short_name: test_result_failures
#   failure_msg: "The following tests did not complete successfully: %s"
#
deny[result] {
	all_failed = resulted_in({"FAILURE", "ERROR"})

	# For the complement operation below (subtraction) we need
	# non_blocking_checks as set and this creates that from the array
	non_blocking_set = {x | x := data.config.policy.non_blocking_checks[_]}

	# Failed tests are those contained within all_failed that
	# are not on the list of non_blocking_checks
	failed_blocking := all_failed - non_blocking_set

	# Fail if there are any
	count(failed_blocking) > 0

	short_failed_blocking := [f | f := split(failed_blocking[_], ":")[1]]
	result := lib.result_helper(
		rego.metadata.chain(),
		[concat(", ", short_failed_blocking)],
	)
}

# METADATA
# title: Some tests were skipped
# description: |-
#   Collects all tests that have their result set to "SKIPPED".
# custom:
#   short_name: test_result_skipped
#   failure_msg: "The following tests were skipped: %s"
#
warn[result] {
	all_skipped = resulted_in({"SKIPPED"})

	# Don't report if there aren't any
	count(all_skipped) > 0

	short_skipped := [f | f := split(all_skipped[_], ":")[1]]
	result := lib.result_helper(
		rego.metadata.chain(),
		[concat(", ", short_skipped)],
	)
}

resulted_in(results) = filtered_by_result {
	# Collect all tests that have resulted with one of the given
	# results and convert their name to "test:<name>" format
	filtered_by_result := {r |
		test := lib.results_from_tests[_]
		test.result in results
		r := sprintf("test:%s", [test.__task_name])
	}
}
