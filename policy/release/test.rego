#
# METADATA
# description: |-
#   Enterprise Contract requires that each build was subjected
#   to a set of tests and that those tests all passed. This package
#   includes a set of rules to verify that.
#
#   The rest result data must be reported by a Tekton Task that has been loaded
#   from an acceptable Tekton Bundle.
#   See xref:release_policy.adoc#attestation_task_bundle_package[Task bundle checks].
#
#   TODO: Document how you can skip the requirement for individual
#   tests if needed using the `non_blocking_rule` configuration.
#
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
#
deny[result] {
	count(lib.pipelinerun_attestations) > 0 # make sure we're looking at a PipelineRun attestation
	results := lib.results_from_tests
	count(results) == 0 # there are none at all

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
	with_results := [result | result := lib.results_from_tests[_][lib.key_value].result]
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
		result := lib.results_from_tests[_]
		test := result[lib.key_value]
		not test.result in lib.rule_data(rego.metadata.rule(), "supported_results")
		u := {"task": result[lib.key_task_name], "result": test.result}
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

	# Failed tests are those contained within all_failed that are not
	# listed in the exclude list
	failed_blocking := all_failed - lib.exclude

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
		result := lib.results_from_tests[_]
		test := result[lib.key_value]
		test.result in results
		r := sprintf("test:%s", [result[lib.key_task_name]])
	}
}
