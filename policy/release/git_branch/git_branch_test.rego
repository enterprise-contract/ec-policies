package git_branch_test

import data.git_branch
import data.lib
import rego.v1

single_test_case(branch, expected_results) if {
	# regal ignore:line-length
	mock_input := {"attestations": [{"statement": {"predicate": {"buildConfig": {"tasks": [{"invocation": {"environment": {"annotations": {"pipelinesascode.tekton.dev/source-branch": branch}}}}]}}}}]}

	mock_rule_data := ["^refs/heads/main$", "^refs/heads/release-[23]$"]

	mock_tasks := mock_input.attestations[0].statement.predicate.buildConfig.tasks

	# regal ignore:with-outside-test-context
	lib.assert_equal_results(expected_results, git_branch.deny) with input as mock_input
		with lib.rule_data as mock_rule_data
		with lib.tasks_from_pipelinerun as mock_tasks
}

test_allow_with_main_branch if {
	single_test_case("refs/heads/main", [])
}

test_allow_with_release_branch if {
	single_test_case("refs/heads/release-2", [])
}

test_deny_with_disallowed_branch if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build is from a branch refs/heads/feature-branch which is not a trusted branch",
	}}
	single_test_case("refs/heads/feature-branch", expected)
}

test_deny_with_unmatched_branch if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build is from a branch refs/heads/release-1 which is not a trusted branch",
	}}
	single_test_case("refs/heads/release-1", expected)
}
