#
# METADATA
# title: Git branch checks
# description: >-
#   Check that the build was done from an expected git branch. The
#   specific branches permitted are specified as a list of regexes
#   in the `allowed_branch_patterns` rule data.
#
package git_branch

import data.lib
import rego.v1

# METADATA
# title: Only allow builds from a trusted branch
# description: Build must originate from a configured branch pattern (e.g., 'refs/heads/main')
# custom:
#   short_name: git_branch
#   failure_msg: Build is from a branch %s which is not a trusted branch
#   collections:
#   - redhat_rpms
#   effective_on: 2025-07-01
deny contains result if {
	some task in lib.tasks_from_pipelinerun

	# Note that we're assuming that the annotation exists.
	# This will not produce a violation if the annotation is missing
	branch := task.invocation.environment.annotations["pipelinesascode.tekton.dev/source-branch"]
	not matches_any(branch)
	result := lib.result_helper(rego.metadata.chain(), [branch])
}

matches_any(branch) if {
	some pattern in lib.rule_data("allowed_branch_patterns")
	regex.match(pattern, branch)
}
