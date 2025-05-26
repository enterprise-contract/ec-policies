package git_branch

import rego.v1
import data.lib

# METADATA
# title: Only allow builds from a trusted branch
# description: Build must originate from a configured branch pattern (e.g., 'refs/heads/main')
# custom:
#   short_name: git_branch
#   failure_msg: Build is not from a trusted branch
#   collections:
#   - redhat_rpms
#   effective_on: 2025-07-01

deny if result {
  some task in lib.tasks_from_pipelinerun
  branch := task.invocation.environment.annotations["pipelinesascode.tekton.dev/source-branch"]

  not matches_any(branch)

  result := lib.result_helper(rego.metadata.chain(), ["invalid branch", branch])
}

matches_any(branch) if {
  some pattern in lib.rule_data("allowed_branch_patterns")
  regex.match(pattern, branch)
}
