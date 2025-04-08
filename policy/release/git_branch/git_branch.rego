package git_branch

import rego.v1
import data.lib

# METADATA
# title: Only allow builds from a trusted branch
# description: Build must originate from a configured branch pattern (e.g., 'refs/heads/main')
# custom:
#   short_name: git_protected_branch_required
#   failure_msg: Build is not from a trusted branch
#   collections:
#   - minimal
#   - redhat

default deny = []

deny contains result if {
  some task in input.attestations[_].statement.predicate.buildConfig.tasks
  branch := task.invocation.environment.annotations["pipelinesascode.tekton.dev/source-branch"]

  not matches_any(branch)

  result := lib.result_helper(rego.metadata.chain(), ["invalid branch", branch])
}

matches_any(branch) {
  some pattern in data.rule_data.git_branch.allowed_branch_patterns[_]
  regex.match(pattern, branch)
}
