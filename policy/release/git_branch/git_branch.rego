package git_branch

import rego.v1

import data.lib

# METADATA
# title: Only allow builds from a trusted branch
# description: Build must originate from a overwrite-protected default branches (for example 'main' or 'master')
# custom:
#   short_name: git_protected_branch_required
#   failure_msg: Build is not from a default branch ('main' or 'master')
#   collections:
#   - minimal
#   - redhat

deny contains result if {
  some task in input.attestations[_].statement.predicate.buildConfig.tasks
  branch := task.invocation.environment.annotations["pipelinesascode.tekton.dev/source-branch"]
  not branch in {"refs/heads/main", "refs/heads/master"}
  result := lib.result_helper(rego.metadata.chain(), ["invalid branch", branch])
}
