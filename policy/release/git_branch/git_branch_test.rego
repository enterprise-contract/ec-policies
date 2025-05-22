package git_branch_test

import rego.v1
import data.lib

git_branch_test_case(branch, expected_results) = passed {
  mock_input := {
    "attestations": [{
      "statement": {
        "predicate": {
          "buildConfig": {
            "tasks": [{
              "invocation": {
                "environment": {
                  "annotations": {
                    "pipelinesascode.tekton.dev/source-branch": branch
                  }
                }
              }
            }]
          }
        }
      }
    }]
  }

  mock_rule_data := {
    "git_branch": {
      "allowed_branch_patterns": ["^refs/heads/main$", "^refs/heads/release-[23]$"]
    }
  }

  mock_tasks := mock_input.attestations[0].statement.predicate.buildConfig.tasks
  lib.assert_equal_results(expected_results, deny)
    with input as mock_input
    with data.rule_data as mock_rule_data
    with data.lib.tasks_from_pipelinerun as mock_tasks

  passed := true
}

test_deny_with_disallowed_branch {
  expected := [{
    "msg": "invalid branch",
    "details": ["invalid branch", "refs/heads/feature-branch"]
  }]
  git_branch_test_case("refs/heads/feature-branch", expected)
}

test_deny_with_unmatched_branch {
  expected := [{
    "msg": "invalid branch",
    "details": ["invalid branch", "refs/heads/release-1"]
  }]
  git_branch_test_case("refs/heads/release-1", expected)
}

test_allow_with_main_branch {
  git_branch_test_case("refs/heads/main", [])
}

test_allow_with_release_branch {
  git_branch_test_case("refs/heads/release-2", [])
}
