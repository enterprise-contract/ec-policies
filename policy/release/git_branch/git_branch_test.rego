package git_branch_test

import rego.v1

import data.lib

test_deny_with_disallowed_branch {
  input := {
    "attestations": [{
      "statement": {
        "predicate": {
          "buildConfig": {
            "tasks": [{
              "invocation": {
                "environment": {
                  "annotations": {
                    "pipelinesascode.tekton.dev/source-branch": "refs/heads/feature-branch"
                  }
                }
              }
            }]
          }
        }
      }
    }]
  }

  deny contains result
  result.msg == "invalid branch"
  result.details[1] == "refs/heads/feature-branch"
}

test_allow_with_main_branch {
  input := {
    "attestations": [{
      "statement": {
        "predicate": {
          "buildConfig": {
            "tasks": [{
              "invocation": {
                "environment": {
                  "annotations": {
                    "pipelinesascode.tekton.dev/source-branch": "refs/heads/main"
                  }
                }
              }
            }]
          }
        }
      }
    }]
  }

  not deny[result]
}
