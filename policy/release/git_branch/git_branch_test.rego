package git_branch_test

import rego.v1
import data.lib

mock_rule_data := {
  "git_branch": {
    "allowed_branch_patterns": ["^refs/heads/main$", "^refs/heads/release-[23]$"]
  }
}

test_deny_with_disallowed_branch {
  mock_input := {
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

  expected := [{
    "msg": "invalid branch",
    "details": ["invalid branch", "refs/heads/feature-branch"]
  }]

  lib.assert_equal_results(expected, deny) with input as mock_input with data.rule_data as mock_rule_data
}

test_deny_with_unmatched_branch {
  mock_input := {
    "attestations": [{
      "statement": {
        "predicate": {
          "buildConfig": {
            "tasks": [{
              "invocation": {
                "environment": {
                  "annotations": {
                    "pipelinesascode.tekton.dev/source-branch": "refs/heads/release-1"
                  }
                }
              }
            }]
          }
        }
      }
    }]
  }

  expected := [{
    "msg": "invalid branch",
    "details": ["invalid branch", "refs/heads/release-1"]
  }]

  lib.assert_equal_results(expected, deny) with input as mock_input with data.rule_data as mock_rule_data
}

test_allow_with_main_branch {
  mock_input := {
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

  expected := []

  lib.assert_equal_results(expected, deny) with input as mock_input with data.rule_data as mock_rule_data
}

test_allow_with_release_branch {
  mock_input := {
    "attestations": [{
      "statement": {
        "predicate": {
          "buildConfig": {
            "tasks": [{
              "invocation": {
                "environment": {
                  "annotations": {
                    "pipelinesascode.tekton.dev/source-branch": "refs/heads/release-2"
                  }
                }
              }
            }]
          }
        }
      }
    }]
  }

  expected := []

  lib.assert_equal_results(expected, deny) with input as mock_input with data.rule_data as mock_rule_data
}
