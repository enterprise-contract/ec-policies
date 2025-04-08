package git_branch_test

import rego.v1
import data.lib

rule_data := {
  "git_branch": {
    "allowed_branch_patterns": ["^refs/heads/main$", "^refs/heads/release-[23]$"]
  }
}

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

  data := {"rule_data": rule_data}

  deny contains result
  result.msg == "invalid branch"
  result.details[1] == "refs/heads/feature-branch"
}

test_deny_with_unmatched_branch {
  input := {
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

  data := {"rule_data": rule_data}

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

  data := {"rule_data": rule_data}

  not deny[result]
}

test_allow_with_release_branch {
  input := {
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

  data := {"rule_data": rule_data}

  not deny[result]
}
