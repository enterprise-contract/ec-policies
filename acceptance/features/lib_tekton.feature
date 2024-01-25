Feature: Lib Tekton
    #
    # Exercise some of the rego logic used to extract task data against
    # real-ish attestations.
    #
    # Pros: It's higher level testing and (hopefully) easier to understand
    # and maintain than the low level rego unit tests with the many snippets
    # of mocked data, and it uses real attestation data as produced by Chains.
    #
    # Cons: EC does not actually use opa like this, so the testing is a little
    # separate from real world usage.
    #
    Scenario: SLSA V0.2 tasks
        Given a sample policy input "v02-sample-attestation"

        When we opa eval
        """
          [ t |
            data.lib.tkn.tasks({"statement":input})[task]
            t := data.lib.tkn.task_data(task)
          ]
        """

        Then the opa result json should be
        """
          [
            {
              "name": "mock-av-scanner"
            },
            {
              "name": "\u003cNAMELESS\u003e"
            },
            {
              "bundle": "quay.io/lucarval/test-policies-chains@sha256:ae5952d5aac1664fbeae9191d9445244051792af903d28d3e0084e9d9b7cce61",
              "name": "mock-build"
            },
            {
              "name": "mock-git-clone"
            }
          ]
        """

    Scenario: SLSA V1.0 tasks
        Given a sample policy input "v1-sample-attestation"

        When we opa eval
        """
          [ t |
            data.lib.tkn.tasks({"statement":input})[task]
            t := data.lib.tkn.task_data(task)
          ]
        """
        Then the opa result json should be
        """
          [
            {
              "name": "mock-git-clone"
            },
            {
              "name": "mock-av-scanner"
            },
            {
              "name": "\u003cNAMELESS\u003e"
            },
            {
              "bundle": "quay.io/lucarval/test-policies-chains@sha256:b766741b8b3e135e4e31281aa4b25899e951798b5f213cc4a5360d01eb9b6880",
              "name": "mock-build"
            }
          ]
        """
