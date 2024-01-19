Feature: Task Definition

    Scenario: Successful Red Hat collection
        Given a sample policy input "clamav-task"
        And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/task"
                        ],
                        "data": [
                            "$GITROOT/example/data"
                        ],
                        "config": {
                            "include": [
                                "@redhat"
                            ]
                        }
                    }
                ]
            }
            """
        When input is validated
        Then there should be no violations in the result
        Then there should be no warnings in the result
