Feature: Golden Container Image

    Scenario: Red Hat collection
        Given a sample policy input "golden-container"
        And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/release"
                        ],
                        "data": [
                            "$GITROOT/example/data"
                        ],
                        "config": {
                            "include": [
                                "@redhat"
                            ],
                            "exclude": [
                                "cve.deprecated_cve_result_name",
                                "source_image"
                            ]
                        }
                    }
                ]
            }
            """
        When input is validated
        Then there should be no violations in the result
        Then there should be no warnings in the result

    Scenario: Various excludes
        Given a sample policy input "golden-container"
         And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/release"
                        ],
                        "data": [
                            "$GITROOT/example/data"
                        ],
                        "config": {
                            "include": ["*"],
                            "exclude": [
                                "@rhtap-jenkins",
                                "source_image",
                                "github_certificate",
                                "rpm_repos.ids_known:pkg:rpm/rhel/basesystem@11-13.el9?arch=noarch&upstream=basesystem-11-13.el9.src.rpm&distro=rhel-9.4"
                            ]
                        }
                    }
                ]
            }
            """
        When input is validated
        Then there should be no violations with "rhtap-jenkins" collection in the result
         And there should be no violations with "source_image" package in the result
         And there should be no violations with "rpm_repos.ids_known" code and "pkg:rpm/rhel/basesystem@11-13.el9?arch=noarch&upstream=basesystem-11-13.el9.src.rpm&distro=rhel-9.4" term in the result
         And there should be no warnings with "github_certificate" package in the result
