#
# METADATA
# title: RHTAP GitLab
# description: >-
#   Some initial checks for images built using an RHTAP GitLab build pipeline. Note
#   that the RHTAP GitLab pipeline is WIP currently, but will be shipped in an upcoming
#   release of RHTAP. It's expected more useful checks will be added in future. RHTAP
#   GitLab pipelines are defined under
#   https://github.com/redhat-appstudio/tssc-sample-templates/tree/main/skeleton/ci
#
package rhtap_gitlab

import rego.v1

import data.lib

# METADATA
# title: RHTAP GitLab SLSA Provenance Attestation Found
# description: >-
#   Verify an attestation created by the RHTAP GitLab build pipeline is present.
# custom:
#   short_name: attestation_found
#   failure_msg: The expected SLSA v1.0 provenance with build type %s was not found.
#   solution: >-
#     It appears the build pipeline did not create a SLSA provenance attestation.
#     Check the logs in GitLab for the cosign-sign-attest stage to see if you can
#     find out why.
#   collections:
#   - rhtap-gitlab
#
deny contains result if {
	count(_rhtap_attestations) < 1
	result := lib.result_helper(rego.metadata.chain(), [_rhtap_build_type])
}

_rhtap_attestations := lib.rhtap_attestations(_rhtap_ci_type)

_rhtap_build_type := lib.rhtap_build_type(_rhtap_ci_type)

_rhtap_ci_type := "gitlab"
