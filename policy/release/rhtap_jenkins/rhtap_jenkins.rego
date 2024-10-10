#
# METADATA
# title: RHTAP Jenkins
# description: >-
#   Some initial checks for images built using an RHTAP Jenkins build pipeline. Note
#   that the RHTAP Jenkins pipeline is WIP currently, but will be shipped in an upcoming
#   release of RHTAP. It's expected more useful checks will be added in future. RHTAP
#   Jenkins pipelines are defined under
#   https://github.com/redhat-appstudio/tssc-sample-templates/tree/main/skeleton/ci
#
package release.rhtap_jenkins

import rego.v1

import data.lib

# METADATA
# title: RHTAP Jenkins SLSA Provenance Attestation Found
# description: >-
#   Verify an attestation created by the RHTAP Jenkins build pipeline is present.
# custom:
#   short_name: attestation_found
#   failure_msg: The expected SLSA v1.0 provenance with build type %s was not found.
#   solution: >-
#     It appears the build pipeline did not create a SLSA provenance attestation.
#     Check the logs in Jenkins for the cosign-sign-attest stage to see if you can
#     find out why.
#   collections:
#   - rhtap-jenkins
#
deny contains result if {
	count(lib.rhtap_jenkins_attestations) < 1
	result := lib.result_helper(rego.metadata.chain(), [lib.rhtap_jenkins_build_type])
}

# METADATA
# title: RHTAP Jenkins SLSA Invocation ID present
# description: >-
#   Confirm that an invocation ID was found in the attestation in the expected location.
# custom:
#   short_name: invocation_id_found
#   failure_msg: The build provenance metadata did not contain an invocation id.
#   solution: >-
#     For some reason the invocation id was missing or empty in the build provenance.
#     It should be located at `predicate.runDetails.metadata.invocationID` in the
#     attestation statement.
#   collections:
#   - rhtap-jenkins
#   depends_on:
#   - rhtap_jenkins.attestation_found
#
deny contains result if {
	attestations_with_invocation_id := {att |
		some att in lib.rhtap_jenkins_attestations
		invocation_id := att.statement.predicate.runDetails.metadata.invocationID
		trim_space(invocation_id) != ""
	}

	# We're expecting just one attestation, but if there are multiple let's apply this check
	# to all of them. Note that we don't produce a violation if lib.rhtap_jenkins_attestations
	# has zero length. (The 'attestation_found' violation defined above would be produced.)
	count(attestations_with_invocation_id) != count(lib.rhtap_jenkins_attestations)

	result := lib.result_helper(rego.metadata.chain(), [])
}
