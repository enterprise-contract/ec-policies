#
# METADATA
# description: >-
#   This package verifies the build task in the attestation was invoked
#   with the expected parameters to perform a hermetic build.
#
package policy.release.hermetic_build_task

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.tkn

# METADATA
# title: Build task called with hermetic param set
# description: >-
#   Verify the build task in the PipelineRun attestation
#   was invoked with the proper parameters to make the build process
#   hermetic.
# custom:
#   short_name: build_task_hermetic
#   failure_msg: Build task was not invoked with the hermetic parameter set
#   solution: >-
#     Make sure the task that builds the image has a parameter named 'HERMETIC' and
#     it's set to 'true'.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	hermetic_build != "true"
	result := lib.result_helper(rego.metadata.chain(), [])
}

default hermetic_build := "false"

hermetic_build := value if {
	some attestation in lib.pipelinerun_attestations
	task := tkn.build_task(attestation)
	value := tkn.task_param(task, "HERMETIC")
}
