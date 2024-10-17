#
# METADATA
# title: Hermetic build task
# description: >-
#   This package verifies the build task in the attestation was invoked
#   with the expected parameters to perform a hermetic build.
#
package hermetic_build_task

import rego.v1

import data.lib
import data.lib.tekton

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
	_hermetic_build != {"true"}
	result := lib.result_helper(rego.metadata.chain(), [])
}

_hermetic_build contains value if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.build_tasks(attestation)
	value := tekton.task_param(task, "HERMETIC")
}
