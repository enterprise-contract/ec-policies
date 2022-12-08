#
# METADATA
# description: |-
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
# title: hermetic_build_task
# description: |-
#   This policy verifies the build task in the PipelineRun attestation
#   was invoked with the proper parameters to make the build process
#   hermetic.
# custom:
#   short_name: build_task_not_hermetic
#   failure_msg: Build task was not invoked with hermetic parameter
deny contains result if {
	hermetic_build != "true"
	result := lib.result_helper(rego.metadata.chain(), [])
}

hermetic_build := value if {
	some attestation in lib.pipelinerun_attestations
	task := tkn.trusted_build_task(attestation)
	value := tkn.task_param(task, "HERMETIC_BUILD")
} else := "false"
