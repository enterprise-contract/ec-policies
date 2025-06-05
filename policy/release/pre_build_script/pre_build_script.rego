#
# METADATA
# title: Pre-build-script task checks
# description: >-
#   This package verifies that the pre-build-script task in the
#   attestation is run in a controlled environment: it must be
#   hermetic, and running in an allowed image)
#
package pre_build_script

import rego.v1

import data.lib
import data.lib.tekton

# METADATA
# title: Pre-Build-Script task called with hermetic param set
# description: >-
#   Verify the pre-build-script task (run-script-oci-ta) in the
#   PipelineRun	attestation was invoked with the proper parameters to
#   make the pre-build script execution hermetic.
# custom:
#   short_name: pre_build_script_hermetic
#   failure_msg: >-
#     Pre-Build-Script task was not invoked with
#     the hermetic parameter set: '%s'
#   solution: >-
#     Make sure that the pre-build-script task (run-script-oci-ta) has
#     a parameter named 'HERMETIC' and it's set to 'true'.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some not_hermetic_script_task in _hermetic_pre_build_scripts
	result := lib.result_helper(rego.metadata.chain(), [tekton.task_name(not_hermetic_script_task)])
}

_hermetic_pre_build_scripts contains task if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_script_tasks(attestation)
	not tekton.task_is_hermetic(task)
}
