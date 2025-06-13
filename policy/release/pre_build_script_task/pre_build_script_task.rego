#
# METADATA
# title: Pre-build-script task checks
# description: >-
#   This package verifies that the pre-build-script tasks in the
#   attestation are executed in a controlled environment
#
package pre_build_script_task

import rego.v1

import data.lib
import data.lib.sbom
import data.lib.tekton

# METADATA
# title: Script runner image is listed in the task results
# description: >-
#   Verify that the image used to run the pre-build script task is
#   listed in the task output SCRIPT_RUNNER_IMAGE_REFERENCE
# custom:
#   short_name: pre_build_script_task_runner_image_in_results
#   failure_msg: >-
#     The runner image used for the pre-Build-Script task '%s' is not
#     listed in the task results
#   solution: >-
#     Make sure the image used to run the pre-build task is referenced
#     in the 'SCRIPT_RUNNER_IMAGE_REFERENCE' task result.
#   collections:
#   - redhat
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_tasks(attestation)
	not tekton.task_result(task, _pre_build_run_script_runner_image_result)
	result := lib.result_helper(rego.metadata.chain(), [tekton.task_name(task)])
}

# METADATA
# title: Script runner image is included in the sbom
# description: >-
#   Verify that the image used to run the pre-build script task is
#   included in the SBOM
# custom:
#   short_name: pre_build_script_task_runner_image_in_sbom
#   failure_msg: Pre-Build-Script task runner image %q is not in the SBOM
#   solution: >-
#     Make sure the image referenced in the 'SCRIPT_RUNNER_IMAGE_REFERENCE'
#     output is included in the SBOM.
#   collections:
#   - redhat
#
deny contains result if {
	some pre_build_image in _script_runner_image_refs
	not _is_image_in_sbom(pre_build_image)
	result := lib.result_helper(rego.metadata.chain(), [pre_build_image])
}

_script_runner_image_refs := [image_ref |
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_tasks(attestation)
	image_ref := tekton.task_result(task, _pre_build_run_script_runner_image_result)
]

_pre_build_run_script_runner_image_result := "SCRIPT_RUNNER_IMAGE_REFERENCE"

_is_image_in_sbom(image) if {
	some s in sbom.all_sboms
	some purl in _purls_from_sbom(s)
	purl == image
}

_purls_from_sbom(s) := purls if {
	# CycloneDX
	purls := {component.purl |
		some component in s.components
	}
	count(purls) > 0
} else := purls if {
	# SPDX
	purls := {ref.referenceLocator |
		some pkg in s.packages
		some ref in pkg.externalRefs
		ref.referenceType == "purl"
		ref.referenceCategory == "PACKAGE-MANAGER"
	}
	count(purls) > 0
}
