#
# METADATA
# title: SLSA - Build - Scripted Build
# description: >-
#   The SLSA requirement states the following:
#
#   "All build steps were fully defined in some sort of “build script”.
#   The only manual command, if any, was to invoke the build script."
#
#   This package verifies the requirement by asserting the image was
#   built by Tekton Pipelines.
#
package policy.release.slsa_build_scripted_build

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.image
import data.lib.tkn

# METADATA
# title: Build task contains steps
# description: >-
#   Verify that the predicate.buildConfig.tasks.steps attribute for the task
#   responsible for building and pushing the image is not empty.
# custom:
#   short_name: build_script_used
#   failure_msg: Build task %q does not contain any steps
#   solution: >-
#     There were no build tasks detected. Make sure the build pipeline contains
#     tasks and that the build system is recording them properly when the attestation
#     is generated.
#   collections:
#   - slsa3
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	build_task := tkn.build_task(attestation)
	count(task_steps(build_task)) == 0
	result := lib.result_helper(rego.metadata.chain(), [build_task.name])
}

# METADATA
# title: Build task set image digest and url task results
# description: >-
#   Confirm that a build task exists and it has the expected
#   IMAGE_DIGEST and IMAGE_URL task results.
# custom:
#   short_name: build_task_image_results_found
#   failure_msg: Build task not found
#   solution: >-
#     Make sure the build pipeline contains a build task. The build task
#     must contain results named 'IMAGE_DIGEST' and 'IMAGE_URL'.
#   collections:
#   - slsa3
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	not tkn.build_task(attestation)
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Provenance subject matches build task image result
# description: >-
#   Verify the subject of the attestations matches the IMAGE_DIGEST and
#   IMAGE_URL values from the build task.
# custom:
#   short_name: subject_build_task_matches
#   failure_msg: The attestation subject, %q, does not match the build task image, %q
#   solution: >-
#     Make sure the subject in the attestation matches the 'IMAGE_URL' and 'IMAGE_DIGEST'
#     results from the build task. The format for the subject should be 'IMAGE_URL@IMAGE_DIGEST'.
#   collections:
#   - slsa3
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	build_task := tkn.build_task(attestation)

	some subject in attestation.statement.subject

	subject_image_ref := concat("@", [subject.name, subject_digest(subject)])
	result_image_ref := concat("@", [
		tkn.task_result(build_task, "IMAGE_URL"),
		tkn.task_result(build_task, "IMAGE_DIGEST"),
	])

	not image.equal_ref(subject_image_ref, result_image_ref)

	result := lib.result_helper(rego.metadata.chain(), [subject_image_ref, result_image_ref])
}

task_steps(task) := steps if {
	steps := task.steps
} else := []

subject_digest(subject) := digest if {
	some algorithm, value in subject.digest
	digest := concat(":", [algorithm, value])
}
