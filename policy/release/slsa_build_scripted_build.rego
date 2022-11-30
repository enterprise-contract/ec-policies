#
# METADATA
# title: SLSA - Build - Scripted Build
# description: |-
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
import data.lib.bundles

# METADATA
# title: Build task contains steps
# description: |-
#   The attestation attribute predicate.buildConfig.tasks.steps is not
#   empty of the pipeline task responsible for building the image.
# custom:
#   short_name: empty_build_task
#   failure_msg: Build task %q does not contain any steps
#
deny contains result if {
	count(task_steps(build_task)) == 0
	result := lib.result_helper(rego.metadata.chain(), [build_task.name])
}

# METADATA
# title: Build task missing
# description: |-
#   The attestations must contain a build task with the expected
#   IMAGE_DIGEST and IMAGE_URL results.
# custom:
#   short_name: missing_build_task
#   failure_msg: Build task not found
#
deny contains result if {
	count(lib.pipelinerun_attestations) > 0
	not build_task
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Mismatch subject
# description: |-
#   The subject of the attestations must match the IMAGE_DIGEST and
#   IMAGE_URL values from the build task.
# custom:
#   short_name: subject_build_task_mismatch
#   failure_msg: The attestation subject, %q, does not match the build task image, %q
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some subject in attestation.subject

	subject_image_ref := concat("@", [subject.name, subject_digest(subject)])
	result_image_ref := concat("@", [
		task_result(build_task, "IMAGE_URL").value,
		task_result(build_task, "IMAGE_DIGEST").value,
	])
	subject_image_ref_no_tag := regex.replace(subject_image_ref, ":[^@]+@", "@")
	result_image_ref_no_tag := regex.replace(result_image_ref, ":[^@]+@", "@")

	subject_image_ref != result_image_ref # the subjects differ
	subject_image_ref_no_tag != result_image_ref_no_tag # and the subjects differ without tags, NOTE: digest is always present (in IMAGE_DIGEST result)

	result := lib.result_helper(rego.metadata.chain(), [subject_image_ref, result_image_ref])
}

task_steps(task) := steps if {
	steps := build_task.steps
} else := [] if {
	true
}

build_task := task if {
	some task in lib.tasks_from_pipelinerun

	bundle := lib.task_data(task)[lib.key_bundle]
	bundles.is_acceptable(bundle)

	image_url := task_result(task, "IMAGE_URL")
	image_url
	image_url.value
	count(trim_space(image_url.value)) > 0

	image_digest := task_result(task, "IMAGE_DIGEST")
	image_digest
	image_digest.value
	count(trim_space(image_digest.value)) > 0
}

task_result(task, name) := result if {
	some result in task.results
	result.name == name
}

subject_digest(subject) := digest if {
	some algorithm, value in subject.digest
	digest := concat(":", [algorithm, value])
}
