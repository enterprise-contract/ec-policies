package policies.source_image_task

import data.lib

# METADATA
# title: Verify the source-image-verify task accepts an image
# description: |-
#    Verify the source-image-verify task accepts a particular image
#    as an input param.
# custom:
#   short_name: disallowed_input_image
#   failure_msg: Task '%s' does not contain '%s' as a param
warn[result] {
	image_sha = data.source_image_verify.input_image
	task_name = data.source_image_verify.task_name
	task := lib.tasks_from_pipelinerun[_]
	task.name == task_name
	task.params.name == "IMAGE"
	task.params.value != image_sha
	result := lib.result_helper(rego.metadata.rule(), [task_name, image_sha])
}
