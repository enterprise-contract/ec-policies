package policy.release.step_image_registries

import data.lib

# METADATA
# title: Task steps ran on container images that are disallowed
# description: |-
#   Enterprise Contract has a list of allowed registry prefixes. Each step in each
#   each TaskRun must run on a container image with a url that matches one of the
#   prefixes in the list.
# custom:
#   short_name: disallowed_task_step_image
#   failure_msg: Step %d in task '%s' has disallowed image ref '%s'
#   rule_data:
#     allowed_registry_prefixes:
#     - quay.io/redhat-appstudio/
#     - registry.access.redhat.com/
#     - registry.redhat.io/
#
deny[result] {
	att := lib.pipelinerun_attestations[_]
	task := att.predicate.buildConfig.tasks[_]
	step := task.steps[step_index]
	image_ref := step.environment.image
	not image_ref_permitted(image_ref, rego.metadata.rule().custom.rule_data.allowed_registry_prefixes)
	result := lib.result_helper(rego.metadata.chain(), [step_index, task.name, image_ref])
}

image_ref_permitted(image_ref, allowed_prefixes) {
	startswith(image_ref, allowed_prefixes[_])
}
