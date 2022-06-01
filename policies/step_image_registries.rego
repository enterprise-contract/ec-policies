# METADATA
# custom:
#   effective_on: 2022-01-01T00:00:00Z
package policies.step_image_registries

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
#   allowed_registry_prefixes:
#   - quay.io/buildah
#   - quay.io/redhat-appstudio
#   - registry.access.redhat.com/ubi8
#   - registry.access.redhat.com/ubi8-minimal
#   - registry.redhat.io/ocp-tools-4-tech-preview
#   - registry.redhat.io/openshift4
#   - registry.redhat.io/openshift-pipelines
#
deny[result] {
	att := lib.pipelinerun_attestations[_]
	task := att.predicate.buildConfig.tasks[_]
	step := task.steps[step_index]
	image_ref := step.environment.image
	not image_ref_permitted(image_ref, rego.metadata.rule().custom.allowed_registry_prefixes)
	result := lib.result_helper(rego.metadata.chain(), [step_index, task.name, image_ref])
}

image_ref_permitted(image_ref, allowed_prefixes) {
	startswith(image_ref, allowed_prefixes[_])
}
