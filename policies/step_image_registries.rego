package policies.step_image_registries

import data.lib

# List of allowed registry prefixes for task images used to run task steps
# This is placeholder since I have no idea what the real policy should be
allowed_registry_prefixes := [
	"quay.io/buildah",
	"quay.io/redhat-appstudio",
	"registry.access.redhat.com/ubi8",
	"registry.access.redhat.com/ubi8-minimal",
	"registry.redhat.io/ocp-tools-4-tech-preview",
	"registry.redhat.io/openshift4",
	"registry.redhat.io/openshift-pipelines",
]

# METADATA
# title: Task steps ran on container images that are disallowed
# custom:
#   short_name: disallowed_task_step_image
#   failure_msg: Step %d has disallowed image ref '%s'
#
deny[result] {
	att := input.attestations[_]
	step := att.predicate.buildConfig.steps[step_index]
	image_ref := step.environment.image
	not image_ref_permitted(image_ref)

	result := lib.result_helper(rego.metadata.rule(), [step_index, image_ref])
}

image_ref_permitted(image_ref) {
	startswith(image_ref, allowed_registry_prefixes[_])
}
