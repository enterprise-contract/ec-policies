#
# METADATA
# description: |-
#   This package contains a rule to ensure that each task in the image's
#   build pipeline ran using a container image from a known and presumably
#   trusted source.
#
package policy.release.step_image_registries

import future.keywords.contains
import future.keywords.if
import future.keywords.in

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
#   collections:
#   - minimal
#
deny contains result if {
	some task in lib.pipelinerun_attestations[_].predicate.buildConfig.tasks
	step := task.steps[step_index]
	image_ref := step.environment.image
	allowed_registry_prefixes := lib.rule_data("allowed_step_image_registry_prefixes")
	not image_ref_permitted(image_ref, allowed_registry_prefixes)
	result := lib.result_helper(rego.metadata.chain(), [step_index, task.name, image_ref])
}

# METADATA
# title: Missing rule data
# description: |-
#   The policy rules in this package require the allowed_step_image_registry_prefixes
#   rule data to be provided.
# custom:
#   short_name: missing_rule_data
#   failure_msg: Missing required allowed_step_image_registry_prefixes rule data
#   collections:
#   - minimal
#
deny contains result if {
	count(lib.rule_data("allowed_step_image_registry_prefixes")) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

image_ref_permitted(image_ref, allowed_prefixes) if {
	startswith(image_ref, allowed_prefixes[_])
}
