#
# METADATA
# description: >-
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
# title: Task steps ran on permitted container images
# description: >-
#   Enterprise Contract has a list of allowed registry prefixes. Each step in each
#   TaskRun must run on a container image with a url that matches one of the
#   prefixes in the list.
# custom:
#   short_name: task_step_images_permitted
#   failure_msg: Step %d in task '%s' has disallowed image ref '%s'
#   solution: >-
#     Make sure the container image used in each step of the build pipeline comes from
#     an approved registry. The approved list is under 'allowed_step_image_registry_prefixes'
#     in the xref:configuration.html#_data_sources[data sources].
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
# title: Permitted step image registry prefix list provided
# description: >-
#   The policy rules in this package require the allowed_step_image_registry_prefixes
#   rule data to be provided.
# custom:
#   short_name: step_image_registry_prefix_list_provided
#   failure_msg: Missing required allowed_step_image_registry_prefixes rule data
#   solution: >-
#     Make sure the xref:configuration.html#_data_sources[data sources] contains a key
#     'allowed_step_image_registry_prefixes' that contains a list of approved registries
#     that can be used to run tasks in the build pipeline.
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
