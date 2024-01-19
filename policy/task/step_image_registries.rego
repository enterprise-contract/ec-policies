#
# METADATA
# description: >-
#   This package ensures that a Task definition contains expected values for the image references
#   used by the Task's steps.
#
package policy.task.step_image_registries

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Step images come from permitted registry
# description: >-
#   Confirm that each step in the Task uses a container image with a URL that matches one of the
#   prefixes in the provided list of allowed step image registry prefixes. The list is customizeable
#   via the `allowed_step_image_registry_prefixes` rule data key.
# custom:
#   short_name: step_images_permitted
#   failure_msg: Step %d uses disallowed image ref '%s'
#   solution: >-
#     Make sure the container image used in each step of the Task comes from an approved registry.
#   collections:
#   - redhat
#
deny contains result if {
	allowed_registry_prefixes := lib.rule_data(_rule_data_key)

	input.kind == "Task"

	some step_index, step in input.spec.steps
	image_ref := step.image
	not image_ref_permitted(image_ref, allowed_registry_prefixes)

	result := lib.result_helper(rego.metadata.chain(), [step_index, image_ref])
}

# METADATA
# title: Permitted step image registry prefix list provided
# description: >-
#   Confirm the `allowed_step_image_registry_prefixes` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: step_image_registry_prefix_list_provided
#   failure_msg: "%s"
#   solution: >-
#     Make sure the xref:ec-cli:ROOT:configuration.adoc#_data_sources[data sources] contains a key
#     'allowed_step_image_registry_prefixes' that contains a list of approved registries
#     that can be used to run tasks in the build pipeline.
#   collections:
#   - policy_data
#   - redhat
#
deny contains result if {
	some error in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

image_ref_permitted(image_ref, allowed_prefixes) if {
	some allowed_prefix in allowed_prefixes
	startswith(image_ref, allowed_prefix)
}

_rule_data_errors contains msg if {
	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(_rule_data_key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
			"minItems": 1,
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, violation.error])
}

_rule_data_key := "allowed_step_image_registry_prefixes"
