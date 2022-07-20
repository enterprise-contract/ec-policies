package policy.release.attestation_task_bundle

import data.lib

# METADATA
# title: Task bundle was not used or is not defined
# description: |-
#   Check for existence of a task bundle. Enforcing this rule will
#   fail the contract if the task is not called from a bundle.
# custom:
#   short_name: disallowed_task_reference
#   failure_msg: Task '%s' does not contain a bundle reference
#
deny[result] {
	task := lib.tasks_from_pipelinerun[_]
	name := task.name
	not task.ref.bundle
	result := lib.result_helper(rego.metadata.chain(), [name])
}

# METADATA
# title: Task bundle was used that was disallowed
# description: |-
#   Check for existence of a valid task bundle. Enforcing this rule will
#   fail the contract if the task is not called using a valid bundle image.
# custom:
#   short_name: disallowed_task_bundle
#   failure_msg: Task '%s' has disallowed bundle image '%s'
#   rule_data:
#     allowed_bundles:
#     - quay.io/redhat-appstudio/build-templates-bundle
#     - quay.io/redhat-appstudio/hacbs-templates-bundle
#     - quay.io/redhat-appstudio/appstudio-tasks
#
deny[result] {
	task := lib.tasks_from_pipelinerun[_]
	name := task.name
	bundle := split(task.ref.bundle, ":")
	not lib.item_in_list(bundle[0], rego.metadata.rule().custom.rule_data.allowed_bundles)
	result := lib.result_helper(rego.metadata.chain(), [name, bundle[0]])
}
