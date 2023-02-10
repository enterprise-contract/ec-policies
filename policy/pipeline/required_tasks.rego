#
# METADATA
# description: |-
#   HACBS expects that certain Tekton tasks are executed during image builds.
#   This package includes policy rules to confirm that the pipeline definition
#   includes the required Tekton tasks.
#
package policy.pipeline.required_tasks

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.tkn

# METADATA
# title: No tasks in Pipeline
# description: |-
#   This policy enforces that at least one Task is present in the Pipeline
#   definition.
# custom:
#   short_name: tasks_missing
#   failure_msg: No tasks found in Pipeline definition
deny contains result if {
	input.kind == "Pipeline"
	count(tkn.tasks(input)) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Missing required pipeline tasks
# description: |-
#   This policy warns if a task list does not exist in the acceptable_bundles.yaml file
# custom:
#   short_name: missing_required_pipeline_task
#   failure_msg: Required tasks do not exist for pipeline %q
warn contains result if {
	count(tkn.tasks(input)) > 0
	not tkn.current_required_pipeline_tasks(input)
	result := lib.result_helper(rego.metadata.chain(), [tkn.pipeline_name])
}

# METADATA
# title: Missing required task
# description: |-
#   This policy enforces that the required set of tasks are included
#   in the Pipeline definition.
# custom:
#   short_name: missing_required_task
#   failure_msg: Required task %q is missing
deny contains result if {
	count(tkn.tasks(input)) > 0

	# Get missing tasks by comparing with the default required task list
	some required_task in _missing_tasks(tkn.current_required_tasks)

	# Don't report an error if a task is required now, but not in the future
	required_task in tkn.latest_required_tasks
	result := lib.result_helper_with_term(rego.metadata.chain(), [required_task], required_task)
}

# METADATA
# title: Missing future required task
# description: |-
#   This policy warns when a task that will be required in the future
#   was not included in the Pipeline definition.
# custom:
#   short_name: missing_future_required_task
#   failure_msg: Task %q is missing and will be required in the future
warn contains result if {
	count(tkn.tasks(input)) > 0

	# Get missing tasks by comparing with the default required task list
	some required_task in _missing_tasks(tkn.latest_required_tasks)

	# If the required_task is also part of the current_required_tasks, do
	# not proceed with a warning since that's clearly a violation.
	not required_task in tkn.current_required_tasks
	result := lib.result_helper_with_term(rego.metadata.chain(), [required_task], required_task)
}

# METADATA
# title: Missing required tasks data
# description: |-
#   The policy rules in this package require the required-tasks data to be provided.
# custom:
#   short_name: missing_required_data
#   failure_msg: Missing required task-bundles data
deny contains result if {
	tkn.missing_required_tasks_data
	not tkn.required_task_list(input)
	result := lib.result_helper(rego.metadata.chain(), [])
}

# _missing_tasks returns a set of task names that are in the given
# required_tasks, but not in the pipeline definition.
_missing_tasks(required_tasks) := tasks if {
	tasks := {task |
		some task in required_tasks
		not task in tkn.tasks_names(input)
	}
}
