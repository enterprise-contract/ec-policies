#
# METADATA
# title: Required tasks
# description: >-
#   RHTAP expects that certain Tekton tasks are executed during image builds.
#   This package includes policy rules to confirm that the pipeline definition
#   includes those required tasks.
#
package policy.pipeline.required_tasks

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.tkn

# METADATA
# title: Pipeline contains tasks
# description: >-
#   Confirm at least one task is present in the pipeline definition.
# custom:
#   short_name: tasks_found
#   failure_msg: No tasks found in pipeline
deny contains result if {
	input.kind == "Pipeline"
	count(tkn.tasks(input)) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Required tasks found in pipeline definition
# description: >-
#   Produce a warning if a task list does not exist in the acceptable
#   bundles rule data.
# custom:
#   short_name: required_tasks_found
#   failure_msg: Required tasks do not exist for pipeline %q
warn contains result if {
	count(tkn.tasks(input)) > 0

	# check for current tasks
	not tkn.current_required_pipeline_tasks(input)

	# check for future tasks
	not tkn.latest_required_pipeline_tasks(input)
	result := lib.result_helper(rego.metadata.chain(), [tkn.pipeline_name])
}

# METADATA
# title: Missing required task
# description: >-
#   Ensure that the set of required tasks is included
#   in the Pipeline definition.
# custom:
#   short_name: missing_required_task
#   failure_msg: Required task %q is missing
deny contains result if {
	count(tkn.tasks(input)) > 0

	# Get missing tasks by comparing with the default required task list
	some required_task in _missing_tasks(current_required_tasks)

	# Don't report an error if a task is required now, but not in the future
	required_task in latest_required_tasks
	result := lib.result_helper_with_term(rego.metadata.chain(), [required_task], required_task)
}

# METADATA
# title: Missing future required task
# description: >-
#   Produce a warning when a task that will be required in the future
#   is not currently included in the Pipeline definition.
# custom:
#   short_name: missing_future_required_task
#   failure_msg: Task %q is missing and will be required in the future
warn contains result if {
	count(tkn.tasks(input)) > 0

	# Get missing tasks by comparing with the default required task list
	some required_task in _missing_tasks(latest_required_tasks)

	# If the required_task is also part of the current_required_tasks, do
	# not proceed with a warning since that's clearly a violation.
	not required_task in current_required_tasks
	result := lib.result_helper_with_term(rego.metadata.chain(), [required_task], required_task)
}

# METADATA
# title: Required task list is present in rule data
# description: >-
#   Confirm the `required-tasks` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: required_tasks_list_present
#   failure_msg: The required tasks list is missing from the rule data
deny contains result if {
	tkn.missing_required_tasks_data
	not tkn.required_task_list(input)
	result := lib.result_helper(rego.metadata.chain(), [])
}

# _missing_tasks returns a set of task names that are in the given
# required_tasks, but not in the pipeline definition.
_missing_tasks(required_tasks) := {task |
	some task in required_tasks
	not task in tkn.tasks_names(input)
}

# get the future tasks that are pipeline specific. If none exists
# get the default list
latest_required_tasks := task_data if {
	task_data := tkn.latest_required_pipeline_tasks(input)
} else := task_data if {
	task_data := tkn.latest_required_default_tasks
}

# get the current tasks that are pipeline specific. If none exists
# get the default list
current_required_tasks := task_data if {
	task_data := tkn.current_required_pipeline_tasks(input)
} else := task_data if {
	task_data := tkn.current_required_default_tasks
}
