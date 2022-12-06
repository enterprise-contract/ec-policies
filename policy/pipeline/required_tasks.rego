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
import data.lib.bundles
import data.lib.refs
import data.lib.time

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
	count(_tasks) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
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
	count(_tasks) > 0
	some required_task in _missing_tasks(_current_required_tasks)

	# Don't report an error if a task is required now, but not in the future
	required_task in _latest_required_tasks
	result := lib.result_helper(rego.metadata.chain(), [required_task])
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
	count(_tasks) > 0
	some required_task in _missing_tasks(_latest_required_tasks)

	# If the required_task is also part of the _current_required_tasks, do
	# not proceed with a warning since that's clearly a violation.
	not required_task in _current_required_tasks
	result := lib.result_helper(rego.metadata.chain(), [required_task])
}

_trusted_tasks contains name if {
	some task in _tasks
	task_ref := refs.task_ref(task)
	task_ref.kind == "task"
	bundle_ref := task_ref.bundle
	bundles.is_acceptable(bundle_ref)
	some name in _task_names(task, task_ref.name)
}

_tasks := result if {
	spec := object.get(input, "spec", {})
	result := array.concat(
		object.get(spec, "tasks", []),
		object.get(spec, "finally", []),
	)
}

_task_names(task, raw_name) = names if {
	name := split(raw_name, "[")[0] # don't allow smuggling task name with parameters
	params := {n |
		v := _params(task)[k]
		n := sprintf("%s[%s=%s]", [name, k, v])
	}
	names := {name} | params
}

# The latest set of required tasks. Tasks here are not required right now
# but will be required in the future.
_latest_required_tasks contains task if {
	some task in data["required-tasks"][0].tasks
}

# The set of required tasks that are required right now.
_current_required_tasks contains task if {
	some task in time.most_current(data["required-tasks"]).tasks
}

# _missing_tasks returns a set of task names that are in the given
# required_tasks, but not in the PipelineRun attestation.
_missing_tasks(required_tasks) := tasks if {
	tasks := {task |
		some task in required_tasks
		not task in _trusted_tasks
	}
}

_params(task) := result if {
	result := {name: value |
		some param in task.params
		name := _named_param(param, "name")
		value := _named_param(param, "value")
	}
}

_named_param(param, name) := value if {
	some key, value in param
	key == name
}
