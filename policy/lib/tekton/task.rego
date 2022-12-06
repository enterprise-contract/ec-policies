package lib.tkn

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib.bundles
import data.lib.refs
import data.lib.time

# The latest set of required tasks. Tasks here are not required right now
# but will be required in the future.
latest_required_tasks contains task if {
	some task in data["required-tasks"][0].tasks
}

# The set of required tasks that are required right now.
current_required_tasks contains task if {
	some task in time.most_current(data["required-tasks"]).tasks
}

# tasks returns a list of tasks.
# Handle tasks from a PipelineRun attestation.
tasks(attestation) := _tasks if {
	attestation.predicate.buildConfig
	_tasks := [task |
		some task in attestation.predicate.buildConfig.tasks
	]
}

# Handle tasks from a Pipeline defintion.
tasks(pipeline) := _tasks if {
	not pipeline.predicate.buildConfig
	spec := object.get(pipeline, "spec", {})
	_tasks := array.concat(
		object.get(spec, "tasks", []),
		object.get(spec, "finally", []),
	)
}

# trusted_tasks returns a set of task names that are found
# in the given obj coming from an acceptable bundle.
trusted_tasks(obj) := names if {
	names = {name |
		some task in tasks(obj)
		task_ref := refs.task_ref(task)
		task_ref.kind == "task"
		bundle_ref := task_ref.bundle
		bundles.is_acceptable(bundle_ref)
		some name in _task_names(task, task_ref.name)
	}
}

# task_names returns the different names of the task. Additional
# names are produced for each parameter given to the task. For
# example, {"my-task", "my-task[spam=maps]" is produced for a
# task named "my-task" which takes the parameter "spam" with
# value "maps".
_task_names(task, raw_name) := names if {
	name := split(raw_name, "[")[0] # don't allow smuggling task name with parameters
	params := {n |
		some k, v in _task_params(task)
		n := sprintf("%s[%s=%s]", [name, k, v])
	}
	names := {name} | params
}

# _task_params returns an object where keys are parameter names
# and values are parameter values.
# Handle parameters of a task from a PipelineRun attestation.
_task_params(task) := params if {
	params := task.invocation.parameters
}

# Handle parameters of a task in a Pipeline definition.
_task_params(task) := params if {
	task.params
	params := {name: value |
		some param in task.params
		name := _key_value(param, "name")
		value := _key_value(param, "value")
	}
}

_key_value(obj, name) := value if {
	some key, value in obj
	key == name
}
