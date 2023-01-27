package lib.tkn

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib.refs
import data.lib.time

missing_required_tasks_data if {
	count(data["required-tasks"]) == 0
} else := false

# The latest set of required tasks. Tasks here are not required right now
# but will be required in the future.
latest_required_tasks contains task if {
	some task in time.newest(data["required-tasks"]).tasks
}

# The set of required tasks that are required right now.
current_required_tasks contains task if {
	some task in time.most_current(data["required-tasks"]).tasks
}

# tasks returns the set of tasks found in the object.
tasks(obj) := _tasks if {
	_tasks := {task |
		some task in _maybe_tasks(obj)
		task_ref := refs.task_ref(task)
		task_ref.kind == "task"
	}
}

# _maybe_tasks returns a set of potential tasks.
# Handle tasks from a PipelineRun attestation.
_maybe_tasks(attestation) := _tasks if {
	attestation.predicate.buildConfig
	_tasks := attestation.predicate.buildConfig.tasks
}

# Handle tasks from a Pipeline defintion.
_maybe_tasks(pipeline) := _tasks if {
	not pipeline.predicate.buildConfig
	spec := object.get(pipeline, "spec", {})
	_tasks := array.concat(
		object.get(spec, "tasks", []),
		object.get(spec, "finally", []),
	)
}

# tasks_names returns the set of task names extracted from the
# given object. It expands names to include the parameterized
# form, see task_names.
tasks_names(obj) := names if {
	names := {name |
		some task in tasks(obj)
		some name in task_names(task)
	}
}

# task_names returns the different names of the task. Additional
# names are produced for each parameter given to the task. For
# example, {"my-task", "my-task[spam=maps]" is produced for a
# task named "my-task" which takes the parameter "spam" with
# value "maps".
task_names(task) := names if {
	raw_name := refs.task_ref(task).name
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

# task_param returns the value of the given parameter in the task.
task_param(task, name) := value if {
	value := _task_params(task)[name]
}

# task_result returns the value of the given result in the task.
task_result(task, name) := value if {
	some result in task.results
	result_name := _key_value(result, "name")
	result_name == name
	value := _key_value(result, "value")
}

# build_task returns the build task found in the attestation
build_task(attestation) := task if {
	some task in tasks(attestation)

	image_url := task_result(task, "IMAGE_URL")
	count(trim_space(image_url)) > 0

	image_digest := task_result(task, "IMAGE_DIGEST")
	count(trim_space(image_digest)) > 0
}

# task_data returns the data relating to the task. If the task is
# referenced from a bundle, the "bundle" attribute is included.
task_data(task) = info if {
	r := refs.task_ref(task)
	info := {"name": r.name, "bundle": r.bundle}
} else := info if {
	info := {"name": task.name}
}

_key_value(obj, name) := value if {
	some key, value in obj
	key == name
}
