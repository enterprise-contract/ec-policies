package lib.tkn

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib.refs
import data.lib.time as ectime

import data.slsa.tekton as slsa_tekton

default missing_required_tasks_data := false

missing_required_tasks_data if {
	count(data["required-tasks"]) == 0
}

# The latest set of required tasks. Tasks here are not required right now
# but will be required in the future.
latest_required_default_tasks contains task if {
	some task in ectime.newest(data["required-tasks"]).tasks
}

# The set of required tasks that are required right now.
current_required_default_tasks contains task if {
	some task in ectime.most_current(data["required-tasks"]).tasks
}

# tasks returns the set of tasks found in the object.
tasks(obj) := {task |
	some task in _maybe_tasks(obj)
	_slsa_task(task)
}

# task from a slsav0.2 attestation
_slsa_task(task) if {
	task_ref := refs.task_ref(task)
	task_ref.kind == "task"
}

# Handle tasks from a Pipeline definition.
_maybe_tasks(pipeline) := _tasks if {
	pipeline.spec
	spec := object.get(pipeline, "spec", {})
	_tasks := array.concat(
		object.get(spec, "tasks", []),
		object.get(spec, "finally", []),
	)
}

# Handle tasks from a slsa attestation, either format
# Will return an empty list if it can't find the tasks for some reason
_maybe_tasks(att) := slsa_tekton.tasks(att.statement.predicate)

# tasks_names returns the set of task names extracted from the
# given object. It expands names to include the parameterized
# form, see task_names.
tasks_names(obj) := {name |
	some task in tasks(obj)
	some name in task_names(task)
}

# task_names returns the different names of the task. Additional
# names are produced for each parameter given to the task. For
# example, {"my-task", "my-task[spam=maps]" is produced for a
# task named "my-task" which takes the parameter "spam" with
# value "maps".
task_names(task) := names if {
	raw_name := task_name(task)
	name := split(raw_name, "[")[0] # don't allow smuggling task name with parameters
	params := {n |
		some k, v in _task_params(task)
		n := sprintf("%s[%s=%s]", [name, k, v])
	}
	names := {name} | params
}

# task name from a v0.2 and v1.0 attestation
task_name(task) := refs.task_ref(task).name

_task_params(task) := task.params

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
task_param(task, name) := _task_params(task)[name]

# slsa attestation results, both formats
_task_results(task) := task.results

# task_result returns the value of the given result in the task.
task_result(task, name) := value if {
	some result in _task_results(task)
	result_name := _key_value(result, "name")
	result_name == name
	value := _key_value(result, "value")
}

task_steps(task) := task.steps

# slsa v0.2 step image
task_step_image_ref(step) := step.environment.image

# slsa v1.0 step image
task_step_image_ref(step) := step.imageID

# build_task returns the build task found in the attestation
build_task(attestation) := task if {
	some task in tasks(attestation)

	image_url := task_result(task, "IMAGE_URL")
	count(trim_space(image_url)) > 0

	image_digest := task_result(task, "IMAGE_DIGEST")
	count(trim_space(image_digest)) > 0
}

git_clone_task(attestation) := task if {
	some task in tasks(attestation)

	commit := task_result(task, "commit")
	count(trim_space(commit)) > 0

	url := task_result(task, "url")
	count(trim_space(url)) > 0
}

# task_data returns the data relating to the task. If the task is
# referenced from a bundle, the "bundle" attribute is included.
task_data(task) := info if {
	r := refs.task_ref(task)
	info := {"name": r.name, "bundle": r.bundle}
} else := info if {
	info := {"name": task_name(task)}
}

_key_value(obj, name) := value if {
	some key, value in obj
	key == name
}

# task_labels returns the key/value pair of task labels
task_labels := input.metadata.labels
