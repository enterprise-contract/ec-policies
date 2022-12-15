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

# trusted_tasks returns the tasks found in the given obj
# that use an acceptable Tekton bundle.
trusted_tasks(obj) := result if {
	result := {task |
		some task in tasks(obj)
		task_ref := refs.task_ref(task)
		task_ref.kind == "task"
		bundle_ref := task_ref.bundle
		bundles.is_acceptable(bundle_ref)
	}
}

# trusted_tasks_names returns the set of task names that use an
# acceptable Tekton bundle. It expands names to include the
# parameterized form, see task_names.
trusted_tasks_names(obj) := names if {
	names := {name |
		some task in trusted_tasks(obj)
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

# trusted_build_task returns the build task found in the attestation
# that uses an acceptable Tekton bundle.
trusted_build_task(attestation) := task if {
	some task in trusted_tasks(attestation)

	bundle := task_data(task).bundle
	bundles.is_acceptable(bundle)

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
