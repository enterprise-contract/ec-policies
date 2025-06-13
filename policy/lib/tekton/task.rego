package lib.tekton

import rego.v1

import data.lib.arrays
import data.lib.time as ectime

default missing_required_tasks_data := false

missing_required_tasks_data if {
	count(data["required-tasks"]) == 0
}

# The latest set of required tasks. Tasks here are not required right now
# but will be required in the future.
latest_required_default_tasks := ectime.newest(data["required-tasks"])

# The set of required tasks that are required right now.
current_required_default_tasks := ectime.most_current(data["required-tasks"])

# tasks returns the set of tasks found in the object.
tasks(obj) := {task |
	some task in _maybe_tasks(obj)
	_slsa_task(task)
}

# task from a slsav0.2 attestation
_slsa_task(task) if {
	ref := task_ref(task)
	ref.kind == "task"
}

# _maybe_tasks returns a set of potential tasks.
# Handle tasks from a PipelineRun attestation.
_maybe_tasks(given) := given.statement.predicate.buildConfig.tasks

# Handle tasks from a Pipeline definition.
_maybe_tasks(given) := _tasks if {
	given.spec
	spec := object.get(given, "spec", {})
	_tasks := array.concat(
		object.get(spec, "tasks", []),
		object.get(spec, "finally", []),
	)
}

# handle tasks from a slsav1 attestation
_maybe_tasks(given) := _tasks if {
	deps := given.statement.predicate.buildDefinition.resolvedDependencies
	_tasks := {json.unmarshal(base64.decode(dep.content)) |
		some dep in deps
		_slsav1_tekton(dep)
	}
}

# check if a resolvedDependency is a pipeline task
_slsav1_tekton(dep) if {
	dep.name == "pipelineTask"
	dep.content
}

# check if a resolvedDependency is a standalone task
_slsav1_tekton(dep) if {
	dep.name == "task"
	dep.content
}

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
		some k, v in task_params(task)
		n := sprintf("%s[%s=%s]", [name, k, v])
	}
	names := {name} | params
}

# task name from a v0.2 and v1.0 attestation
task_name(task) := task_ref(task).name

# returns a slsav0.2 pipeline task name
# the name field (which is the taskRun name) for slsav1.0 is metadata.name
# so this only passes for slsav0.2
pipeline_task_name(task) := task.name

# returns a slsav1.0 pipeline task name
pipeline_task_name(task) := value if {
	not task.name
	some label, value in task.metadata.labels
	label == "tekton.dev/pipelineTask"
}

# task_params returns an object where keys are parameter names
# and values are parameter values.
# Handle parameters of a task from a PipelineRun attestation.
task_params(task) := task.invocation.parameters

# Handle parameters of a task in a Pipeline definition.
task_params(task) := params if {
	task.params
	params := {name: value |
		some param in task.params
		name := _key_value(param, "name")
		value := _key_value(param, "value")
	}
}

# handle params from a slsav1.0 attestation
task_params(task) := params if {
	task.spec.params
	params := {name: value |
		some param in task.spec.params
		name := _key_value(param, "name")
		value := _key_value(param, "value")
	}
}

# task_param returns the value of the given parameter in the task.
task_param(task, name) := task_params(task)[name]

# slsa v0.2 results
task_results(task) := task.results

# slsa v1.0 results
task_results(task) := task.status.taskResults

# task_result returns the value of the given result in the task.
task_result(task, name) := value if {
	some result in task_results(task)
	result_name := _key_value(result, "name")
	result_name == name
	value := _key_value(result, "value")
}

task_result_endswith(task, suffix) := values if {
	results := arrays.sort_by("name", [result |
		some result in task_results(task)
		result_name := _key_value(result, "name")
		endswith(result_name, suffix)
	])
	values := [result.value | some result in results]
}

# slsa v0.2 step image
task_step_image_ref(step) := step.environment.image

# slsa v1.0 step image
task_step_image_ref(step) := step.imageID

# build_task returns the build task found in the attestation
build_tasks(attestation) := [task |
	some task in tasks(attestation)

	image_url := task_result_artifact_url(task)
	count(image_url) > 0

	image_digest := task_result_artifact_digest(task)
	count(image_digest) > 0
]

pre_build_tasks(attestation) := [task |
	some task in tasks(attestation)
	some pre_build_task_name in _pre_build_task_names
	task_name(task) == pre_build_task_name
]

_pre_build_task_names := ["run-script-oci-ta"]

# return the tasks that have "TEST_OUTPUT" as a result
tasks_output_result(attestation) := [task |
	some task in tasks(attestation)
	test_output := task_result(task, "TEST_OUTPUT")
	count(test_output) > 0
]

git_clone_tasks(attestation) := [task |
	some task in tasks(attestation)

	commit := task_result(task, "commit")
	count(trim_space(commit)) > 0

	url := task_result(task, "url")
	count(trim_space(url)) > 0
]

source_build_tasks(attestation) := [task |
	some task in tasks(attestation)

	url := trim_space(task_result(task, "SOURCE_IMAGE_URL"))
	count(url) > 0

	digest := trim_space(task_result(task, "SOURCE_IMAGE_DIGEST"))
	count(digest) > 0
]

# task_data returns the data relating to the task. If the task is
# referenced from a bundle, the "bundle" attribute is included.
task_data(task) := info if {
	r := task_ref(task)
	info := {"name": r.name, "bundle": r.bundle}
} else := info if {
	info := {"name": task_name(task)}
}

_key_value(obj, name) := value if {
	some key, value in obj
	key == name
}

# task_labels returns the key/value pair of task labels
task_labels(task) := labels if {
	# Task was the input, provided either as input to the task rules or SLSA v1
	# tasks from resolvedDependencies.content decoded and unmarshalled by
	# _maybe_tasks
	labels := task.metadata.labels
} else := labels if {
	# SLSA 0.2
	labels := task.invocation.environment.labels
}

# task_annotations returns the key/value pair of task annotations
task_annotations(task) := annotations if {
	# Task was the input, provided either as input to the task rules or SLSA v1
	# tasks from resolvedDependencies.content decoded and unmarshalled by
	# _maybe_tasks
	annotations := task.metadata.annotations
} else := annotations if {
	# SLSA 0.2
	annotations := task.invocation.environment.annotations
}
