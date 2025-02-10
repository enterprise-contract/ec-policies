package lib

import rego.v1

import data.lib.tekton

slsa_provenance_predicate_type_v1 := "https://slsa.dev/provenance/v1"

slsa_provenance_predicate_type_v02 := "https://slsa.dev/provenance/v0.2"

tekton_pipeline_run := "tekton.dev/v1beta1/PipelineRun"

pipelinerun_att_build_types := {
	tekton_pipeline_run,
	# Legacy build type
	"https://tekton.dev/attestations/chains/pipelinerun@v2",
}

tekton_slsav1_pipeline_run := "https://tekton.dev/chains/v2/slsa-tekton"

slsav1_pipelinerun_att_build_types := {
	"https://tekton.dev/chains/v2/slsa",
	tekton_slsav1_pipeline_run,
}

tekton_task_run := "tekton.dev/v1beta1/TaskRun"

taskrun_att_build_types := {
	tekton_task_run,
	# Legacy build type
	"https://tekton.dev/attestations/chains@v2",
}

# (We can't call this test_task_result_name since anything prefixed
# with test_ is treated as though it was a test.)
task_test_result_name := "TEST_OUTPUT"

task_test_image_result_name := "IMAGES_PROCESSED"

slsa_provenance_attestations := [att |
	some att in input.attestations
	att.statement.predicateType in {slsa_provenance_predicate_type_v1, slsa_provenance_predicate_type_v02}
]

# These are the ones we're interested in
pipelinerun_attestations := att if {
	v1_0 := [a |
		some a in pipelinerun_slsa_provenance_v1
	]
	v0_2 := [a |
		some a in pipelinerun_slsa_provenance02
	]

	att := array.concat(v1_0, v0_2)
}

pipelinerun_slsa_provenance02 := [att |
	some att in input.attestations
	att.statement.predicate.buildType in pipelinerun_att_build_types
]

# TODO: Make this work with pipelinerun_attestations above so policy rules can be
# written for either.
pipelinerun_slsa_provenance_v1 := [att |
	some att in input.attestations
	att.statement.predicateType == slsa_provenance_predicate_type_v1

	att.statement.predicate.buildDefinition.buildType in slsav1_pipelinerun_att_build_types

	# TODO: Workaround to distinguish between taskrun and pipelinerun attestations
	spec_keys := object.keys(att.statement.predicate.buildDefinition.externalParameters.runSpec)

	pipeline_keys := {"pipelineRef", "pipelineSpec"}

	count(pipeline_keys - spec_keys) != count(pipeline_keys)
]

# These ones we don't care about any more
taskrun_attestations := [att |
	some att in input.attestations

	att.statement.predicate.buildType in taskrun_att_build_types
]

tasks_from_pipelinerun := [task |
	some att in pipelinerun_attestations
	some task in tekton.tasks(att)
]

# slsa v0.2 results
task_results(task) := task.results

# slsa v1.0 results
task_results(task) := task.status.taskResults

# All results from the attested PipelineRun with the provided name. Results are
# expected to contain a JSON value. The return object contains the following
# keys:
#   name: name of the task in which the result appears.
#   name: Tekton bundle image reference for the corresponding task.
#   value: unmarshalled task result.
results_named(name) := [r |
	some task in tasks_from_pipelinerun
	some result in task_results(task)
	result.name == name
	result_map := unmarshal(result.value)

	# Inject the task data, currently task name and task bundle image
	# reference so we can show it in failure messages
	r := object.union({"value": result_map}, tekton.task_data(task))
]

# Attempts to json.unmarshal the given value. If not possible, the given
# value is returned as is. This is helpful when interpreting certain values
# in attestations created by Tekton Chains.
unmarshal(raw) := value if {
	json.is_valid(raw)
	value := json.unmarshal(raw)
} else := raw

# (Don't call it test_results since test_ means a unit test)
# First find results using the new task result name
results_from_tests := results_named(task_test_result_name)

images_processed_results_from_tests := results_named(task_test_image_result_name)

# Check for a task by name. Return the task if found
task_in_pipelinerun(name) := task if {
	some task in tasks_from_pipelinerun
	task.name == name
	task
}

# Check for a task result by name
result_in_task(task_name, result_name) if {
	task := task_in_pipelinerun(task_name)
	some task_result in task.results
	task_result.name == result_name
}

# Check for a Succeeded status from a task
task_succeeded(name) if {
	task := task_in_pipelinerun(name)
	task.status == "Succeeded"
}

# param_values expands the value into a list of values as needed. This is useful when handling
# parameters that could be of type string or an array of strings.
param_values(value) := {value} if {
	is_string(value)
} else := values if {
	is_array(value)
	values := {v | some v in value}
} else := values if {
	is_object(value)
	values := {v | some v in value}
}

# result_values expands the value of the given result into a list of values. This is useful when
# handling results that could be of type string, array of strings, or an object.
result_values(result) := value if {
	result.type == "string"
	value := {result.value}
} else := value if {
	result.type == "array"
	value := {v | some v in result.value}
} else := value if {
	result.type == "object"
	value := {v | some v in result.value}
}
