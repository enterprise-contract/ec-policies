package lib

import future.keywords.in

import data.lib.tkn

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

java_sbom_component_count_result_name := "SBOM_JAVA_COMPONENTS_COUNT"

build_base_images_digests_result_name := "BASE_IMAGES_DIGESTS"

# These are the ones we're interested in
pipelinerun_attestations := [statement |
	some att in input.attestations
	statement := _statement(att)
	statement.predicate.buildType in pipelinerun_att_build_types
]

# TODO: Make this work with pipelinerun_attestations above so policy rules can be
# written for either.
pipelinerun_slsa_provenance_v1 := [statement |
	some att in input.attestations
	statement := _statement(att)
	statement.predicateType == "https://slsa.dev/provenance/v1"

	statement.predicate.buildDefinition.buildType in slsav1_pipelinerun_att_build_types

	# TODO: Workaround to distinguish between taskrun and pipelinerun attestations
	spec_keys := object.keys(statement.predicate.buildDefinition.externalParameters.runSpec)
	pipeline_keys := {"pipelineRef", "pipelineSpec"}
	count(pipeline_keys - spec_keys) != count(pipeline_keys)
]

# These ones we don't care about any more
taskrun_attestations := [statement |
	some att in input.attestations
	statement := _statement(att)

	statement.predicate.buildType in taskrun_att_build_types
]

_statement(att) := statement {
	statement := att.statement
} else = att

tasks_from_pipelinerun := [task |
	some att in pipelinerun_attestations
	some task in att.predicate.buildConfig.tasks
]

# All results from the attested PipelineRun with the provided name. Results are
# expected to contain a JSON value. The return object contains the following
# keys:
#   name: name of the task in which the result appears.
#   name: Tekton bundle image reference for the corresponding task.
#   value: unmarshalled task result.
results_named(name) := [r |
	some task in tasks_from_pipelinerun
	some result in task.results
	result.name == name
	result_map := unmarshal(result.value)

	# Inject the task data, currently task name and task bundle image
	# reference so we can show it in failure messages
	r := object.union({"value": result_map}, tkn.task_data(task))
]

# Attempts to json.unmarshal the given value. If not possible, the given
# value is returned as is. This is helpful when interpreting certain values
# in attestations created by Tekton Chains.
unmarshal(raw) := value {
	json.is_valid(raw)
	value := json.unmarshal(raw)
} else = raw

# (Don't call it test_results since test_ means a unit test)
# First find results using the new task result name
results_from_tests := results_named(task_test_result_name)

# Check for a task by name. Return the task if found
task_in_pipelinerun(name) := task {
	some task in tasks_from_pipelinerun
	task.name == name
	task
}

# Check for a task result by name
result_in_task(task_name, result_name) {
	task := task_in_pipelinerun(task_name)
	some task_result in task.results
	task_result.name == result_name
}

# Check for a Succeeded status from a task
task_succeeded(name) {
	task := task_in_pipelinerun(name)
	task.status == "Succeeded"
}
