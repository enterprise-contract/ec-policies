package lib

pipelinerun_att_build_type := "https://tekton.dev/attestations/chains/pipelinerun@v2"

taskrun_att_build_type := "https://tekton.dev/attestations/chains@v2"

# These are the ones we're interested in
pipelinerun_attestations := [att |
	att := input.attestations[_]
	att.predicate.buildType == pipelinerun_att_build_type
]

# These ones we don't care about any more
taskrun_attestations := [att |
	att := input.attestations[_]
	att.predicate.buildType == taskrun_att_build_type
]

tasks_from_pipelinerun := [task |
	att := pipelinerun_attestations[_]
	task := att.predicate.buildConfig.tasks[_]
]

hacbs_test_task_result_name := "HACBS_TEST_OUTPUT"

# (Don't call it test_results since test_ means a unit test)
results_from_tests := [r |
	task := tasks_from_pipelinerun[_]
	result := task.results[_]
	result.name == hacbs_test_task_result_name
	result_map := json.unmarshal(result.value)

	# Inject the task name so we can show it in failure messages
	r := object.union(result_map, {"__task_name": task.name})
]
