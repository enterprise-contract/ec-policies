package lib

import data.lib

pr_build_type := "tekton.dev/v1beta1/PipelineRun"

pr_build_type_legacy := "https://tekton.dev/attestations/chains/pipelinerun@v2"

tr_build_type := "tekton.dev/v1beta1/TaskRun"

tr_build_type_legacy := "https://tekton.dev/attestations/chains@v2"

mock_pr_att := {"predicate": {"buildType": pr_build_type}}

mock_pr_att_legacy := {"predicate": {"buildType": pr_build_type_legacy}}

mock_tr_att := {"predicate": {"buildType": tr_build_type}}

mock_tr_att_legacy := {"predicate": {"buildType": tr_build_type_legacy}}

garbage_att := {"predicate": {"buildType": "garbage"}}

# Used also in main_test and test_test
att_mock_helper(name, result_map, task_name) = d {
	d := {"predicate": {
		"buildType": pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [{"name": task_name, "results": [{
			"name": name,
			"value": json.marshal(result_map),
		}]}]},
	}}
}

att_mock_task_helper(task) = d {
	d := [{"predicate": {
		"buildConfig": {"tasks": [task]},
		"buildType": pipelinerun_att_build_types[0],
	}}]
}

att_mock_materials(uri, sha1) = d {
	d := [{"predicate": {
		"buildType": pipelinerun_att_build_types[0],
		"materials": [{
			"uri": uri,
			"digest": {"sha1": sha1},
		}],
	}}]
}

test_pr_attestations {
	assert_equal([mock_pr_att, mock_pr_att_legacy], pipelinerun_attestations) with input.attestations as [
		mock_tr_att,
		mock_tr_att_legacy,
		mock_pr_att,
		mock_pr_att_legacy,
		garbage_att,
	]

	assert_equal([], pipelinerun_attestations) with input.attestations as [
		mock_tr_att,
		mock_tr_att_legacy,
		garbage_att,
	]
}

test_tr_attestations {
	assert_equal([mock_tr_att], taskrun_attestations) with input.attestations as [
		mock_tr_att,
		mock_pr_att,
		garbage_att,
	]

	assert_equal([], taskrun_attestations) with input.attestations as [mock_pr_att, garbage_att]
}

test_att_mock_helper {
	expected := {"predicate": {
		"buildType": pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [{"name": "mytask", "results": [{
			"name": "result-name",
			"value": "{\"foo\":\"bar\"}",
		}]}]},
	}}

	assert_equal(expected, lib.att_mock_helper("result-name", {"foo": "bar"}, "mytask"))
}

test_results_from_tests {
	expected := {"result": "SUCCESS", "foo": "bar", lib.task_name: "mytask"}
	assert_equal([expected], results_from_tests) with input.attestations as [att_mock_helper(lib.hacbs_test_task_result_name, {"result": "SUCCESS", "foo": "bar"}, "mytask")]
}

test_task_in_pipelinerun {
	task_name := "my-task"
	d := att_mock_task_helper({"name": task_name})

	assert_equal({"name": task_name}, task_in_pipelinerun(task_name)) with input.attestations as d
}

test_task_not_in_pipelinerun {
	task_name := "bad-task"
	d := att_mock_task_helper({"name": "my-task"})

	not task_in_pipelinerun(task_name) with input.attestations as d
}

test_result_in_task {
	task_name := "my-task"
	result_name := "IMAGE"
	d := att_mock_task_helper({
		"name": task_name,
		"results": [{
			"name": result_name,
			"value": "result value",
		}],
	})

	result_in_task(task_name, result_name) with input.attestations as d
}

test_result_not_in_task {
	task_name := "my-task"
	result_name := "BAD-RESULT"
	d := att_mock_task_helper({
		"name": task_name,
		"results": [{
			"name": "result name",
			"value": "result value",
		}],
	})

	not result_in_task(task_name, result_name) with input.attestations as d
}

test_task_succeeded {
	task_name := "my-task"
	d := att_mock_task_helper({
		"name": task_name,
		"status": "Succeeded",
	})

	task_succeeded(task_name) with input.attestations as d
}

test_task_not_succeeded {
	task_name := "my-task"
	d := att_mock_task_helper({
		"name": task_name,
		"status": "Failed",
	})

	not task_succeeded(task_name) with input.attestations as d
}
