package lib

import data.lib

pr_build_type := "https://tekton.dev/attestations/chains/pipelinerun@v2"

tr_build_type := "https://tekton.dev/attestations/chains@v2"

mock_pr_att := {"predicate": {"buildType": pr_build_type}}

mock_tr_att := {"predicate": {"buildType": tr_build_type}}

garbage_att := {"predicate": {"buildType": "garbage"}}

# Used also in main_test and test_test
att_mock_helper(result_map, task_name) = d {
	d := {"predicate": {
		"buildType": pipelinerun_att_build_type,
		"buildConfig": {"tasks": [{"name": task_name, "results": [{
			"name": hacbs_test_task_result_name,
			"value": json.marshal(result_map),
		}]}]},
	}}
}

test_pr_attestations {
	assert_equal([mock_pr_att], pipelinerun_attestations) with input.attestations as [mock_tr_att, mock_pr_att, garbage_att]
	assert_equal([], pipelinerun_attestations) with input.attestations as [mock_tr_att, garbage_att]
}

test_tr_attestations {
	assert_equal([mock_tr_att], taskrun_attestations) with input.attestations as [mock_tr_att, mock_pr_att, garbage_att]
	assert_equal([], taskrun_attestations) with input.attestations as [mock_pr_att, garbage_att]
}

test_att_mock_helper {
	expected := {"predicate": {
		"buildType": pipelinerun_att_build_type,
		"buildConfig": {"tasks": [{"name": "mytask", "results": [{
			"name": hacbs_test_task_result_name,
			"value": "{\"foo\":\"bar\"}",
		}]}]},
	}}

	assert_equal(expected, lib.att_mock_helper({"foo": "bar"}, "mytask"))
}

test_results_from_tests {
	expected := {"result": "SUCCESS", "foo": "bar", "__task_name": "mytask"}
	assert_equal([expected], results_from_tests) with input.attestations as [att_mock_helper({"result": "SUCCESS", "foo": "bar"}, "mytask")]
}
