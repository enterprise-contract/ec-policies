package policies.source_image_task

import data.lib

mock_data(task) = d {
	d := [{"predicate": {
		"buildConfig": {"tasks": [task]},
		"buildType": lib.pipelinerun_att_build_type,
	}}]
}

task_name := "source-image-verify"

input_image := "my-image:1234"

task_data := {
	"input_image": input_image,
	"task_name": task_name,
}

test_invalid_image_param {
	d := mock_data({
		"name": task_name,
		"params": {
			"name": "IMAGE",
			"value": "bad-image:latest",
		},
		"ref": {"name": "good-task"},
	})

	expected_msg := sprintf("Task '%s' does not contain '%s' as a param", [task_name, input_image])
	lib.assert_equal(warn, {{"code": "disallowed_input_image", "msg": expected_msg}}) with input.attestations as d with data.source_image_verify as task_data
}

test_valid_image_param {
	d := mock_data({
		"name": task_name,
		"params": {
			"name": "IMAGE",
			"value": "my-image:1234",
		},
		"ref": {"name": "good-task"},
	})

	expected_msg := sprintf("Task '%s' does not contain '%s' as a param", [task_name, input_image])
	not lib.assert_equal(warn, {{"code": "disallowed_input_image", "msg": expected_msg}}) with input.attestations as d with data.source_image_verify as task_data
}
