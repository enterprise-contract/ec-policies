package policies.release.attestation_task_bundle

import data.lib

mock_data(task) = d {
	d := [{"predicate": {
		"buildConfig": {"tasks": [task]},
		"buildType": lib.pipelinerun_att_build_type,
	}}]
}

test_bundle_not_exists {
	name := "my-task"
	d := mock_data({
		"name": name,
		"ref": {"name": "good-task"},
	})

	expected_msg := "Task 'my-task' does not contain a bundle reference"
	lib.assert_equal(warn, {{
		"code": "disallowed_task_reference",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as d
}

test_bundle_not_exists_emtpy_string {
	name := "my-task"
	image := ""
	d := mock_data({
		"name": name,
		"ref": {"name": "good-task", "bundle": image},
	})

	expected_msg := sprintf("Task '%s' has disallowed bundle image '%s'", [name, image])
	lib.assert_equal(warn, {{
		"code": "disallowed_task_bundle",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as d
}

test_bundle_reference_not_valid {
	name := "my-task"
	image := "hacker.io/bundle:evil"
	prefix = split(image, ":")
	d := mock_data({
		"name": name,
		"ref": {
			"name": "good-task",
			"bundle": image,
		},
	})

	expected_msg := sprintf("Task '%s' has disallowed bundle image '%s'", [name, prefix[0]])
	lib.assert_equal(warn, {{
		"code": "disallowed_task_bundle",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as d
}

test_bundle_reference_valid {
	name := "my-task"
	image := "quay.io/redhat-appstudio/hacbs-templates-bundle:latest"
	d := mock_data({
		"name": name,
		"ref": {
			"name": "good-task",
			"bundle": image,
		},
	})

	lib.assert_empty(warn) with input.attestations as d
}
