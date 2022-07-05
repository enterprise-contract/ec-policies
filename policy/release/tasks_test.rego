package policy.release.tasks

import data.lib

test_no_tasks_present {
	expected := {{
		"code": "tasks_missing",
		"msg": "No tasks found in PipelineRun attestation",
		"effective_on": "2022-01-01T00:00:00Z",
	}}

	lib.assert_equal(deny, expected) with input.attestations as [{"predicate": {
		"buildType": lib.pipelinerun_att_build_type,
		"buildConfig": {"tasks": []},
	}}]
}

test_empty_task_attested {
	expected := missing_tasks_error(all_required_tasks)

	lib.assert_equal(deny, expected) with input.attestations as [{"predicate": {
		"buildType": lib.pipelinerun_att_build_type,
		"buildConfig": {"tasks": [{}]},
	}}]
}

test_all_required_tasks_not_present {
	expected := missing_tasks_error(all_required_tasks)

	lib.assert_equal(deny, expected) with input.attestations as [{"predicate": {
		"buildType": lib.pipelinerun_att_build_type,
		"buildConfig": {"tasks": [{"ref": {"name": "custom", "kind": "Task"}}]},
	}}]
}

test_all_but_one_required_task_not_present {
	expected := missing_tasks_error(all_required_tasks - {"sanity-inspect-image"})

	lib.assert_equal(deny, expected) with input.attestations as [{"predicate": {
		"buildType": lib.pipelinerun_att_build_type,
		"buildConfig": {"tasks": [{"ref": {"name": "sanity-inspect-image", "kind": "Task"}}]},
	}}]
}

test_several_tasks_not_present {
	expected := missing_tasks_error(all_required_tasks - {"sanity-inspect-image", "clamav-scan", "add-sbom-and-push"})

	lib.assert_equal(deny, expected) with input.attestations as [{"predicate": {
		"buildType": lib.pipelinerun_att_build_type,
		"buildConfig": {"tasks": [
			{"ref": {"name": "sanity-inspect-image", "kind": "Task"}},
			{"ref": {"name": "clamav-scan", "kind": "Task"}},
			{"ref": {"name": "add-sbom-and-push", "kind": "Task"}},
		]},
	}}]
}

test_tricks {
	expected := missing_tasks_error(all_required_tasks)

	lib.assert_equal(deny, expected) with input.attestations as [{"predicate": {
		"buildType": lib.pipelinerun_att_build_type,
		"buildConfig": {"tasks": [
			{"name": "sanity-inspect-image"},
			{"ref": {"name": "sanity-inspect-image", "kind": "NotTask"}},
		]},
	}}]
}

missing_tasks_error(missing) = error {
	error := {{
		"code": "tasks_required",
		"msg": sprintf("Required task(s) '%s' not found in the PipelineRun attestation", [concat("', '", missing)]),
		"effective_on": "2022-01-01T00:00:00Z",
	}}
}
