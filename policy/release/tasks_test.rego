package policy.release.tasks

import data.lib
import data.lib.bundles

test_no_tasks_present {
	expected := {{
		"code": "tasks_missing",
		"msg": "No tasks found in PipelineRun attestation",
		"effective_on": "2022-01-01T00:00:00Z",
	}}

	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": []},
		}}]
}

test_empty_task_attested {
	expected := missing_tasks_error(all_required_tasks)

	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": [{}]},
		}}]
}

test_all_required_tasks_not_present {
	expected := missing_tasks_error(all_required_tasks)

	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": [{"ref": {"name": "custom", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}}]},
		}}]
}

test_all_but_one_required_task_not_present {
	expected := missing_tasks_error(all_required_tasks - {"sanity-inspect-image"})

	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": [{"ref": {"name": "sanity-inspect-image", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}}]},
		}}]
}

test_several_tasks_not_present {
	expected := missing_tasks_error(all_required_tasks - {"sanity-inspect-image", "clamav-scan", "add-sbom-and-push"})

	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": [
				{"ref": {"name": "sanity-inspect-image", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}},
				{"ref": {"name": "clamav-scan", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}},
				{"ref": {"name": "add-sbom-and-push", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}},
			]},
		}}]
}

test_tricks {
	expected := missing_tasks_error(all_required_tasks)

	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": [
				{"name": "sanity-inspect-image"},
				{"ref": {"name": "sanity-inspect-image", "kind": "NotTask", "bundle": bundles.acceptable_bundle_ref}},
			]},
		}}]
}

test_task_present_from_unacceptable_bundle {
	names := all_required_tasks - {"sanity-inspect-image"}

	task_from_unacceptable := [{"ref": {"name": "sanity-inspect-image", "kind": "Task", "bundle": "registry.img/unacceptable@sha256:digest"}}]

	tasks := array.concat(
		[t |
			name := names[_]
			t := {"ref": {"name": name, "kind": "Task", "bundle": bundles.acceptable_bundle_ref}}
		],
		task_from_unacceptable,
	)

	attestations := [{"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": tasks},
	}}]

	expected := missing_tasks_error({"sanity-inspect-image"})
	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as attestations
}

missing_tasks_error(missing) = error {
	error := {{
		"code": "tasks_required",
		"msg": sprintf("Required task(s) '%s' not found in the PipelineRun attestation", [concat("', '", missing)]),
		"effective_on": "2022-01-01T00:00:00Z",
	}}
}
