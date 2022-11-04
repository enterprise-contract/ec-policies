package policy.release.tasks

import data.lib
import data.lib.bundles

test_all_tasks_present {
	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": [
				{"ref": {"name": "sanity-inspect-image", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}},
				{"ref": {"name": "clamav-scan", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}},
				{"ref": {"name": "add-sbom-and-push", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}},
				{"ref": {"name": "get-clair-scan", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}},
				{"ref": {"name": "deprecated-image-check", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}},
				{
					"ref": {"name": "sanity-label-check", "kind": "Task", "bundle": bundles.acceptable_bundle_ref},
					"invocation": {"parameters": {"POLICY_NAMESPACE": "required_checks"}},
				},
				{
					"ref": {"name": "sanity-label-check", "kind": "Task", "bundle": bundles.acceptable_bundle_ref},
					"invocation": {"parameters": {"POLICY_NAMESPACE": "optional_checks"}},
				},
				{"ref": {"name": "sbom-json-check", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}},
			]},
		}}]
}

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
	expected := _missing_tasks_error(all_required_tasks)

	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": [{}]},
		}}]
}

test_all_required_tasks_not_present {
	expected := _missing_tasks_error(all_required_tasks)

	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": [{"ref": {"name": "custom", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}}]},
		}}]
}

test_all_but_one_required_task_not_present {
	expected := _missing_tasks_error(all_required_tasks - {"sanity-inspect-image"})

	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": [{"ref": {"name": "sanity-inspect-image", "kind": "Task", "bundle": bundles.acceptable_bundle_ref}}]},
		}}]
}

test_several_tasks_not_present {
	expected := _missing_tasks_error(all_required_tasks - {"sanity-inspect-image", "clamav-scan", "add-sbom-and-push"})

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
	expected := _missing_tasks_error(all_required_tasks)

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
	task_from_unacceptable := [{"ref": {"name": "sanity-inspect-image", "kind": "Task", "bundle": "registry.img/unacceptable@sha256:digest"}}]

	attestations := _attestations_with_tasks(all_required_tasks - {"sanity-inspect-image"}, task_from_unacceptable)

	expected := _missing_tasks_error({"sanity-inspect-image"})
	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as attestations
}

test_parameterized {
	with_wrong_parameter := [
		{
			"ref": {
				"name": "sanity-label-check",
				"kind": "Task",
				"bundle": bundles.acceptable_bundle_ref,
			},
			"invocation": {"parameters": {"POLICY_NAMESPACE": "something-else"}},
		},
		{
			"ref": {
				"name": "sanity-label-check",
				"kind": "Task",
				"bundle": bundles.acceptable_bundle_ref,
			},
			"invocation": {"parameters": {"POLICY_NAMESPACE": "optional_checks"}},
		},
	]

	attestations := _attestations_with_tasks(all_required_tasks - {"sanity-label-check[POLICY_NAMESPACE=required_checks]", "sanity-label-check[POLICY_NAMESPACE=optional_checks]"}, with_wrong_parameter)

	expected := _missing_tasks_error({"sanity-label-check[POLICY_NAMESPACE=required_checks]"})
	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as attestations
}

_attestations_with_tasks(names, add_tasks) = attestations {
	tasks := array.concat([t | t := _task(names[_])], add_tasks)

	attestations := [{"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": tasks},
	}}]
}

_task(name) = task {
	parts := regex.split("[\\[\\]=]", name)
	parts[1]
	task_name := parts[0]

	task := {"ref": {"name": task_name, "kind": "Task", "bundle": bundles.acceptable_bundle_ref}, "invocation": {"parameters": {parts[1]: parts[2]}}}
}

_task(name) = task {
	parts := regex.split("[\\[\\]=]", name)
	not parts[1]
	task := {"ref": {"name": name, "kind": "Task", "bundle": bundles.acceptable_bundle_ref}}
}

_missing_tasks_error(missing) = error {
	error := {{
		"code": "tasks_required",
		"msg": sprintf("Required task(s) '%s' not found in the PipelineRun attestation", [concat("', '", missing)]),
		"effective_on": "2022-01-01T00:00:00Z",
	}}
}
