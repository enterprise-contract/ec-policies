package policy.release.tasks

import data.lib
import data.lib.bundles

import future.keywords.contains
import future.keywords.if
import future.keywords.in

test_required_tasks_met if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(deny) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data
}

test_required_tasks_not_met if {
	missing_tasks := {"buildah"}
	attestations := _attestations_with_tasks(_expected_required_tasks - missing_tasks, [])

	expected := _missing_tasks_violation(missing_tasks)
	lib.assert_equal(expected, deny) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data
}

test_future_required_tasks_met if {
	attestations := _attestations_with_tasks(_expected_future_required_tasks, [])
	lib.assert_empty(warn) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data
}

test_future_required_tasks_not_met if {
	missing_tasks := {"conftest-clair"}
	attestations := _attestations_with_tasks(_expected_required_tasks - missing_tasks, [])

	expected := _missing_tasks_warning(missing_tasks)
	lib.assert_equal(expected, warn) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data
}

test_extra_tasks_ignored if {
	attestations := _attestations_with_tasks(_expected_future_required_tasks | {"spam"}, [])
	lib.assert_empty(deny) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data
	lib.assert_empty(warn) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data
}

test_current_equal_latest if {
	required_tasks := [{"effective_on": "2021-01-01T00:00:00Z", "tasks": _time_based_required_tasks[0].tasks}]
	attestations := _attestations_with_tasks(_expected_future_required_tasks, [])

	lib.assert_empty(deny | warn) with data["required-tasks"] as required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data
}

test_current_equal_latest_also if {
	required_tasks := [{"effective_on": "2021-01-01T00:00:00Z", "tasks": _time_based_required_tasks[0].tasks}]
	attestations := _attestations_with_tasks(_expected_required_tasks, [])

	lib.assert_empty(warn) with data["required-tasks"] as required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data

	expected_denies := _missing_tasks_violation(_expected_future_required_tasks - _expected_required_tasks)
	lib.assert_equal(expected_denies, deny) with data["required-tasks"] as required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data
}

test_no_tasks_present if {
	expected := {{
		"code": "tasks.tasks_missing",
		"msg": "No tasks found in PipelineRun attestation",
		"effective_on": "2022-01-01T00:00:00Z",
	}}

	lib.assert_equal(deny, expected) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as [{"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": []},
		}}]
		with data["task-bundles"] as bundles.bundle_data
}

test_task_present_from_unacceptable_bundle if {
	bad_task := "git-clone"
	task_from_unacceptable := [{"ref": {
		"name": bad_task,
		"kind": "Task",
		"bundle": "registry.img/unacceptable@sha256:digest",
	}}]
	attestations := _attestations_with_tasks(_expected_required_tasks - {bad_task}, task_from_unacceptable)

	expected := _missing_tasks_violation({bad_task})
	lib.assert_equal(expected, deny) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data
}

test_parameterized if {
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
	attestations := _attestations_with_tasks({"git-clone", "buildah"}, with_wrong_parameter)

	expected := _missing_tasks_violation({"sanity-label-check[POLICY_NAMESPACE=required_checks]"})
	lib.assert_equal(deny, expected) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as attestations
		with data["task-bundles"] as bundles.bundle_data
}

test_missing_required_tasks_data if {
	expected := {{
		"code": "tasks.missing_required_data",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Missing required task-bundles data",
	}}
	lib.assert_equal(expected, deny) with data["required-tasks"] as []
}

_attestations_with_tasks(names, add_tasks) = attestations if {
	tasks := array.concat([t | t := _task(names[_])], add_tasks)

	attestations := [{"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": tasks},
	}}]
}

_task(name) = task if {
	parts := regex.split("[\\[\\]=]", name)
	parts[1]
	task_name := parts[0]

	task := {"ref": {"name": task_name, "kind": "Task", "bundle": bundles.acceptable_bundle_ref}, "invocation": {"parameters": {parts[1]: parts[2]}}}
}

_task(name) = task if {
	parts := regex.split("[\\[\\]=]", name)
	not parts[1]
	task := {"ref": {"name": name, "kind": "Task", "bundle": bundles.acceptable_bundle_ref}}
}

_missing_tasks_violation(tasks) = errors if {
	errors := {error |
		some task in tasks
		error := {
			"code": "tasks.missing_required_task",
			"msg": sprintf("Required task %q is missing", [task]),
			"effective_on": "2022-01-01T00:00:00Z",
		}
	}
}

_missing_tasks_warning(tasks) = warnings if {
	warnings := {warning |
		some task in tasks
		warning := {
			"code": "tasks.missing_future_required_task",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": sprintf("Task %q is missing and will be required in the future", [task]),
		}
	}
}

_expected_required_tasks := {
	"git-clone",
	"buildah",
	"sanity-label-check[POLICY_NAMESPACE=required_checks]",
	"sanity-label-check[POLICY_NAMESPACE=optional_checks]",
}

_expected_future_required_tasks := {
	"git-clone",
	"buildah",
	"conftest-clair",
	"sanity-label-check[POLICY_NAMESPACE=required_checks]",
	"sanity-label-check[POLICY_NAMESPACE=optional_checks]",
}

_time_based_required_tasks := [
	{
		"effective_on": "2099-01-02T00:00:00Z",
		"tasks": [
			"git-clone",
			"buildah",
			"conftest-clair",
			"sanity-label-check[POLICY_NAMESPACE=required_checks]",
			"sanity-label-check[POLICY_NAMESPACE=optional_checks]",
		],
	},
	{
		"effective_on": "2099-01-01T00:00:00Z",
		"tasks": ["also-ignored"],
	},
	{
		"effective_on": "2022-12-01T00:00:00Z",
		"tasks": [
			"git-clone",
			"buildah",
			"not-required-in-future",
			"sanity-label-check[POLICY_NAMESPACE=required_checks]",
			"sanity-label-check[POLICY_NAMESPACE=optional_checks]",
		],
	},
	{
		"effective_on": "2022-01-01T00:00:00Z",
		"tasks": ["ignored"],
	},
]
