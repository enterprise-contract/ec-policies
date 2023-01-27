package policy.pipeline.required_tasks

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

test_required_tasks_met if {
	pipeline := _pipeline_with_tasks(_expected_required_tasks, [], [])
	lib.assert_empty(deny) with data["required-tasks"] as _time_based_required_tasks
		with input as pipeline

	pipeline_finally := _pipeline_with_tasks([], _expected_required_tasks, [])
	lib.assert_empty(deny) with data["required-tasks"] as _time_based_required_tasks
		with input as pipeline_finally
}

test_required_tasks_not_met if {
	missing_tasks := {"buildah"}
	pipeline := _pipeline_with_tasks(_expected_required_tasks - missing_tasks, [], [])

	expected := _missing_tasks_violation(missing_tasks)
	lib.assert_equal(expected, deny) with data["required-tasks"] as _time_based_required_tasks
		with input as pipeline
}

test_future_required_tasks_met if {
	pipeline := _pipeline_with_tasks(_expected_future_required_tasks, [], [])
	lib.assert_empty(warn) with data["required-tasks"] as _time_based_required_tasks
		with input as pipeline

	pipeline_finally := _pipeline_with_tasks([], _expected_future_required_tasks, [])
	lib.assert_empty(warn) with data["required-tasks"] as _time_based_required_tasks
		with input as pipeline_finally
}

test_future_required_tasks_not_met if {
	missing_tasks := {"conftest-clair"}
	pipeline := _pipeline_with_tasks(_expected_required_tasks - missing_tasks, [], [])

	expected := _missing_tasks_warning(missing_tasks)
	lib.assert_equal(expected, warn) with data["required-tasks"] as _time_based_required_tasks
		with input as pipeline
}

test_extra_tasks_ignored if {
	pipeline := _pipeline_with_tasks(_expected_future_required_tasks | {"spam"}, [], [])
	lib.assert_empty(deny | warn) with data["required-tasks"] as _time_based_required_tasks
		with input as pipeline
}

test_current_equal_latest if {
	required_tasks := [{"effective_on": "2021-01-01T00:00:00Z", "tasks": _time_based_required_tasks[0].tasks}]
	pipeline := _pipeline_with_tasks(_expected_future_required_tasks, [], [])

	lib.assert_empty(deny | warn) with data["required-tasks"] as required_tasks
		with input as pipeline
}

test_current_equal_latest_also if {
	required_tasks := [{"effective_on": "2021-01-01T00:00:00Z", "tasks": _time_based_required_tasks[0].tasks}]
	pipeline := _pipeline_with_tasks(_expected_required_tasks, [], [])

	lib.assert_empty(warn) with data["required-tasks"] as required_tasks
		with input as pipeline

	expected_denies := _missing_tasks_violation(_expected_future_required_tasks - _expected_required_tasks)
	lib.assert_equal(expected_denies, deny) with data["required-tasks"] as required_tasks
		with input as pipeline
}

test_no_tasks_present if {
	expected := {{
		"code": "required_tasks.tasks_missing",
		"msg": "No tasks found in Pipeline definition",
		"effective_on": "2022-01-01T00:00:00Z",
	}}

	lib.assert_equal(expected, deny) with data["required-tasks"] as _time_based_required_tasks
		with input as {"kind": "Pipeline"}

	lib.assert_equal(expected, deny) with data["required-tasks"] as _time_based_required_tasks
		with input as {"kind": "Pipeline", "spec": {}}

	lib.assert_equal(expected, deny) with data["required-tasks"] as _time_based_required_tasks
		with input as {"kind": "Pipeline", "spec": {"tasks": [], "finally": []}}
}

test_parameterized if {
	with_wrong_parameter := [
		{
			"taskRef": {
				"name": "sanity-label-check",
				"kind": "Task",
				"bundle": _bundle,
			},
			"params": [{"name": "POLICY_NAMESPACE", "value": "something-else"}],
		},
		{
			"taskRef": {
				"name": "sanity-label-check",
				"kind": "Task",
				"bundle": _bundle,
			},
			"params": [{"name": "POLICY_NAMESPACE", "value": "optional_checks"}],
		},
	]
	pipeline := _pipeline_with_tasks({"git-clone", "buildah"}, [], with_wrong_parameter)

	expected := _missing_tasks_violation({"sanity-label-check[POLICY_NAMESPACE=required_checks]"})
	lib.assert_equal(expected, deny) with data["required-tasks"] as _time_based_required_tasks
		with input as pipeline
}

test_missing_required_tasks_data if {
	expected := {{
		"code": "required_tasks.missing_required_data",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Missing required task-bundles data",
	}}
	lib.assert_equal(expected, deny) with data["required-tasks"] as []
}

_pipeline_with_tasks(names, finally_names, add_tasks) = pipeline if {
	tasks := array.concat([t | t := _task(names[_])], add_tasks)
	finally_tasks := [t | t := _task(finally_names[_])]

	pipeline := {
		"kind": "Pipeline",
		"spec": {"tasks": tasks, "finally": finally_tasks},
	}
}

_task(name) = task if {
	parts := regex.split("[\\[\\]=]", name)
	parts[1]
	task_name := parts[0]

	task := {
		"taskRef": {"name": task_name, "kind": "Task", "bundle": _bundle},
		"params": [{"name": parts[1], "value": parts[2]}],
	}
}

_task(name) = task if {
	parts := regex.split("[\\[\\]=]", name)
	not parts[1]
	task := {"taskRef": {"name": name, "kind": "Task", "bundle": _bundle}}
}

_missing_tasks_violation(tasks) = errors if {
	errors := {error |
		some task in tasks
		error := {
			"code": "required_tasks.missing_required_task",
			"msg": sprintf("Required task %q is missing", [task]),
			"effective_on": "2022-01-01T00:00:00Z",
		}
	}
}

_missing_tasks_warning(tasks) = warnings if {
	warnings := {warning |
		some task in tasks
		warning := {
			"code": "required_tasks.missing_future_required_task",
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

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
