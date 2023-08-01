package policy.release.tasks

import data.lib

import future.keywords.contains
import future.keywords.if
import future.keywords.in

test_required_tasks_met if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(deny) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations
}

test_required_tasks_met_no_label if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(deny) with data["required-tasks"] as _time_based_required_tasks
		with data["pipeline-required-tasks"] as {}
		with input.attestations as attestations

	attestations_no_label := _attestations_with_tasks_no_label(_expected_required_tasks, [])
	lib.assert_empty(deny) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as attestations_no_label
}

test_required_tasks_warning_no_label if {
	attestations := _attestations_with_tasks_no_label(_expected_required_tasks, [])
	expected := {{
		"code": "tasks.pipeline_required_tasks_list_provided",
		"msg": "Required tasks do not exist for pipeline",
	}}
	lib.assert_equal_results(expected, warn) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations
}

test_required_tasks_not_met if {
	missing_tasks := {"buildah"}
	attestations := _attestations_with_tasks(_expected_required_tasks - missing_tasks, [])

	expected := _missing_tasks_violation(missing_tasks)
	lib.assert_equal_results(expected, deny) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations
}

test_future_required_tasks_met if {
	attestations := _attestations_with_tasks(_expected_future_required_tasks, [])
	lib.assert_empty(warn) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations
}

test_future_required_tasks_not_met if {
	missing_tasks := {"conftest-clair"}
	attestations := _attestations_with_tasks(_expected_required_tasks - missing_tasks, [])

	expected := _missing_tasks_warning(missing_tasks)
	lib.assert_equal_results(expected, warn) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations
}

test_extra_tasks_ignored if {
	attestations := _attestations_with_tasks(_expected_future_required_tasks | {"spam"}, [])
	lib.assert_empty(deny) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations
	lib.assert_empty(warn) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations
}

test_current_equal_latest if {
	required_tasks := {"generic": [{"effective_on": "2021-01-01T00:00:00Z", "tasks": _time_based_required_pipeline_tasks.generic[0].tasks}]}
	attestations := _attestations_with_tasks(_expected_future_required_tasks, [])

	lib.assert_empty(deny | warn) with data["pipeline-required-tasks"] as required_tasks
		with input.attestations as attestations
}

test_current_equal_latest_also if {
	required_tasks := {"generic": [{"effective_on": "2021-01-01T00:00:00Z", "tasks": _time_based_required_pipeline_tasks.generic[0].tasks}]}
	attestations := _attestations_with_tasks(_expected_required_tasks, [])

	lib.assert_empty(warn) with data["pipeline-required-tasks"] as required_tasks
		with input.attestations as attestations

	expected_denies := _missing_tasks_violation(_expected_future_required_tasks - _expected_required_tasks)
	lib.assert_equal_results(expected_denies, deny) with data["pipeline-required-tasks"] as required_tasks
		with input.attestations as attestations
}

test_no_tasks_present if {
	expected := {{
		"code": "tasks.pipeline_has_tasks",
		"msg": "No tasks found in PipelineRun attestation",
	}}

	lib.assert_equal_results(deny, expected) with data["pipeline-required-tasks"] as _time_based_required_tasks
		with input.attestations as [{"statement": {"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": []},
		}}}]
}

test_parameterized if {
	with_wrong_parameter := [
		{
			"ref": {
				"name": "label-check",
				"kind": "Task",
				"bundle": _bundle,
			},
			"invocation": {"parameters": {"POLICY_NAMESPACE": "something-else"}},
		},
		{
			"ref": {
				"name": "label-check",
				"kind": "Task",
				"bundle": _bundle,
			},
			"invocation": {"parameters": {"POLICY_NAMESPACE": "optional_checks"}},
		},
	]
	attestations := _attestations_with_tasks({"git-clone", "buildah"}, with_wrong_parameter)

	expected := _missing_tasks_violation({"label-check[POLICY_NAMESPACE=required_checks]"})
	lib.assert_equal_results(deny, expected) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations
}

test_required_tasks_founds_data if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	expected := {{
		"code": "tasks.required_tasks_list_provided",
		"msg": "Missing required task-bundles data",
	}}
	lib.assert_equal_results(expected, deny) with data["required-tasks"] as [] with input.attestations as attestations
		with data["pipeline-required-tasks"] as {}
}

test_missing_required_pipeline_data if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	expected := {{
		"code": "tasks.pipeline_required_tasks_list_provided",
		"msg": "Required tasks do not exist for pipeline",
	}}
	lib.assert_equal_results(expected, warn) with data["required-tasks"] as _expected_required_tasks with input.attestations as attestations
}

_attestations_with_tasks(names, add_tasks) = attestations if {
	tasks := array.concat([t | t := _task(names[_])], add_tasks)

	attestations := [{"statement": {"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": tasks},
		"invocation": {"environment": {"labels": {"pipelines.openshift.io/runtime": "generic"}}},
	}}}]
}

_attestations_with_tasks_no_label(names, add_tasks) = attestations if {
	tasks := array.concat([t | t := _task(names[_])], add_tasks)

	attestations := [{"statement": {"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": tasks},
	}}}]
}

_task(name) = task if {
	parts := regex.split("[\\[\\]=]", name)
	parts[1]
	task_name := parts[0]

	task := {"ref": {"name": task_name, "kind": "Task", "bundle": _bundle}, "invocation": {"parameters": {parts[1]: parts[2]}}}
}

_task(name) = task if {
	parts := regex.split("[\\[\\]=]", name)
	not parts[1]
	task := {"ref": {"name": name, "kind": "Task", "bundle": _bundle}}
}

_missing_tasks_violation(tasks) = errors if {
	errors := {error |
		some task in tasks
		error := {
			"code": "tasks.required_tasks_found",
			"msg": sprintf("Required task %q is missing", [task]),
			"term": task,
		}
	}
}

_missing_tasks_warning(tasks) = warnings if {
	warnings := {warning |
		some task in tasks
		warning := {
			"code": "tasks.future_required_tasks_found",
			"msg": sprintf("Task %q is missing and will be required in the future", [task]),
			"term": task,
		}
	}
}

_expected_required_tasks := {
	"git-clone",
	"buildah",
	"label-check[POLICY_NAMESPACE=required_checks]",
	"label-check[POLICY_NAMESPACE=optional_checks]",
}

_expected_future_required_tasks := {
	"git-clone",
	"buildah",
	"conftest-clair",
	"label-check[POLICY_NAMESPACE=required_checks]",
	"label-check[POLICY_NAMESPACE=optional_checks]",
}

_time_based_required_pipeline_tasks := {"generic": [
	{
		"effective_on": "2099-01-02T00:00:00Z",
		"tasks": [
			"git-clone",
			"buildah",
			"conftest-clair",
			"label-check[POLICY_NAMESPACE=required_checks]",
			"label-check[POLICY_NAMESPACE=optional_checks]",
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
			"label-check[POLICY_NAMESPACE=required_checks]",
			"label-check[POLICY_NAMESPACE=optional_checks]",
		],
	},
	{
		"effective_on": "2022-01-01T00:00:00Z",
		"tasks": ["ignored"],
	},
]}

_time_based_required_tasks := [
	{
		"effective_on": "2099-01-02T00:00:00Z",
		"tasks": [
			"git-clone",
			"buildah",
			"conftest-clair",
			"label-check[POLICY_NAMESPACE=required_checks]",
			"label-check[POLICY_NAMESPACE=optional_checks]",
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
			"label-check[POLICY_NAMESPACE=required_checks]",
			"label-check[POLICY_NAMESPACE=optional_checks]",
		],
	},
	{
		"effective_on": "2022-01-01T00:00:00Z",
		"tasks": ["ignored"],
	},
]

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
