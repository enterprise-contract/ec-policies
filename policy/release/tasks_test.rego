package policy.release.tasks_test

import data.lib
import data.lib.tkn_test
import data.policy.release.tasks

import future.keywords.contains
import future.keywords.if
import future.keywords.in

test_no_tasks_present if {
	expected := {{
		"code": "tasks.pipeline_has_tasks",
		"msg": "No tasks found in PipelineRun attestation",
	}}

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as [{"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": []},
	}}}]

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as _slsav1_attestations_with_tasks([], [])
}

test_failed_tasks if {
	expected := {
		{
			"code": "tasks.successful_pipeline_tasks",
			"msg": "Pipeline task \"av-scanner\" did not complete successfully, \"Failed\"",
			"term": "av-scanner",
		},
		{
			"code": "tasks.successful_pipeline_tasks",
			"msg": "Pipeline task \"cve-scanner\" did not complete successfully, \"MISSING\"",
			"term": "cve-scanner",
		},
	}

	given_tasks := [
		_task("buildah"),
		json.patch(_task("av-scanner"), [{
			"op": "add",
			"path": "/status",
			"value": "Failed",
		}]),
		json.remove(_task("cve-scanner"), ["/status"]),
	]

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as [{"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": given_tasks},
	}}}]

	slsav1_tasks := [
		_slsav1_task("buildah"),
		json.patch(_slsav1_task("av-scanner"), [{
			"op": "replace",
			"path": "/status/conditions",
			"value": [{"type": "Succeeded", "status": "False"}],
		}]),
		json.patch(_slsav1_task("cve-scanner"), [{
			"op": "replace",
			"path": "/status/conditions",
			"value": [],
		}]),
	]

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as _slsav1_attestations_with_tasks([], slsav1_tasks)
}

test_required_tasks_met if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as slsav1_attestations
}

test_required_tasks_met_no_label if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with data["pipeline-required-tasks"] as {}
		with input.attestations as attestations

	attestations_no_label := _attestations_with_tasks_no_label(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as attestations_no_label

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with data["pipeline-required-tasks"] as {}
		with input.attestations as slsav1_attestations

	slsav1_attestations_no_label := _slsav1_attestations_with_tasks_no_label(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with input.attestations as slsav1_attestations_no_label
}

test_required_tasks_warning_no_label if {
	attestations := _attestations_with_tasks_no_label(_expected_required_tasks, [])
	expected := {{
		"code": "tasks.pipeline_required_tasks_list_provided",
		"msg": "Required tasks do not exist for pipeline",
	}}
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks_no_label(_expected_required_tasks, [])
	lib.assert_equal_results(expected, tasks.warn) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as slsav1_attestations
}

test_required_tasks_not_met if {
	missing_tasks := {"buildah"}
	attestations := _attestations_with_tasks(_expected_required_tasks - missing_tasks, [])

	expected := _missing_tasks_violation(missing_tasks)
	lib.assert_equal_results(
		expected,
		tasks.deny,
	) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_required_tasks - missing_tasks, [])
	lib.assert_equal_results(expected, tasks.deny) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as slsav1_attestations
}

test_future_required_tasks_met if {
	attestations := _attestations_with_tasks(_expected_future_required_tasks, [])
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_future_required_tasks, [])
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as slsav1_attestations
}

test_future_required_tasks_not_met if {
	missing_tasks := {"conftest-clair"}
	attestations := _attestations_with_tasks(_expected_future_required_tasks - missing_tasks, [])

	expected := _missing_tasks_warning(missing_tasks)
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_future_required_tasks - missing_tasks, [])
	lib.assert_equal_results(expected, tasks.warn) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as slsav1_attestations
}

test_extra_tasks_ignored if {
	attestations := _attestations_with_tasks(_expected_future_required_tasks | {"spam"}, [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_future_required_tasks | {"spam"}, [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as slsav1_attestations
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as slsav1_attestations
}

test_current_equal_latest if {
	required_tasks := {"generic": [{
		"effective_on": "2021-01-01T00:00:00Z",
		"tasks": _time_based_required_pipeline_tasks.generic[0].tasks,
	}]}
	attestations := _attestations_with_tasks(_expected_future_required_tasks, [])

	lib.assert_empty(tasks.deny | tasks.warn) with data["pipeline-required-tasks"] as required_tasks
		with input.attestations as attestations
}

test_current_equal_latest_also if {
	required_tasks := {"generic": [{
		"effective_on": "2021-01-01T00:00:00Z",
		"tasks": _time_based_required_pipeline_tasks.generic[0].tasks,
	}]}
	attestations := _attestations_with_tasks(_expected_required_tasks, [])

	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as required_tasks
		with input.attestations as attestations

	expected_denies := _missing_tasks_violation(_expected_future_required_tasks - _expected_required_tasks)
	lib.assert_equal_results(expected_denies, tasks.deny) with data["pipeline-required-tasks"] as required_tasks
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as required_tasks
		with input.attestations as slsav1_attestations

	lib.assert_equal_results(expected_denies, tasks.deny) with data["pipeline-required-tasks"] as required_tasks
		with input.attestations as slsav1_attestations
}

test_parameterized if {
	with_wrong_parameter := [
		{
			"status": "Succeeded",
			"ref": {
				"name": "label-check",
				"kind": "Task",
				"bundle": _bundle,
			},
			"invocation": {"parameters": {"POLICY_NAMESPACE": "something-else"}},
		},
		{
			"status": "Succeeded",
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
	lib.assert_equal_results(
		tasks.deny,
		expected,
	) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as attestations

	slsav1_no_param := _slsav1_task("label-check")
	slsav1_task1 := json.patch(slsav1_no_param, [{
		"op": "replace",
		"path": "/spec/params",
		"value": [{"name": "POLICY_NAMESPACE", "value": "something-else"}],
	}])
	slsav1_task2 := json.patch(slsav1_no_param, [{
		"op": "replace",
		"path": "/spec/params",
		"value": [{"name": "POLICY_NAMESPACE", "value": "optional_checks"}],
	}])

	slsav1_attestations := _slsav1_attestations_with_tasks({"git-clone", "buildah"}, [slsav1_task1, slsav1_task2])
	lib.assert_equal_results(tasks.deny, expected) with data["pipeline-required-tasks"] as _time_based_required_pipeline_tasks
		with input.attestations as slsav1_attestations
}

test_required_tasks_founds_data if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	expected := {{
		"code": "tasks.required_tasks_list_provided",
		"msg": "Missing required task-bundles data",
	}}
	lib.assert_equal_results(expected, tasks.deny) with data["required-tasks"] as []
		with input.attestations as attestations
		with data["pipeline-required-tasks"] as {}

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_equal_results(expected, tasks.deny) with data["required-tasks"] as []
		with input.attestations as slsav1_attestations with data["pipeline-required-tasks"] as {}
}

test_missing_required_pipeline_data if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	expected := {{
		"code": "tasks.pipeline_required_tasks_list_provided",
		"msg": "Required tasks do not exist for pipeline",
	}}
	lib.assert_equal_results(expected, tasks.warn) with data["required-tasks"] as _expected_required_tasks
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_equal_results(expected, tasks.warn) with data["required-tasks"] as _expected_required_tasks
		with input.attestations as slsav1_attestations
}

test_multiple_conditions_in_status if {
	conditions := [
		{
			"type": "Succeeded",
			"status": "True",
		},
		{
			"type": "Succeeded",
			"status": "False",
		},
	]
	slsav1_task := json.patch(_slsav1_task("buildah"), [{
		"op": "replace",
		"path": "/status/conditions",
		"value": conditions,
	}])

	lib.assert_equal(["Succeeded", "Failed"], tasks._status(slsav1_task))
}

_attestations_with_tasks(names, add_tasks) := attestations if {
	tasks := array.concat([t | some name in names; t := _task(name)], add_tasks)

	attestations := [{"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": tasks},
		"invocation": {"environment": {"labels": {"pipelines.openshift.io/runtime": "generic"}}},
	}}}]
}

_slsav1_attestations_with_tasks(names, add_tasks) := attestations if {
	slsav1_tasks := array.concat([t | some name in names; t := _slsav1_task(name)], add_tasks)

	attestations := [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": lib.tekton_slsav1_pipeline_run,
			"externalParameters": {"runSpec": {"pipelineRef": {"name": "pipeline1"}}},
			"resolvedDependencies": _resolved_dependencies(slsav1_tasks),
			"internalParameters": {"labels": {"pipelines.openshift.io/runtime": "generic"}},
		}},
	}}]
}

_attestations_with_tasks_no_label(names, add_tasks) := attestations if {
	tasks := array.concat([t | some name in names; t := _task(name)], add_tasks)

	attestations := [{"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": tasks},
	}}}]
}

_slsav1_attestations_with_tasks_no_label(names, add_tasks) := attestations if {
	slsav1_tasks := array.concat([t | some name in names; t := _slsav1_task(name)], add_tasks)

	attestations := [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": lib.tekton_slsav1_pipeline_run,
			"externalParameters": {"runSpec": {"pipelineRef": {"name": "pipeline1"}}},
			"resolvedDependencies": _resolved_dependencies(slsav1_tasks),
			"internalParameters": {},
		}},
	}}]
}

_task(name) := task if {
	parts := regex.split(`[\[\]=]`, name)
	parts[1]
	task_name := parts[0]
	pipeline_task_name := sprintf("%s-p", [task_name])

	task := {
		"name": pipeline_task_name,
		"status": "Succeeded",
		"ref": {"name": task_name, "kind": "Task", "bundle": _bundle},
		"invocation": {"parameters": {parts[1]: parts[2]}},
	}
}

_task(name) := task if {
	parts := regex.split(`[\[\]=]`, name)
	not parts[1]
	pipeline_task_name := sprintf("%s-p", [name])
	task := {
		"name": pipeline_task_name,
		"status": "Succeeded",
		"ref": {"name": name, "kind": "Task", "bundle": _bundle},
	}
}

_slsav1_task(name) := task if {
	parts := regex.split(`[\[\]=]`, name)
	not parts[1]
	pipeline_task_name := sprintf("%s-p", [name])
	unnamed_task := {
		"metadata": {"name": pipeline_task_name},
		"spec": tkn_test.slsav1_attestation_local_spec,
		"status": {"conditions": [{
			"type": "Succeeded",
			"status": "True",
		}]},
	}
	task := json.patch(unnamed_task, [{
		"op": "replace",
		"path": "/spec/taskRef/name",
		"value": name,
	}])
}

_slsav1_task(name) := task if {
	parts := regex.split(`[\[\]=]`, name)
	parts[1]
	task_name := parts[0]
	pipeline_task_name := sprintf("%s-p", [task_name])
	unnamed_task := {
		"metadata": {"name": pipeline_task_name},
		"spec": tkn_test.slsav1_attestation_local_spec,
		"status": {"conditions": [{
			"type": "Succeeded",
			"status": "True",
		}]},
	}
	task := json.patch(unnamed_task, [
		{
			"op": "replace",
			"path": "/spec/taskRef/name",
			"value": task_name,
		},
		{
			"op": "replace",
			"path": "/spec/params",
			"value": [{"name": parts[1], "value": parts[2]}],
		},
	])
}

_resolved_dependencies(tasks) := [r |
	some task in tasks
	r := {
		"name": "pipelineTask",
		"content": json.marshal(task),
	}
]

_missing_tasks_violation(tasks) := {error |
	some task in tasks
	error := {
		"code": "tasks.required_tasks_found",
		"msg": sprintf("Required task %q is missing", [task]),
		"term": task,
	}
}

_missing_tasks_warning(tasks) := {warning |
	some task in tasks
	warning := {
		"code": "tasks.future_required_tasks_found",
		"msg": sprintf("Task %q is missing and will be required in the future", [task]),
		"term": task,
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
