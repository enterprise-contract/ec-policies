# regal ignore:file-length
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

# regal ignore:rule-length
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
		tkn_test.slsav1_task("buildah"),
		json.patch(tkn_test.slsav1_task("av-scanner"), [{
			"op": "replace",
			"path": "/status/conditions",
			"value": [{"type": "Succeeded", "status": "False"}],
		}]),
		json.patch(tkn_test.slsav1_task("cve-scanner"), [{
			"op": "replace",
			"path": "/status/conditions",
			"value": [],
		}]),
	]

	lib.assert_equal_results(
		tasks.deny,
		expected,
	) with input.attestations as _slsav1_attestations_with_tasks([], slsav1_tasks)
}

test_required_tasks_met if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as slsav1_attestations
}

test_required_tasks_met_no_label if {
	attestations := _attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with data["pipeline-required-tasks"] as {}
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations

	attestations_no_label := _attestations_with_tasks_no_label(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations_no_label

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with data["pipeline-required-tasks"] as {}
		with data["task-bundles"] as _expected_bundles
		with input.attestations as slsav1_attestations

	slsav1_attestations_no_label := _slsav1_attestations_with_tasks_no_label(_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with data["task-bundles"] as _expected_bundles
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
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks_no_label(_expected_required_tasks, [])
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with input.attestations as slsav1_attestations
}

test_required_tasks_not_met if {
	missing_tasks := {"buildah"}
	attestations := _attestations_with_tasks(_expected_required_tasks - missing_tasks, [])

	expected := _missing_tasks_violation(missing_tasks)
	lib.assert_equal_results(
		expected,
		tasks.deny,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_required_tasks - missing_tasks, [])
	lib.assert_equal_results(
		expected,
		tasks.deny,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as slsav1_attestations
}

test_future_required_tasks_met if {
	attestations := _attestations_with_tasks(_expected_future_required_tasks, [])
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_future_required_tasks, [])
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as slsav1_attestations
}

test_future_required_tasks_not_met if {
	missing_tasks := {"conftest-clair"}
	attestations := _attestations_with_tasks(_expected_future_required_tasks - missing_tasks, [])

	expected := _missing_tasks_warning(missing_tasks)
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_future_required_tasks - missing_tasks, [])
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as slsav1_attestations
}

test_extra_tasks_ignored if {
	attestations := _attestations_with_tasks(_expected_future_required_tasks | {"spam"}, [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_future_required_tasks | {"spam"}, [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as slsav1_attestations
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as slsav1_attestations
}

test_current_equal_latest if {
	required_tasks := {"generic": [{
		"effective_on": "2021-01-01T00:00:00Z",
		"tasks": _required_pipeline_tasks.generic[0].tasks,
	}]}
	attestations := _attestations_with_tasks(_expected_future_required_tasks, [])

	lib.assert_empty(tasks.deny | tasks.warn) with data["pipeline-required-tasks"] as required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations
}

test_current_equal_latest_also if {
	required_tasks := {"generic": [{
		"effective_on": "2021-01-01T00:00:00Z",
		"tasks": _required_pipeline_tasks.generic[0].tasks,
	}]}
	attestations := _attestations_with_tasks(_expected_required_tasks, [])

	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations

	expected_denies := _missing_tasks_violation(_expected_future_required_tasks - _expected_required_tasks)
	lib.assert_equal_results(expected_denies, tasks.deny) with data["pipeline-required-tasks"] as required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations

	slsav1_attestations := _slsav1_attestations_with_tasks(_expected_required_tasks, [])
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as slsav1_attestations

	lib.assert_equal_results(expected_denies, tasks.deny) with data["pipeline-required-tasks"] as required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as slsav1_attestations
}

# regal ignore:rule-length
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
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations

	slsav1_no_param := tkn_test.slsav1_task_bundle("label-check", _bundle)
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
	lib.assert_equal_results(
		tasks.deny,
		expected,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
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
		{"type": "invalid"},
	]
	slsav1_task := json.patch(tkn_test.slsav1_task("buildah"), [{
		"op": "replace",
		"path": "/status/conditions",
		"value": conditions,
	}])

	lib.assert_equal(["Succeeded", "Failed"], tasks._status(slsav1_task))
}

test_invalid_status_conditions if {
	conditions := []
	slsav1_task1 := json.patch(tkn_test.slsav1_task("buildah"), [{
		"op": "replace",
		"path": "/status/conditions",
		"value": conditions,
	}])
	lib.assert_equal(["MISSING"], tasks._status(slsav1_task1))

	given_task := json.remove(_task("buildah"), ["/status"])
	lib.assert_equal(["MISSING"], tasks._status(given_task))
}

test_one_of_required_tasks if {
	attestation_v02 := _attestations_with_tasks(["a", "b", "c1", "d2", "e", "f"], [])
	data_required_tasks := {"generic": [{
		"tasks": {"a", ["c1", "c2", "c3"], ["d1", "d2", "d3"], ["e"]},
		"effective_on": "2009-01-02T00:00:00Z",
	}]}
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as data_required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestation_v02

	attestation_v1 := _slsav1_attestations_with_tasks(["a", "b", "c1", "d2", "e", "f"], [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as data_required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestation_v1
}

test_one_of_required_tasks_missing if {
	attestation_v02 := _attestations_with_tasks(["a", "b", "d2", "e", "f"], [])

	data_required_tasks := {"generic": [{
		"tasks": {"a", ["c1", "c2", "c3"], ["d1", "d3"]},
		"effective_on": "2009-01-02T00:00:00Z",
	}]}

	expected := {
		{
			"code": "tasks.required_tasks_found",
			"msg": `One of "c1", "c2", "c3" tasks is missing`,
			"term": ["c1", "c2", "c3"],
		},
		{
			"code": "tasks.required_tasks_found",
			"msg": `One of "d1", "d3" tasks is missing`,
			"term": ["d1", "d3"],
		},
	}

	lib.assert_equal_results(expected, tasks.deny) with data["pipeline-required-tasks"] as data_required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestation_v02

	attestation_v1 := _slsav1_attestations_with_tasks(["a", "b", "d2", "e", "f"], [])
	lib.assert_equal_results(expected, tasks.deny) with data["pipeline-required-tasks"] as data_required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestation_v1
}

test_future_one_of_required_tasks if {
	attestation_v02 := _attestations_with_tasks(["a", "b", "c1", "d2", "e", "f"], [])
	data_required_tasks := {"generic": [{
		"tasks": {"a", ["c1", "c2", "c3"], ["d1", "d2", "d3"], ["e"]},
		"effective_on": "2099-01-02T00:00:00Z",
	}]}
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as data_required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestation_v02

	attestation_v1 := _slsav1_attestations_with_tasks(["a", "b", "c1", "d2", "e", "f"], [])
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as data_required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestation_v1
}

test_future_one_of_required_tasks_missing if {
	attestation_v02 := _attestations_with_tasks(["a", "b", "d2", "e", "f"], [])

	data_required_tasks := {"generic": [{
		"tasks": {"a", ["c1", "c2", "c3"], ["d1", "d3"]},
		"effective_on": "2099-01-02T00:00:00Z",
	}]}

	expected := {
		{
			"code": "tasks.future_required_tasks_found",
			"msg": `One of "c1", "c2", "c3" tasks is missing and will be required in the future`,
			"term": ["c1", "c2", "c3"],
		},
		{
			"code": "tasks.future_required_tasks_found",
			"msg": `One of "d1", "d3" tasks is missing and will be required in the future`,
			"term": ["d1", "d3"],
		},
	}
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as data_required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestation_v02

	attestation_v1 := _slsav1_attestations_with_tasks(["a", "b", "d2", "e", "f"], [])
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as data_required_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestation_v1
}

test_required_task_from_unacceptable if {
	attestations := _attestations_with_tasks(_expected_required_tasks - {"buildah"}, [{
		"name": "buildah",
		"ref": {"name": "buildah", "kind": "Task", "bundle": "registry.io/repository/unacceptable"},
	}])
	expected := {
		{
			"code": "tasks.future_required_tasks_found",
			"msg": "Task \"conftest-clair\" is missing and will be required in the future",
			"term": "conftest-clair",
		},
		{
			"code": "tasks.required_task_unacceptable_found",
			"msg": "Required task \"buildah\" is required and present but not from an acceptable bundle",
			"term": "buildah",
		},
	}
	lib.assert_equal_results(expected, tasks.warn) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data["task-bundles"] as _expected_bundles
		with input.attestations as attestations
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
	slsav1_tasks := array.concat([t | some name in names; t := tkn_test.slsav1_task_bundle(name, _bundle)], add_tasks)

	attestations := [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": lib.tekton_slsav1_pipeline_run,
			"externalParameters": {"runSpec": {"pipelineRef": {"name": "pipeline1"}}},
			"resolvedDependencies": tkn_test.resolved_dependencies(slsav1_tasks),
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
	slsav1_tasks := array.concat([t | some name in names; t := tkn_test.slsav1_task_bundle(name, _bundle)], add_tasks)

	attestations := [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": lib.tekton_slsav1_pipeline_run,
			"externalParameters": {"runSpec": {"pipelineRef": {"name": "pipeline1"}}},
			"resolvedDependencies": tkn_test.resolved_dependencies(slsav1_tasks),
			"internalParameters": {},
		}},
	}}]
}

_task(name) := task if {
	parts := regex.split(`[\[\]=]`, name)

	# regal ignore:redundant-existence-check
	parts[1]
	task_name := parts[0]
	pipeline_task_name := sprintf("%s", [task_name])

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
	pipeline_task_name := sprintf("%s", [name])
	task := {
		"name": pipeline_task_name,
		"status": "Succeeded",
		"ref": {"name": name, "kind": "Task", "bundle": _bundle},
	}
}

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

_required_pipeline_tasks := {"generic": [
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

_expected_bundles := {"registry.img/spam": [{
	"digest": "sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
	"tag": "0.1",
	"effective_on": "2000-01-01T00:00:00Z",
}]}
