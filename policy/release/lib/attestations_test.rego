package lib

import data.lib
import data.lib.bundles

pr_build_type := "tekton.dev/v1beta1/PipelineRun"

pr_build_type_legacy := "https://tekton.dev/attestations/chains/pipelinerun@v2"

tr_build_type := "tekton.dev/v1beta1/TaskRun"

tr_build_type_legacy := "https://tekton.dev/attestations/chains@v2"

mock_pr_att := {"predicate": {"buildType": pr_build_type}}

mock_pr_att_legacy := {"predicate": {"buildType": pr_build_type_legacy}}

mock_tr_att := {"predicate": {"buildType": tr_build_type}}

mock_tr_att_legacy := {"predicate": {"buildType": tr_build_type_legacy}}

garbage_att := {"predicate": {"buildType": "garbage"}}

# This is used through the tests to generate an attestation of a PipelineRun
# with an inline Task definition, look at using att_mock_helper_ref to generate
# an attestation with a Task referenced from a Tekton Bundle image
att_mock_helper(name, result_map, task_name) = d {
	d := att_mock_helper_ref(name, result_map, task_name, "")
}

_task_ref(task_name, bundle_ref) = r {
	bundle_ref != ""
	ref_data := {"kind": "Task", "name": task_name, "bundle": bundle_ref}
	r := {"ref": ref_data}
}

_task_ref(task_name, bundle_ref) = r {
	bundle_ref == ""
	r := {}
}

# This is used through the tests to generate an attestation of a PipelineRun
# with an Task definition loaded from a Tekton Bundle image provided via
# `bundle_ref`.
# Use:
# att_mock_helper_ref_plain_result(
#	"result_name", "result_value", "task_name", "registry.io/name:tag...")
# Make note of `bundle_data` and `acceptable_bundle_ref` in the data.lib.bundles
# package that helps setup the acceptable bundle, for example:
#
# import data.lib
# import data.lib.bundles
# attestations := [lib.att_mock_helper_ref_plain_result(
#	"RESULT_NAME", "result_value", "task-name", bundles.acceptable_bundle_ref
# )]
# {...} == deny
#	with data["task-bundles"] as bundles.bundle_data
#	with input.attestations as attestations
#
# NOTE: In most cases, a task produces a result that is JSON encoded. When mocking results
# from such tasks, prefer the att_mock_helper_ref function instead.
att_mock_helper_ref_plain_result(name, result, task_name, bundle_ref) = d {
	d := {"predicate": {
		"buildType": pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [object.union(
			{"name": task_name, "results": [{
				"name": name,
				"value": result,
			}]},
			_task_ref(task_name, bundle_ref),
		)]},
	}}
}

# This is used through the tests to generate an attestation of a PipelineRun
# with an Task definition loaded from a Tekton Bundle image provided via
# `bundle_ref`.
# Use:
# att_mock_helper_ref(
# 	"result_name", {"value1": 1, "value2", "b"}, "task_name", "registry.io/name:tag...")
# Make note of `bundle_data` and `acceptable_bundle_ref` in the data.lib.bundles
# package that helps setup the acceptable bundle, for example:
#
# import data.lib
# import data.lib.bundles
# attestations := [lib.att_mock_helper_ref(
#	"RESULT_NAME", {...}, "task-name", bundles.acceptable_bundle_ref
# )]
# {...} == deny
#	with data["task-bundles"] as bundles.bundle_data
#	with input.attestations as attestations
#
# NOTE: If the task being mocked does not produced a JSON encoded result, use
# att_mock_helper_ref_plain_result instead.
att_mock_helper_ref(name, result, task_name, bundle_ref) = d {
	d := att_mock_helper_ref_plain_result(name, json.marshal(result), task_name, bundle_ref)
}

att_mock_task_helper(task) = d {
	d := [{"predicate": {
		"buildConfig": {"tasks": [task]},
		"buildType": pipelinerun_att_build_types[0],
	}}]
}

test_pr_attestations {
	assert_equal([mock_pr_att, mock_pr_att_legacy], pipelinerun_attestations) with input.attestations as [
		mock_tr_att,
		mock_tr_att_legacy,
		mock_pr_att,
		mock_pr_att_legacy,
		garbage_att,
	]

	assert_equal([], pipelinerun_attestations) with input.attestations as [
		mock_tr_att,
		mock_tr_att_legacy,
		garbage_att,
	]
}

test_tr_attestations {
	assert_equal([mock_tr_att], taskrun_attestations) with input.attestations as [
		mock_tr_att,
		mock_pr_att,
		garbage_att,
	]

	assert_equal([], taskrun_attestations) with input.attestations as [mock_pr_att, garbage_att]
}

test_att_mock_helper {
	expected := {"predicate": {
		"buildType": pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [{"name": "mytask", "results": [{
			"name": "result-name",
			"value": "{\"foo\":\"bar\"}",
		}]}]},
	}}

	assert_equal(expected, lib.att_mock_helper("result-name", {"foo": "bar"}, "mytask"))
}

test_att_mock_helper_ref {
	expected := {"predicate": {
		"buildType": pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [{
			"name": "mytask",
			"ref": {
				"name": "mytask",
				"kind": "Task",
				"bundle": "registry.img/name:tag@sha256:digest",
			},
			"results": [{
				"name": "result-name",
				"value": "{\"foo\":\"bar\"}",
			}],
		}]},
	}}

	assert_equal(expected, lib.att_mock_helper_ref("result-name", {"foo": "bar"}, "mytask", "registry.img/name:tag@sha256:digest"))
}

test_results_from_tests {
	assert_equal("TEST_OUTPUT", lib.task_test_result_name)
	assert_equal("HACBS_TEST_OUTPUT", lib.task_test_result_name_deprecated)

	expected := {
		"value": {"result": "SUCCESS", "foo": "bar"},
		"name": "mytask",
		"bundle": "registry.img/acceptable@sha256:digest",
	}

	assert_equal([expected], results_from_tests) with input.attestations as [att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS", "foo": "bar"}, "mytask", bundles.acceptable_bundle_ref)]

	assert_equal([expected], results_from_tests) with input.attestations as [att_mock_helper_ref(lib.task_test_result_name_deprecated, {"result": "SUCCESS", "foo": "bar"}, "mytask", bundles.acceptable_bundle_ref)]

	# An edge case that may never happen
	assert_equal([expected], results_from_tests) with input.attestations as [
		att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS", "foo": "bar"}, "mytask", bundles.acceptable_bundle_ref),
		att_mock_helper_ref(lib.task_test_result_name_deprecated, {"result": "SUCCESS", "baz": "quux"}, "myothertask", bundles.acceptable_bundle_ref),
	]
}

test_task_in_pipelinerun {
	task_name := "my-task"
	d := att_mock_task_helper({"name": task_name})

	assert_equal({"name": task_name}, task_in_pipelinerun(task_name)) with input.attestations as d
}

test_task_not_in_pipelinerun {
	task_name := "bad-task"
	d := att_mock_task_helper({"name": "my-task"})

	not task_in_pipelinerun(task_name) with input.attestations as d
}

test_result_in_task {
	task_name := "my-task"
	result_name := "IMAGE"
	d := att_mock_task_helper({
		"name": task_name,
		"results": [{
			"name": result_name,
			"value": "result value",
		}],
	})

	result_in_task(task_name, result_name) with input.attestations as d
}

test_result_not_in_task {
	task_name := "my-task"
	result_name := "BAD-RESULT"
	d := att_mock_task_helper({
		"name": task_name,
		"results": [{
			"name": "result name",
			"value": "result value",
		}],
	})

	not result_in_task(task_name, result_name) with input.attestations as d
}

test_task_succeeded {
	task_name := "my-task"
	d := att_mock_task_helper({
		"name": task_name,
		"status": "Succeeded",
	})

	task_succeeded(task_name) with input.attestations as d
}

test_task_not_succeeded {
	task_name := "my-task"
	d := att_mock_task_helper({
		"name": task_name,
		"status": "Failed",
	})

	not task_succeeded(task_name) with input.attestations as d
}
