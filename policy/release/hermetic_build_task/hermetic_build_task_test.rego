package hermetic_build_task_test

import rego.v1

import data.hermetic_build_task
import data.lib

test_hermetic_build if {
	lib.assert_empty(hermetic_build_task.deny) with input.attestations as [_good_attestation]
}

test_not_hermetic_build if {
	expected := {{
		"code": "hermetic_build_task.build_task_hermetic",
		"msg": "Build task was not invoked with the hermetic parameter set",
	}}

	hermetic_not_true := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
		"value": "false",
	}])
	lib.assert_equal_results(expected, hermetic_build_task.deny) with input.attestations as [hermetic_not_true]

	# regal ignore:line-length
	hermetic_missing := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC"])
	lib.assert_equal_results(expected, hermetic_build_task.deny) with input.attestations as [hermetic_missing]
}

test_hermetic_build_many_build_tasks if {
	task1 := {
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"kind": "Task", "name": "build-1", "bundle": "reg.img/spam@sha256:abc"},
		"invocation": {"parameters": {"HERMETIC": "true"}},
	}

	task2 := {
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"kind": "Task", "name": "build-2", "bundle": "reg.img/spam@sha256:abc"},
		"invocation": {"parameters": {"HERMETIC": "true"}},
	}

	attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, task2]},
	}}}
	lib.assert_empty(hermetic_build_task.deny) with input.attestations as [attestation]

	attestation_mixed_hermetic := json.patch(
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [task1, task2]},
		}}},
		[{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
			"value": "false",
		}],
	)
	expected := {{
		"code": "hermetic_build_task.build_task_hermetic",
		"msg": "Build task was not invoked with the hermetic parameter set",
	}}
	lib.assert_equal_results(expected, hermetic_build_task.deny) with input.attestations as [attestation_mixed_hermetic]

	attestation_non_hermetic := json.patch(
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [task1, task2]},
		}}},
		[
			{
				"op": "replace",
				"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
				"value": "false",
			},
			{
				"op": "replace",
				"path": "/statement/predicate/buildConfig/tasks/1/invocation/parameters/HERMETIC",
				"value": "false",
			},
		],
	)
	lib.assert_equal_results(expected, hermetic_build_task.deny) with input.attestations as [attestation_non_hermetic]
}

_good_attestation := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"kind": "Task", "name": "any-task", "bundle": "reg.img/spam@sha256:abc"},
		"invocation": {"parameters": {"HERMETIC": "true"}},
	}]},
}}}
