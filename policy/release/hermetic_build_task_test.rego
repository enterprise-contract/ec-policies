package policy.release.hermetic_build_task_test

import future.keywords.if

import data.lib
import data.policy.release.hermetic_build_task

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
