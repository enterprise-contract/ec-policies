package policy.release.hermetic_build_task

import future.keywords.if

import data.lib

test_hermetic_build if {
	lib.assert_empty(deny) with input.attestations as [_good_attestation]
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
	lib.assert_equal_results(expected, deny) with input.attestations as [hermetic_not_true]

	hermetic_missing := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC"])
	lib.assert_equal_results(expected, deny) with input.attestations as [hermetic_missing]
}

_good_attestation := {"statement": {"predicate": {
	"buildType": lib.pipelinerun_att_build_types[0],
	"buildConfig": {"tasks": [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"kind": "Task", "name": "any-task", "bundle": "reg.img/spam@sha256:abc"},
		"invocation": {"parameters": {"HERMETIC": "true"}},
	}]},
}}}
