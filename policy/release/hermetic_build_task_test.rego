package policy.release.hermetic_build_task

import future.keywords.if

import data.lib

test_hermetic_build if {
	lib.assert_empty(deny) with input.attestations as [_good_attestation]
}

test_not_hermetic_build if {
	expected := {{
		"code": "hermetic_build_task.build_task_not_hermetic",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Build task was not invoked with hermetic parameter",
	}}

	hermetic_not_true := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
		"value": "false",
	}])
	lib.assert_equal(expected, deny) with input.attestations as [hermetic_not_true]

	hermetic_missing := json.remove(_good_attestation, ["/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC"])
	lib.assert_equal(expected, deny) with input.attestations as [hermetic_missing]
}

_good_attestation := {"predicate": {
	"buildType": lib.pipelinerun_att_build_types[0],
	"buildConfig": {"tasks": [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"kind": "Task", "name": "any-task", "bundle": "reg.img/spam@sha256:abc"},
		"invocation": {"parameters": {"HERMETIC": "true"}},
	}]},
}}
