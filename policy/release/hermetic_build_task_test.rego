package policy.release.hermetic_build_task

import future.keywords.if

import data.lib
import data.lib.bundles

test_hermetic_build if {
	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_good_attestation]
}

test_not_hermetic_build if {
	expected := {{
		"code": "build_task_not_hermetic",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Build task was not invoked with hermetic parameter",
	}}

	untrusted_bundle := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/predicate/buildConfig/tasks/0/ref/bundle",
		"value": "untrusted.registry.com/bundle",
	}])
	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [untrusted_bundle]

	hermetic_not_true := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC_BUILD",
		"value": "false",
	}])
	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [hermetic_not_true]
}

_good_attestation := {"predicate": {
	"buildType": lib.pipelinerun_att_build_types[0],
	"buildConfig": {"tasks": [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"kind": "Task", "name": "any-task", "bundle": bundles.acceptable_bundle_ref},
		"invocation": {"parameters": {"HERMETIC_BUILD": "true"}},
	}]},
}}
