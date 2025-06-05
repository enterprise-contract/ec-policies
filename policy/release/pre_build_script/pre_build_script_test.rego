package pre_build_script_test

import rego.v1

import data.lib
import data.pre_build_script

test_good_pre_build_scripts if {
	lib.assert_empty(pre_build_script.deny) with input.attestations as [_good_attestation]
}

test_not_hermetic_pre_build_scripts if {
	expected := {{
		"code": "pre_build_script.pre_build_script_hermetic",
		# regal ignore:line-length
		"msg": "Pre-Build-Script task was not invoked with the hermetic parameter set: 'run-script-oci-ta'",
	}}

	hermetic_not_true := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
		"value": "false",
	}])
	lib.assert_equal_results(expected, pre_build_script.deny) with input.attestations as [hermetic_not_true]

	hermetic_invalid := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
		"value": "something else",
	}])
	lib.assert_equal_results(expected, pre_build_script.deny) with input.attestations as [hermetic_invalid]

	# regal ignore:line-length
	hermetic_missing := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC"])
	lib.assert_equal_results(expected, pre_build_script.deny) with input.attestations as [hermetic_missing]
}

_good_attestation := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [
		{
			"name": "run-script-oci-ta-1",
			"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {"HERMETIC": "true", "SCRIPT": "/some-script.sh"}},
		},
		{
			"name": "run-script-oci-ta-2",
			"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": "reg.img/spam@sha256:def"},
			"invocation": {"parameters": {"HERMETIC": "true", "SCRIPT": "/some-other-script.sh"}},
		},
		{
			"name": "prefetch-dependencies",
			"ref": {"kind": "Task", "name": "prefetch-dependencies", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {}},
		},
		{
			"after": ["run-script-oci-ta-1", "run-script-oci-ta-2", "prefetch-dependencies"],
			"results": [
				{"name": "IMAGE_URL", "value": "registry/repo"},
				{"name": "IMAGE_DIGEST", "value": "digest"},
			],
			"ref": {"kind": "Task", "name": "any-task", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {"HERMETIC": "true"}},
		},
	]},
}}}
