package pre_build_script_test

import rego.v1

import data.lib
import data.pre_build_script

test_good_pre_build_scripts if {
	lib.assert_empty(pre_build_script.deny) with input.attestations as [_good_attestation]
		with data.rule_data.allowed_registry_prefixes as _allowed_registries
}

test_not_hermetic_pre_build_scripts if {
	expected := {{
		"code": "pre_build_script.pre_build_script_hermetic",
		# regal ignore:line-length
		"msg": "Pre-Build-Script task was not invoked with the hermetic parameter set: 'run-script-oci-ta-1'",
	}}

	hermetic_not_true := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
		"value": "false",
	}])
	lib.assert_equal_results(expected, pre_build_script.deny) with input.attestations as [hermetic_not_true]
		with data.rule_data.allowed_registry_prefixes as _allowed_registries

	hermetic_invalid := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
		"value": "something else",
	}])
	lib.assert_equal_results(expected, pre_build_script.deny) with input.attestations as [hermetic_invalid]
		with data.rule_data.allowed_registry_prefixes as _allowed_registries

	# regal ignore:line-length
	hermetic_missing := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC"])
	lib.assert_equal_results(expected, pre_build_script.deny) with input.attestations as [hermetic_missing]
		with data.rule_data.allowed_registry_prefixes as _allowed_registries
}

test_disallowed_script_runner_image if {
	expected := {{
		"code": "pre_build_script.pre_build_script_runner_image_allowed",
		"msg": "Pre-Build-Script runner image \"malicious.io/img:latest@sha256:abc\" is from a disallowed registry",
		"term": "malicious.io/img",
	}}

	disallowed_image := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/SCRIPT_RUNNER_IMAGE",
		"value": "malicious.io/img:latest@sha256:abc",
	}])
	lib.assert_equal_results(expected, pre_build_script.deny) with input.attestations as [disallowed_image]
		with data.rule_data.allowed_registry_prefixes as _allowed_registries
}

_good_attestation := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [
		{
			"name": "run-script-oci-ta-1",
			"ref": {"kind": "Task", "name": "run-script-oci-ta-1", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {
				"HERMETIC": "true",
				"SCRIPT": "/some-script.sh",
				"SCRIPT_RUNNER_IMAGE": "registry.redhat.io/ubi7:latest@sha256:abc",
			}},
		},
		{
			"name": "run-script-oci-ta-2",
			"ref": {"kind": "Task", "name": "run-script-oci-ta-2", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {
				"HERMETIC": "true",
				"SCRIPT": "/some-other-script.sh",
				"SCRIPT_RUNNER_IMAGE": "quay.io/konflux-ci/bazel6-ubi9:latest@sha256:bcd",
			}},
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

_allowed_registries := ["registry.redhat.io/", "quay.io/konflux-ci/bazel6-ubi9"]
