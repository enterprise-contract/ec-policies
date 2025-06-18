package pre_build_script_task_test

import rego.v1

import data.lib
import data.pre_build_script_task

test_good_pre_build_script_tasks if {
	lib.assert_empty(pre_build_script_task.deny) with input.attestations as [_good_attestation]
		with data.rule_data.allowed_registry_prefixes as _allowed_registries
}

test_disallowed_script_task_runner_image if {
	expected := {{
		"code": "pre_build_script_task.pre_build_script_task_runner_image_allowed",
		"msg": "Pre-Build-Script task runner image \"malicious.io/img:latest@sha256:abc\" is from a disallowed registry",
		"term": "malicious.io/img",
	}}

	disallowed_image := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/SCRIPT_RUNNER_IMAGE",
		"value": "malicious.io/img:latest@sha256:abc",
	}])
	lib.assert_equal_results(expected, pre_build_script_task.deny) with input.attestations as [disallowed_image]
		with data.rule_data.allowed_registry_prefixes as _allowed_registries
}

_good_attestation := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [
		{
			"name": "run-script-oci-ta-1",
			"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {
				"SCRIPT": "/some-script.sh",
				"SCRIPT_RUNNER_IMAGE": "registry.redhat.io/ubi7:latest@sha256:abc",
			}},
		},
		{
			"name": "run-script-oci-ta-2",
			"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {
				"SCRIPT": "/some-other-script.sh",
				"SCRIPT_RUNNER_IMAGE": "quay.io/konflux-ci/bazel6-ubi9:latest@sha256:bcd",
			}},
		},
	]},
}}}

_allowed_registries := ["registry.redhat.io/", "quay.io/konflux-ci/bazel6-ubi9"]
