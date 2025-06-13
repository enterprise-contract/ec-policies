package pre_build_script_task_test

import rego.v1

import data.lib
import data.pre_build_script_task

test_pre_build_image_not_in_task_result if {
	expected := {{
		"code": "pre_build_script_task.pre_build_script_task_runner_image_in_results",
		"msg": "The runner image used for the pre-Build-Script task 'run-script-oci-ta' is not listed in the task results",
	}}

	attestation_missing_task_result := json.patch(_good_attestation, [{
		"op": "remove",
		"path": "/statement/predicate/buildConfig/tasks/0/results/0",
	}])

	# regal ignore:line-length
	lib.assert_equal_results(expected, pre_build_script_task.deny) with input.attestations as [attestation_missing_task_result, _cyclonedx_sbom_attestation]
}

test_pre_build_image_in_sbom if {
	# regal ignore:line-length
	lib.assert_empty(pre_build_script_task.deny) with input.attestations as [_good_attestation, _cyclonedx_sbom_attestation]

	# regal ignore:line-length
	lib.assert_empty(pre_build_script_task.deny) with input.attestations as [_good_attestation, _spdx_sbom_attestation]
}

test_pre_build_image_not_in_sbom if {
	expected := {{
		"code": "pre_build_script_task.pre_build_script_task_runner_image_in_sbom",
		"msg": "Pre-Build-Script task runner image \"registry.redhat.io/ubi7:latest@sha256:abc\" is not in the SBOM",
	}}

	incomplete_cyclonedx_sbom_attestation := json.patch(_cyclonedx_sbom_attestation, [{
		"op": "remove",
		"path": "/statement/predicate/components/1",
	}])

	# regal ignore:line-length
	lib.assert_equal_results(expected, pre_build_script_task.deny) with input.attestations as [_good_attestation, incomplete_cyclonedx_sbom_attestation]

	incomplete_spdx_sbom_attestation := json.patch(_spdx_sbom_attestation, [{
		"op": "remove",
		"path": "/statement/predicate/packages/0/externalRefs/1",
	}])

	# regal ignore:line-length
	lib.assert_equal_results(expected, pre_build_script_task.deny) with input.attestations as [_good_attestation, incomplete_spdx_sbom_attestation]
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
			"results": [{"name": "SCRIPT_RUNNER_IMAGE_REFERENCE", "value": "registry.redhat.io/ubi7:latest@sha256:abc"}],
		},
		{
			"name": "run-script-oci-ta-2",
			"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {
				"SCRIPT": "/some-other-script.sh",
				"SCRIPT_RUNNER_IMAGE": "quay.io/konflux-ci/bazel6-ubi9:latest@sha256:bcd",
			}},
			"results": [{"name": "SCRIPT_RUNNER_IMAGE_REFERENCE", "value": "quay.io/konflux-ci/bazel6-ubi9:latest@sha256:bcd"}],
		},
	]},
}}}

_spdx_sbom_attestation := {"statement": {
	"predicateType": "https://spdx.dev/Document",
	"predicate": {"packages": [{"externalRefs": [
		{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceType": "purl",
			"referenceLocator": "oci://example.com/org/spam:v0.2",
		},
		{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceType": "purl",
			"referenceLocator": "registry.redhat.io/ubi7:latest@sha256:abc",
		},
		{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceType": "purl",
			"referenceLocator": "quay.io/konflux-ci/bazel6-ubi9:latest@sha256:bcd",
		},
	]}]},
}}

_cyclonedx_sbom_attestation := {"statement": {
	"predicateType": "https://cyclonedx.org/bom",
	"predicate": {"components": [
		{"purl": "oci://example.com/org/spam:v0.2"},
		{"purl": "registry.redhat.io/ubi7:latest@sha256:abc"},
		{"purl": "quay.io/konflux-ci/bazel6-ubi9:latest@sha256:bcd"},
	]},
}}
