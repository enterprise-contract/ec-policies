package policy.release.buildah_build_task

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

test_good_dockerfile_param if {
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "./Dockerfile"}})
	lib.assert_empty(deny) with input.attestations as [attestation]
}

test_dockerfile_param_https_source if {
	expected := {{
		"code": "buildah_build_task.dockerfile_param_external_source",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "DOCKERFILE param value (https://Dockerfile) is an external source",
	}}
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "https://Dockerfile"}})
	lib.assert_equal(expected, deny) with input.attestations as [attestation]
}

test_dockerfile_param_http_source if {
	expected := {{
		"code": "buildah_build_task.dockerfile_param_external_source",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "DOCKERFILE param value (http://Dockerfile) is an external source",
	}}
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "http://Dockerfile"}})
	lib.assert_equal(expected, deny) with input.attestations as [attestation]
}

test_dockerfile_param_not_included if {
	expected := {{
		"code": "buildah_build_task.dockerfile_param_not_included",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "DOCKERFILE param is not included in the task",
	}}
	lib.assert_equal(expected, deny) with input.attestations as [_attestation("buildah", {})]
}

test_task_not_named_buildah if {
	lib.assert_empty(deny) with input.attestations as [_attestation("java", {})]
}

test_missing_pipeline_run_attestations if {
	attestation := {"predicate": {"buildType": "something/else"}}
	lib.assert_empty(deny) with input.attestations as [attestation]
}

_attestation(task_name, params) = attestation if {
	attestation := {"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [{
			"name": "ignored",
			"ref": {"kind": "Task", "name": task_name, "bundle": _bundle},
			"invocation": params,
		}]},
	}}
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
