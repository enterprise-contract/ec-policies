package policy.release.buildah_build_task

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

test_good_dockerfile_param if {
	expected := {{}}
	lib.assert_equal(set(), deny) with input.attestations as [_attestation({"parameters": {"DOCKERFILE": "./Dockerfile"}})]
}

test_dockerfile_param_https_source if {
	expected := {{
		"code": "dockerfile_param_external_source",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "DOCKERFILE param value (https://Dockerfile) is an external source",
	}}
	lib.assert_equal(expected, deny) with input.attestations as [_attestation({"parameters": {"DOCKERFILE": "https://Dockerfile"}})]
}

test_dockerfile_param_http_source if {
	expected := {{
		"code": "dockerfile_param_external_source",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "DOCKERFILE param value (http://Dockerfile) is an external source",
	}}
	lib.assert_equal(expected, deny) with input.attestations as [_attestation({"parameters": {"DOCKERFILE": "http://Dockerfile"}})]
}

test_dockerfile_param_not_included if {
	expected := {{
		"code": "dockerfile_param_not_included",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "DOCKERFILE param is not included in the task",
	}}
	lib.assert_equal(expected, deny) with input.attestations as [_attestation({})]
}

_attestation(params) = attestation if {
	attestation := {"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [{
			"name": "buildah",
			"invocation": params,
		}]},
	}}
}
