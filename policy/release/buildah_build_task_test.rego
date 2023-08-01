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
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (https://Dockerfile) is an external source",
	}}
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "https://Dockerfile"}})
	lib.assert_equal_results(expected, deny) with input.attestations as [attestation]
}

test_dockerfile_param_http_source if {
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (http://Dockerfile) is an external source",
	}}
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "http://Dockerfile"}})
	lib.assert_equal_results(expected, deny) with input.attestations as [attestation]
}

test_buildah_task_has_dockerfile_param if {
	expected := {{
		"code": "buildah_build_task.buildah_task_has_dockerfile_param",
		"msg": "The DOCKERFILE param was not included in the buildah task(s): \"ignored\"",
		"term": "ignored",
	}}
	lib.assert_equal_results(expected, deny) with input.attestations as [_attestation("buildah", {})]
}

test_task_not_named_buildah if {
	lib.assert_empty(deny) with input.attestations as [_attestation("java", {})]
}

test_missing_pipeline_run_attestations if {
	attestation := {"statement": {"predicate": {"buildType": "something/else"}}}
	lib.assert_empty(deny) with input.attestations as [attestation]
}

test_multiple_buildah_tasks if {
	attestation := {"statement": {"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [
			{
				"name": "b1",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"invocation": {"parameters": {"DOCKERFILE": "one/Dockerfile"}},
			},
			{
				"name": "b2",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"invocation": {"parameters": {"DOCKERFILE": "two/Dockerfile"}},
			},
		]},
	}}}
	lib.assert_empty(deny) with input.attestations as [attestation]
}

test_multiple_buildah_tasks_one_without_params if {
	attestation := {"statement": {"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [
			{
				"name": "b1",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"invocation": {"parameters": {"DOCKERFILE": "one/Dockerfile"}},
			},
			{
				"name": "b2",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
			},
		]},
	}}}
	expected := {{
		"code": "buildah_build_task.buildah_task_has_dockerfile_param",
		"msg": "The DOCKERFILE param was not included in the buildah task(s): \"b2\"",
		"term": "b2",
	}}
	lib.assert_equal_results(expected, deny) with input.attestations as [attestation]
}

test_multiple_buildah_tasks_all_without_params if {
	attestation := {"statement": {"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [
			{
				"name": "b1",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"invocation": {"parameters": {}},
			},
			{
				"name": "b2",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
			},
		]},
	}}}
	expected := {
		{
			"code": "buildah_build_task.buildah_task_has_dockerfile_param",
			"msg": "The DOCKERFILE param was not included in the buildah task(s): \"b1\"",
			"term": "b1",
		},
		{
			"code": "buildah_build_task.buildah_task_has_dockerfile_param",
			"msg": "The DOCKERFILE param was not included in the buildah task(s): \"b2\"",
			"term": "b2",
		},
	}
	lib.assert_equal_results(expected, deny) with input.attestations as [attestation]
}

test_multiple_buildah_tasks_one_with_external_dockerfile if {
	attestation := {"statement": {"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [
			{
				"name": "b1",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"invocation": {"parameters": {"DOCKERFILE": "one/Dockerfile"}},
			},
			{
				"name": "b2",
				"invocation": {"parameters": {"DOCKERFILE": "http://Dockerfile"}},
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
			},
		]},
	}}}
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (http://Dockerfile) is an external source",
	}}
	lib.assert_equal_results(expected, deny) with input.attestations as [attestation]
}

_attestation(task_name, params) = attestation if {
	attestation := {"statement": {"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [{
			"name": "ignored",
			"ref": {"kind": "Task", "name": task_name, "bundle": _bundle},
			"invocation": params,
		}]},
	}}}
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
