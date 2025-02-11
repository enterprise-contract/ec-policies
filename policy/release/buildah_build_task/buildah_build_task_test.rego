package buildah_build_task_test

import rego.v1

import data.buildah_build_task
import data.lib
import data.lib.tekton_test

test_good_dockerfile_param if {
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "./Dockerfile"}}, _results)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation]
	slsav1_attestation := _slsav1_attestation("buildah", [{"name": "DOCKERFILE", "value": "./Dockerfile"}], _results)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

# regal ignore:rule-length
test_buildah_tasks if {
	tasks := [
		{
			"name": "pipelineTask",
			"content": base64.encode(json.marshal(tekton_test.slsav1_attestation_local_spec)),
		},
		{
			"name": "pipelineTask",
			"content": base64.encode(json.marshal(tekton_test.slsav1_attestation_local_spec)),
		},
	]
	slsav1_attestation := json.patch(
		_slsav1_attestation(
			"buildah", [{
				"name": "DOCKERFILE",
				"value": "./Dockerfile",
			}],
			_results,
		),
		[{
			"op": "add",
			"path": "/statement/predicate/buildDefinition/resolvedDependencies",
			"value": tasks,
		}],
	)

	expected := {{
		"params": [
			{"name": "IMAGE", "value": "quay.io/jstuart/hacbs-docker-build"},
			{"name": "DOCKERFILE", "value": "./image_with_labels/Dockerfile"},
		],
		"podTemplate": {
			"imagePullSecrets": [{"name": "docker-chains"}],
			"securityContext": {"fsGroup": 65532},
		},
		"results": _results,
		"serviceAccountName": "default", "taskRef": {
			"kind": "Task",
			"name": "buildah",
		},
		"timeout": "1h0m0s", "workspaces": [
			{"name": "source", "persistentVolumeClaim": {"claimName": "pvc-bf2ed289ae"}},
			{"name": "dockerconfig", "secret": {"secretName": "docker-credentials"}},
		],
	}}
	lib.assert_equal(expected, buildah_build_task._buildah_tasks) with input.attestations as [slsav1_attestation]
}

test_dockerfile_param_https_source if {
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (https://Dockerfile) is an external source",
	}}

	# attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "https://Dockerfile"}}, _results)
	# lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	slsav1_attestation := _slsav1_attestation("buildah", [{"name": "DOCKERFILE", "value": "https://Dockerfile"}], _results)
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

test_dockerfile_param_http_source if {
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (http://Dockerfile) is an external source",
	}}
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "http://Dockerfile"}}, _results)
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	slsav1_attestation := _slsav1_attestation("buildah", [{"name": "DOCKERFILE", "value": "http://Dockerfile"}], _results)
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

test_missing_pipeline_run_attestations if {
	attestation := {"statement": {"predicate": {"buildType": "something/else"}}}
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation]

	slsav1_attestation := {"statement": {"predicate": {"buildDefinition": {"buildType": "something/else"}}}}
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

# regal ignore:rule-length
test_multiple_buildah_tasks if {
	attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
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
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation]

	tasks := [
		{
			"name": "task",
			"content": base64.encode(json.marshal(json.patch(tekton_test.slsav1_attestation_local_spec, [{
				"op": "add",
				"path": "/taskRef/name",
				"value": "task1",
			}]))),
		},
		{
			"name": "pipelineTask",
			"content": base64.encode(json.marshal(json.patch(tekton_test.slsav1_attestation_local_spec, [{
				"op": "add",
				"path": "/taskRef/name",
				"value": "task1",
			}]))),
		},
		{
			"name": "pipeline",
			"content": base64.encode(json.marshal(json.patch(tekton_test.slsav1_attestation_local_spec, [{
				"op": "add",
				"path": "/taskRef/name",
				"value": "task1",
			}]))),
		},
	]
	slsav1_attestation := json.patch(_slsav1_attestation("buildah", [{}], _results), [{
		"op": "add",
		"path": "/statement/predicate/buildDefinition/resolvedDependencies",
		"value": tasks,
	}])
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

# regal ignore:rule-length
test_multiple_buildah_tasks_one_with_external_dockerfile if {
	attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [
			{
				"name": "b1",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"invocation": {"parameters": {"DOCKERFILE": "one/Dockerfile"}},
				"results": _results,
			},
			{
				"name": "b2",
				"invocation": {"parameters": {"DOCKERFILE": "http://Dockerfile"}},
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"results": _results,
			},
		]},
	}}}
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (http://Dockerfile) is an external source",
	}}
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	tasks := [
		{
			"name": "task",
			"content": base64.encode(json.marshal(json.patch(tekton_test.slsav1_attestation_local_spec, [{
				"op": "add",
				"path": "params",
				"value": [{"name": "DOCKERFILE", "value": "Dockerfile"}],
			}]))),
		},
		{
			"name": "pipelineTask",
			"content": base64.encode(json.marshal(json.patch(tekton_test.slsav1_attestation_local_spec, [{
				"op": "add",
				"path": "/params",
				"value": [{"name": "DOCKERFILE", "value": "http://Dockerfile"}],
			}]))),
		},
	]
	slsav1_attestation := json.patch(_slsav1_attestation("buildah", {}, _results), [{
		"op": "add",
		"path": "/statement/predicate/buildDefinition/resolvedDependencies",
		"value": tasks,
	}])

	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

test_add_capabilities_param if {
	expected := {{
		"code": "buildah_build_task.add_capabilities_param",
		"msg": "ADD_CAPABILITIES parameter is not allowed",
	}}

	attestation := _slsav1_attestation("buildah", [{"name": "ADD_CAPABILITIES", "value": "spam"}], _results)
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	attestation_spaces := _slsav1_attestation("buildah", [{"name": "ADD_CAPABILITIES", "value": "   "}], _results)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation_spaces]
}

test_platform_param if {
	expected := {{
		"code": "buildah_build_task.platform_param",
		"msg": "PLATFORM parameter value \"linux-root/arm64\" is disallowed by regex \".*root.*\"",
	}}

	attestations := [
		_slsav1_attestation("buildah", [{"name": "PLATFORM", "value": "linux-root/arm64"}], _results),
		_slsav1_attestation("buildah", [{"name": "PLATFORM", "value": "linux/arm64"}], _results),
	]

	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as attestations
		with data.rule_data.disallowed_platform_patterns as [".*root.*"]
}

test_plat_patterns_rule_data_validation if {
	d := {"disallowed_platform_patterns": [
		# Wrong type and invalid regex
		1,
		# Duplicated items
		".*foo",
		".*foo",
		# Invalid regex in rego
		"(?=a)?b",
	]}

	expected := {
		{
			"code": "buildah_build_task.disallowed_platform_patterns_pattern",
			# regal ignore:line-length
			"msg": "Rule data disallowed_platform_patterns has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "buildah_build_task.disallowed_platform_patterns_pattern",
			"msg": "'\\x01' is not a valid regular expression in rego",
			"severity": "failure",
		},
		{
			"code": "buildah_build_task.disallowed_platform_patterns_pattern",
			"msg": "Rule data disallowed_platform_patterns has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "buildah_build_task.disallowed_platform_patterns_pattern",
			"msg": "\"(?=a)?b\" is not a valid regular expression in rego",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(buildah_build_task.deny, expected) with data.rule_data as d
}

test_privileged_nested_param if {
	expected := {{
		"code": "buildah_build_task.privileged_nested_param",
		"msg": "setting PRIVILEGED_NESTED parameter to true is not allowed",
	}}

	attestation := _slsav1_attestation("buildah", [{"name": "PRIVILEGED_NESTED", "value": "true"}], _results)
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	attestation_empty := _slsav1_attestation("buildah", [{"name": "PRIVILEGED_NESTED", "value": ""}], _results)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation_empty]

	attestation_false := _slsav1_attestation("buildah", [{"name": "PRIVILEGED_NESTED", "value": "false"}], _results)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation_false]
}

_attestation(task_name, params, results) := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [{
		"name": task_name,
		"ref": {"kind": "Task", "name": task_name, "bundle": _bundle},
		"invocation": params,
		"results": results,
	}]},
}}}

_slsav1_attestation(task_name, params, results) := attestation if {
	content := base64.encode(json.marshal(json.patch(tekton_test.slsav1_task(task_name), [
		{
			"op": "replace",
			"path": "/spec/params",
			"value": params,
		},
		{
			"op": "add",
			"path": "/status/taskResults",
			"value": results,
		},
	])))
	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			"resolvedDependencies": [{
				"name": "pipelineTask",
				"content": content,
			}],
		}},
	}}
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_results := [
	{
		"name": "IMAGE_DIGEST",
		"type": "string",
		"value": "sha256:hash",
	},
	{
		"name": "IMAGE_URL",
		"type": "string",
		"value": "quay.io/jstuart/hacbs-docker-build:tag@sha256:hash",
	},
]
