package policy.release.trusted_artifacts_test

import future.keywords.if

import data.lib
import data.policy.release.trusted_artifacts

test_happy_day_chain if {
	lib.assert_empty(trusted_artifacts.deny) with data["task-bundles"] as trusted_bundles
		with input.attestations as [attestation]
}

test_tampering if {
	evil_attestation := json.patch(attestation, [{
		"op": "replace",
		"path": "/statement/predicate/buildConfig/tasks/1/ref/bundle",
		"value": "registry.io/evil/bundle@sha256:cde",
	}])

	lib.assert_equal_results(trusted_artifacts.deny, {{
		"code": "trusted_artifacts.valid_trusted_artifact_chain",
		# regal ignore:line-length
		"msg": `Code tampering detected, unacceptable task "task_b" was included in build chain comprised of: task_a, task_b, task_c`,
		"term": "task_b",
	}}) with data["task-bundles"] as trusted_bundles
		with input.attestations as [evil_attestation]
}

test_tampered_inputs if {
	evil_attestation := json.patch(attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/1/invocation/parameters/F_ARTIFACT",
		"value": "file:sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}])

	lib.assert_equal_results(trusted_artifacts.deny, {{
		"code": "trusted_artifacts.valid_trusted_artifact_inputs",
		# regal ignore:line-length
		"msg": `Code tampering detected, input "file:sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" for task "task_b" was not produced by the pipeline as attested.`,
		"term": "file:sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}}) with data["task-bundles"] as trusted_bundles
		with input.attestations as [evil_attestation]
}

test_artifact_chain if {
	expected := {attestation: {
		"task_a": {"task_b", "task_c"},
		"task_b": {"task_c"},
		"task_c": set(),
	}}

	lib.assert_equal(trusted_artifacts._artifact_chain, expected) with input.attestations as [attestation]
}

test_inputs_from_parameters if {
	task := {"invocation": {"parameters": {
		"param1": "value1",
		"SOME_ARTIFACT": "value2",
		"SOURCE_ARTIFACT": artifact_a,
		"UNEXPECTED_ARTIFACT": "file:sha256-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}}}

	lib.assert_equal(trusted_artifacts._inputs(task), {artifact_a})
}

test_outputs_from_results if {
	task := {"results": [
		{
			"name": "result1",
			"value": "value1",
			"type": "string",
		},
		{
			"name": "SOME_ARTIFACT",
			"value": "value2",
			"type": "string",
		},
		{
			"name": "SOURCE_ARTIFACT",
			"value": artifact_a,
			"type": "string",
		},
		{
			"name": "UNEXPECTED1_ARTIFACT",
			"value": "file:sha256-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			"type": "string",
		},
		{
			"name": "UNEXPECTED2_ARTIFACT",
			"value": artifact_a,
			"type": "array",
		},
	]}

	lib.assert_equal(
		trusted_artifacts._outputs(task),
		{artifact_a},
	)
}

artifact_a := "file:sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

artifact_b := "file:sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

artifact_c := "file:sha256-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

artifact_d := "file:sha256-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

trusted_bundle := "registry.io/trusted/bundle@sha256:abc"

task_a := {
	"metadata": {"labels": {"tekton.dev/pipelineTask": "task_a"}},
	"invocation": {"parameters": {"B_ARTIFACT": artifact_b, "D_ARTIFACT": artifact_d}},
	"results": [
		{
			"name": "IMAGE_URL",
			"value": "registry.io/repository/image",
			"type": "string",
		},
		{
			"name": "IMAGE_DIGEST",
			"value": "sha256-ghi",
			"type": "string",
		},
	],
	"ref": {"name": "TaskA", "kind": "Task", "bundle": trusted_bundle},
}

task_b := {
	"metadata": {"labels": {"tekton.dev/pipelineTask": "task_b"}},
	"invocation": {"parameters": {"C_ARTIFACT": artifact_c}},
	"results": [{
		"name": "B_ARTIFACT",
		"value": artifact_b,
		"type": "string",
	}],
	"ref": {"name": "TaskB", "kind": "Task", "bundle": trusted_bundle},
}

task_c := {
	"metadata": {"labels": {"tekton.dev/pipelineTask": "task_c"}},
	"results": [
		{
			"name": "C_ARTIFACT",
			"value": artifact_c,
			"type": "string",
		},
		{
			"name": "D_ARTIFACT",
			"value": artifact_d,
			"type": "string",
		},
	],
	"ref": {"name": "TaskC", "kind": "Task", "bundle": trusted_bundle},
}

attestation := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [task_a, task_b, task_c]},
}}}

trusted_bundles := {"registry.io/trusted/bundle": [{
	"digest": "sha256:abc",
	"tag": "1.0",
	"effective_on": "2000-01-01T00:00:00Z",
}]}
