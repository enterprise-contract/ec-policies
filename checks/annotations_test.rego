package checks

import data.lib

opa_inspect_valid := {
	"namespaces": {
		"data.policy.release.attestation_task_bundle": ["policy/release/attestation_task_bundle.rego"],
		"data.policy.release.attestation_type": ["policy/release/attestation_type.rego"],
	},
	"annotations": [
		{
			"annotations": {
				"description": "Check if the Tekton Bundle used for the Tasks in the Pipeline definition is pinned to a digest.",
				"scope": "rule",
				"title": "Task bundle references pinned to digest",
				"custom": {
					"depends_on": ["attestation_type.known_attestation_type"],
					"failure_msg": "Pipeline task '%s' uses an unpinned task bundle reference '%s'",
					"short_name": "task_ref_bundles_pinned",
					"solution": "Specify the task bundle reference with a full digest rather than a tag.",
				},
			},
			"location": {
				"file": "policy/release/attestation_task_bundle.rego",
				"row": 71,
				"col": 1,
			},
		},
		{
			"annotations": {
				"custom": {
					"collections": ["minimal"],
					"depends_on": ["attestation_type.pipelinerun_attestation_found"],
					"failure_msg": "Unknown attestation type '%s'",
					"short_name": "known_attestation_type",
					"solution": "Make sure the \"_type\" field in the attestation is supported. Supported types are configured in xref:ec-cli:ROOT:configuration.adoc#_data_sources[data sources].",
				},
				"description": "A sanity check to confirm the attestation found for the image has a known attestation type.",
				"scope": "rule",
				"title": "Known attestation type found",
			},
			"location": {
				"file": "policy/release/attestation_type.rego",
				"row": 30,
				"col": 1,
			},
		},
		{
			"annotations": {
				"custom": {
					"collections": ["minimal"],
					"failure_msg": "Missing pipelinerun attestation",
					"short_name": "pipelinerun_attestation_found",
					"solution": "Make sure the attestation being verified was generated from a Tekton pipelineRun.",
				},
				"description": "At least one PipelineRun attestation must be present.",
				"scope": "rule",
				"title": "PipelineRun attestation found",
			},
			"location": {
				"file": "policy/release/attestation_type.rego",
				"row": 49,
				"col": 1,
			},
		},
	],
}

test_required_annotations_valid {
	lib.assert_empty(violation) with input as opa_inspect_valid
}

opa_inspect_missing_annotations := {
	"namespaces": {"data.policy.release.attestation_task_bundle": [
		"policy/release/attestation_task_bundle.rego",
		"policy/release/attestation_task_bundle_test.rego",
	]},
	"annotations": [{
		"annotations": {
			"scope": "rule",
			"description": "Check for existence of a task bundle. Enforcing this rule will\nfail the contract if the task is not called from a bundle.",
			"custom": {
				"flagiure_msg": "Task '%s' does not contain a bundle reference",
				"short_name": "disallowed_task_reference",
			},
		},
		"location": {
			"file": "policy/release/attestation_task_bundle.rego",
			"row": 13,
			"col": 1,
		},
	}],
}

opa_inspect_missing_dependency := {
	"namespaces": {"data.policy.release.attestation_task_bundle": [
		"policy/release/attestation_task_bundle.rego",
		"policy/release/attestation_task_bundle_test.rego",
	]},
	"annotations": [{
		"annotations": {
			"description": "Check if the Tekton Bundle used for the Tasks in the Pipeline definition is pinned to a digest.",
			"scope": "rule",
			"title": "Task bundle references pinned to digest",
			"custom": {
				"depends_on": ["attestation_type.known_attestation_type"],
				"failure_msg": "Pipeline task '%s' uses an unpinned task bundle reference '%s'",
				"short_name": "task_ref_bundles_pinned",
				"solution": "Specify the task bundle reference with a full digest rather than a tag.",
			},
		},
		"location": {
			"file": "policy/release/attestation_task_bundle.rego",
			"row": 71,
			"col": 1,
		},
	}],
}

test_required_annotations_invalid {
	lib.assert_equal({"ERROR: Missing annotation(s) custom.failure_msg, title at policy/release/attestation_task_bundle.rego:13"}, violation) with input as opa_inspect_missing_annotations
}

test_missing_dependency_invalid {
	lib.assert_equal({"ERROR: Missing dependency rule \"data.policy.release.attestation_type.known_attestation_type\" at policy/release/attestation_task_bundle.rego:71"}, violation) with input as opa_inspect_missing_dependency
}
