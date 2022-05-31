package checks

import data.lib

opa_inspect_valid := {
	"namespaces": {"data.policies.release.attestation_task_bundle": [
		"policies/release/attestation_task_bundle.rego",
		"policies/release/attestation_task_bundle_test.rego",
	]},
	"annotations": [{
		"location": {
			"file": "policies/release/attestation_task_bundle.rego",
			"row": 13,
			"col": 1,
		},
		"annotations": {
			"scope": "rule",
			"title": "Task bundle was not used or is not defined",
			"description": "Check for existence of a task bundle. Enforcing this rule will\nfail the contract if the task is not called from a bundle.",
			"custom": {
				"failure_msg": "Task '%s' does not contain a bundle reference",
				"short_name": "disallowed_task_reference",
			},
		},
	}],
}

test_required_annotations_valid {
	lib.assert_empty(violation) with input as opa_inspect_valid
}

opa_inspect_invalid := {
	"namespaces": {"data.policies.release.attestation_task_bundle": [
		"policies/release/attestation_task_bundle.rego",
		"policies/release/attestation_task_bundle_test.rego",
	]},
	"annotations": [{
		"location": {
			"file": "policies/release/attestation_task_bundle.rego",
			"row": 13,
			"col": 1,
		},
		"annotations": {
			"scope": "rule",
			"description": "Check for existence of a task bundle. Enforcing this rule will\nfail the contract if the task is not called from a bundle.",
			"custom": {
				"flagiure_msg": "Task '%s' does not contain a bundle reference",
				"short_name": "disallowed_task_reference",
			},
		},
	}],
}

test_required_annotations_invalid {
	lib.assert_equal({"ERROR: Missing annotation(s) custom.failure_msg, title at policies/release/attestation_task_bundle.rego:13"}, violation) with input as opa_inspect_invalid
}
