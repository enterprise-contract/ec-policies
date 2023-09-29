package policy.release.attestation_task_bundle_test

import future.keywords.in

import data.lib
import data.policy.release.attestation_task_bundle
import data.lib.tkn_test
import data.lib_test

mock_data(task) := {"statement": {"predicate": {
	"buildConfig": {"tasks": [task]},
	"buildType": lib.tekton_pipeline_run,
}}}

test_bundle_not_exists {
	name := "my-task"
	attestations := [
		mock_data({
			"name": name,
			"ref": {"name": "my-task"},
		}),
		lib_test.mock_slsav1_attestation(
			[tkn_test.slsav1_task("my-task")]
		)
	]

	expected_msg := "Pipeline task 'my-task' does not contain a bundle reference"
	lib.assert_equal_results(attestation_task_bundle.deny, {{
		"code": "attestation_task_bundle.tasks_defined_in_bundle",
		"msg": expected_msg,
	}}) with input.attestations as attestations with data["task-bundles"] as task_bundles

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
}

test_bundle_not_exists_empty_string {
	name := "my-task"
	image := ""

	attestations := [
		mock_data({
			"name": name,
			"ref": {"name": "my-task", "bundle": image},
		}),
		lib_test.mock_slsav1_attestation([tkn_test.slsav1_task_bundle("my-task", image)])
	]

	expected_msg := sprintf("Pipeline task '%s' uses an empty bundle image reference", [name])
	lib.assert_equal_results(attestation_task_bundle.deny, {{
		"code": "attestation_task_bundle.task_ref_bundles_not_empty",
		"msg": expected_msg,
	}}) with input.attestations as attestations with data["task-bundles"] as task_bundles

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
}

test_bundle_unpinned {
	name := "my-task"
	image := "reg.com/repo:latest"
	attestations := [
		mock_data({
			"name": name,
			"ref": {
				"name": "my-task",
				"bundle": image,
			},
		}),
		lib_test.mock_slsav1_attestation([tkn_test.slsav1_task_bundle("my-task", image)])
	]

	expected_msg := sprintf("Pipeline task '%s' uses an unpinned task bundle reference '%s'", [name, image])
	lib.assert_equal_results(attestation_task_bundle.warn, {{
		"code": "attestation_task_bundle.task_ref_bundles_pinned",
		"msg": expected_msg,
	}}) with input.attestations as attestations
}

test_bundle_reference_valid {
	name := "my-task"
	image := "quay.io/redhat-appstudio/hacbs-templates-bundle:latest@sha256:abc"
	attestations := [
		mock_data({
			"name": name,
			"ref": {
				"name": "my-task",
				"bundle": image,
			},
		}),
		lib_test.mock_slsav1_attestation([tkn_test.slsav1_task_bundle("my-task", image)])
	]

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
	lib.assert_empty(attestation_task_bundle.deny) with input.attestations as attestations with data["task-bundles"] as task_bundles
}

# All good when the most recent bundle is used.
test_acceptable_bundle_up_to_date {
	image := "reg.com/repo@sha256:abc"
	attestations := [
		lib_test.mock_slsav02_attestation_bundles([image]),
		lib_test.mock_slsav1_attestation([tkn_test.slsav1_task_bundle("my-task", image)])
	]

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_empty(attestation_task_bundle.deny) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

# Warn about out of date bundles that are still acceptable.
test_acceptable_bundle_out_of_date_past {
	images := ["reg.com/repo@sha256:bcd", "reg.com/repo@sha256:cde"]
	attestations := [
		lib_test.mock_slsav02_attestation_bundles(images),
		lib_test.mock_slsav1_attestation_bundles(images),
	]

	lib.assert_equal_results(attestation_task_bundle.warn, {
		{
			"code": "attestation_task_bundle.task_ref_bundles_current",
			"msg": "Pipeline task 'my-task' uses an out of date task bundle 'reg.com/repo@sha256:bcd'",
		},
		{
			"code": "attestation_task_bundle.task_ref_bundles_current",
			"msg": "Pipeline task 'my-task' uses an out of date task bundle 'reg.com/repo@sha256:cde'",
		},
	}) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_empty(attestation_task_bundle.deny) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

# Deny bundles that are no longer active.
test_acceptable_bundle_expired {
	image := ["reg.com/repo@sha256:def"]
	attestations := [
		lib_test.mock_slsav02_attestation_bundles(image),
		lib_test.mock_slsav1_attestation_bundles(image),
	]
	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_equal_results(attestation_task_bundle.deny, {{
		"code": "attestation_task_bundle.task_ref_bundles_acceptable",
		"msg": "Pipeline task 'my-task' uses an unacceptable task bundle 'reg.com/repo@sha256:def'",
	}}) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

test_acceptable_bundles_provided {
	expected := {{
		"code": "attestation_task_bundle.acceptable_bundles_provided",
		"msg": "Missing required task-bundles data",
	}}
	lib.assert_equal_results(expected, attestation_task_bundle.deny) with data["task-bundles"] as []
}

mock_attestation(bundles) := a {
	tasks := [task |
		some index, bundle in bundles
		task := {
			"name": sprintf("task-run-%d", [index]),
			"ref": {
				"name": "my-task",
				"bundle": bundle,
			},
		}
	]

	a := [{"statement": {"predicate": {
		"buildConfig": {"tasks": tasks},
		"buildType": lib.tekton_pipeline_run,
	}}}]
}

task_bundles := {"reg.com/repo": [
	{
		# Latest bundle, allowed
		"digest": "sha256:abc",
		"tag": "",
		"effective_on": "2262-04-11T00:00:00Z",
	},
	{
		# Recent bundle effective in the future, allowed but attestation_task_bundle.warn to upgrade
		"digest": "sha256:bcd",
		"tag": "",
		"effective_on": "2262-03-11T00:00:00Z",
	},
	{
		# Recent bundle effective in the past, allowed but attestation_task_bundle.warn to upgrade
		"digest": "sha256:cde",
		"tag": "",
		"effective_on": "2022-02-01T00:00:00Z",
	},
	{
		# Old bundle, denied
		"digest": "sha256:def",
		"tag": "",
		"effective_on": "2021-01-01T00:00:00Z",
	},
]}
