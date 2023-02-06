package policy.release.attestation_task_bundle

import data.lib

mock_data(task) = d {
	d := [{"predicate": {
		"buildConfig": {"tasks": [task]},
		"buildType": lib.pipelinerun_att_build_types[0],
	}}]
}

test_bundle_not_exists {
	name := "my-task"
	d := mock_data({
		"name": name,
		"ref": {"name": "good-task"},
	})

	expected_msg := "Pipeline task 'my-task' does not contain a bundle reference"
	lib.assert_equal(deny, {{
		"code": "attestation_task_bundle.disallowed_task_reference",
		"collections": ["minimal"],
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as d with data["task-bundles"] as task_bundles

	lib.assert_empty(warn) with input.attestations as d
}

test_bundle_not_exists_empty_string {
	name := "my-task"
	image := ""
	d := mock_data({
		"name": name,
		"ref": {"name": "good-task", "bundle": image},
	})

	expected_msg := sprintf("Pipeline task '%s' uses an empty bundle image reference", [name])
	lib.assert_equal(deny, {{
		"code": "attestation_task_bundle.empty_task_bundle_reference",
		"collections": ["minimal"],
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as d with data["task-bundles"] as task_bundles

	lib.assert_empty(warn) with input.attestations as d
}

test_bundle_unpinned {
	name := "my-task"
	image := "reg.com/repo:latest"
	d := mock_data({
		"name": name,
		"ref": {
			"name": "good-task",
			"bundle": image,
		},
	})

	expected_msg := sprintf("Pipeline task '%s' uses an unpinned task bundle reference '%s'", [name, image])
	lib.assert_equal(warn, {{
		"code": "attestation_task_bundle.unpinned_task_bundle",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as d
}

test_bundle_reference_valid {
	name := "my-task"
	image := "quay.io/redhat-appstudio/hacbs-templates-bundle:latest@sha256:abc"
	d := mock_data({
		"name": name,
		"ref": {
			"name": "good-task",
			"bundle": image,
		},
	})

	lib.assert_empty(warn) with input.attestations as d
	lib.assert_empty(deny) with input.attestations as d with data["task-bundles"] as task_bundles
}

# All good when the most recent bundle is used.
test_acceptable_bundle_up_to_date {
	attestations := mock_attestation(["reg.com/repo@sha256:abc"])

	lib.assert_empty(warn) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_empty(deny) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

# Warn about out of date bundles that are still acceptable.
test_acceptable_bundle_out_of_date_past {
	attestations := mock_attestation(["reg.com/repo@sha256:bcd", "reg.com/repo@sha256:cde"])

	lib.assert_equal(warn, {
		{
			"code": "attestation_task_bundle.out_of_date_task_bundle",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Pipeline task 'task-run-0' uses an out of date task bundle 'reg.com/repo@sha256:bcd'",
		},
		{
			"code": "attestation_task_bundle.out_of_date_task_bundle",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Pipeline task 'task-run-1' uses an out of date task bundle 'reg.com/repo@sha256:cde'",
		},
	}) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_empty(deny) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

# Deny bundles that are no longer active.
test_acceptable_bundle_expired {
	attestations := mock_attestation(["reg.com/repo@sha256:def"])
	lib.assert_empty(warn) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_equal(deny, {{
		"code": "attestation_task_bundle.unacceptable_task_bundle",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Pipeline task 'task-run-0' uses an unacceptable task bundle 'reg.com/repo@sha256:def'",
	}}) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

test_missing_required_data {
	expected := {{
		"code": "attestation_task_bundle.missing_required_data",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Missing required task-bundles data",
	}}
	lib.assert_equal(expected, deny) with data["task-bundles"] as []
}

mock_attestation(bundles) = a {
	tasks := [task |
		bundle := bundles[index]
		task := {
			"name": sprintf("task-run-%d", [index]),
			"ref": {
				"name": "my-task",
				"bundle": bundle,
			},
		}
	]

	a := [{"predicate": {
		"buildConfig": {"tasks": tasks},
		"buildType": lib.pipelinerun_att_build_types[0],
	}}]
}

task_bundles = {"reg.com/repo": [
	{
		# Latest bundle, allowed
		"digest": "sha256:abc",
		"tag": "",
		"effective_on": "2262-04-11T00:00:00Z",
	},
	{
		# Recent bundle effective in the future, allowed but warn to upgrade
		"digest": "sha256:bcd",
		"tag": "",
		"effective_on": "2262-03-11T00:00:00Z",
	},
	{
		# Recent bundle effective in the past, allowed but warn to upgrade
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
