package policy.pipeline.task_bundle

import data.lib

test_bundle_not_exists {
	tasks := [{"name": "my-task", "taskRef": {}}]

	expected_msg := "Pipeline task 'my-task' does not contain a bundle reference"
	lib.assert_equal_results(deny, {{
		"code": "task_bundle.disallowed_task_reference",
		"msg": expected_msg,
	}}) with input.spec.tasks as tasks with data["task-bundles"] as task_bundles

	lib.assert_empty(warn) with input.spec.tasks as tasks
}

test_bundle_not_exists_empty_string {
	tasks := [{"name": "my-task", "taskRef": {"bundle": ""}}]

	expected_msg := "Pipeline task 'my-task' uses an empty bundle image reference"
	lib.assert_equal_results(deny, {{
		"code": "task_bundle.empty_task_bundle_reference",
		"msg": expected_msg,
	}}) with input.spec.tasks as tasks with data["task-bundles"] as task_bundles

	lib.assert_empty(warn) with input.spec.tasks as tasks
}

test_bundle_unpinned {
	tasks := [{
		"name": "my-task",
		"taskRef": {"bundle": "reg.com/repo:latest"},
	}]

	lib.assert_equal_results(warn, {{
		"code": "task_bundle.unpinned_task_bundle",
		"msg": "Pipeline task 'my-task' uses an unpinned task bundle reference 'reg.com/repo:latest'",
	}}) with input.spec.tasks as tasks
}

test_bundle_reference_valid {
	tasks := [{
		"name": "my-task",
		"taskRef": {"bundle": "quay.io/redhat-appstudio/hacbs-templates-bundle:latest@sha256:abc"},
	}]

	lib.assert_empty(deny) with input.spec.tasks as tasks with data["task-bundles"] as task_bundles
	lib.assert_empty(warn) with input.spec.tasks as tasks with data["task-bundles"] as task_bundles
}

# All good when the most recent bundle is used.
test_acceptable_bundle_up_to_date {
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo@sha256:abc"}}]

	lib.assert_empty(warn) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles

	lib.assert_empty(deny) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles
}

# Warn about out of date bundles that are still acceptable.
test_acceptable_bundle_out_of_date_past {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": "reg.com/repo@sha256:bcd"}},
		{"name": "my-task-2", "taskRef": {"bundle": "reg.com/repo@sha256:cde"}},
	]

	lib.assert_equal_results(warn, {
		{
			"code": "task_bundle.out_of_date_task_bundle",
			"msg": "Pipeline task 'my-task-1' uses an out of date task bundle 'reg.com/repo@sha256:bcd'",
		},
		{
			"code": "task_bundle.out_of_date_task_bundle",
			"msg": "Pipeline task 'my-task-2' uses an out of date task bundle 'reg.com/repo@sha256:cde'",
		},
	}) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles

	lib.assert_empty(deny) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles
}

# Deny bundles that are no longer active.
test_acceptable_bundle_expired {
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo@sha256:def"}}]

	lib.assert_empty(warn) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles

	lib.assert_equal_results(deny, {{
		"code": "task_bundle.unacceptable_task_bundle",
		"msg": "Pipeline task 'my-task' uses an unacceptable task bundle 'reg.com/repo@sha256:def'",
	}}) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles
}

test_missing_required_data {
	expected := {{
		"code": "task_bundle.missing_required_data",
		"msg": "Missing required task-bundles data",
	}}
	lib.assert_equal_results(expected, deny) with data["task-bundles"] as []
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
