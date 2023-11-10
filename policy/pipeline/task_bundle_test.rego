package policy.pipeline.task_bundle_test

import data.lib
import data.policy.pipeline.task_bundle
import future.keywords.if

test_bundle_not_exists if {
	tasks := [{"name": "my-task", "taskRef": {}}]

	expected_msg := "Pipeline task 'my-task' does not contain a bundle reference"
	lib.assert_equal_results(task_bundle.deny, {{
		"code": "task_bundle.disallowed_task_reference",
		"msg": expected_msg,
	}}) with input.spec.tasks as tasks with data["task-bundles"] as task_bundles

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
}

test_bundle_not_exists_empty_string if {
	tasks := [{"name": "my-task", "taskRef": {"bundle": ""}}]

	expected_msg := "Pipeline task 'my-task' uses an empty bundle image reference"
	lib.assert_equal_results(task_bundle.deny, {{
		"code": "task_bundle.empty_task_bundle_reference",
		"msg": expected_msg,
	}}) with input.spec.tasks as tasks with data["task-bundles"] as task_bundles

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
}

test_bundle_unpinned if {
	tasks := [{
		"name": "my-task",
		"taskRef": {"bundle": "reg.com/repo:latest"},
	}]

	lib.assert_equal_results(task_bundle.warn, {{
		"code": "task_bundle.unpinned_task_bundle",
		"msg": "Pipeline task 'my-task' uses an unpinned task bundle reference 'reg.com/repo:latest'",
	}}) with input.spec.tasks as tasks with data["task-bundles"] as []
}

test_bundle_reference_valid if {
	tasks := [{
		"name": "my-task",
		"taskRef": {"bundle": "reg.com/repo:latest@sha256:abc"},
	}]

	lib.assert_empty(task_bundle.deny) with input.spec.tasks as tasks with data["task-bundles"] as task_bundles
	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks with data["task-bundles"] as task_bundles
}

# All good when the most recent bundle is used.
test_acceptable_bundle_up_to_date if {
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo@sha256:abc"}}]

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles

	lib.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles
}

# All good when the most recent bundle is used for a version that is still maintained
test_acceptable_bundle_up_to_date_maintained_version if {
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo@sha256:ghi"}}]

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles

	lib.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles
}

# Warn about out of date bundles that are still acceptable.
test_acceptable_bundle_out_of_date_past if {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": "reg.com/repo@sha256:bcd"}},
		{"name": "my-task-2", "taskRef": {"bundle": "reg.com/repo@sha256:cde"}},
	]

	lib.assert_equal_results(task_bundle.warn, {{
		"code": "task_bundle.out_of_date_task_bundle",
		"msg": "Pipeline task 'my-task-1' uses an out of date task bundle 'reg.com/repo@sha256:bcd'",
	}}) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2022-03-12T00:00:00Z")

	lib.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2022-03-12T00:00:00Z")
}

# Deny bundles that are no longer active.
test_acceptable_bundle_expired if {
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo@sha256:def"}}]

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles

	lib.assert_equal_results(task_bundle.deny, {{
		"code": "task_bundle.unacceptable_task_bundle",
		"msg": "Pipeline task 'my-task' uses an unacceptable task bundle 'reg.com/repo@sha256:def'",
	}}) with input.spec.tasks as tasks
		with data["task-bundles"] as task_bundles
}

test_missing_required_data if {
	expected := {{
		"code": "task_bundle.missing_required_data",
		"msg": "Missing required task-bundles data",
	}}
	lib.assert_equal_results(expected, task_bundle.deny) with data["task-bundles"] as []
}

task_bundles := {"reg.com/repo": [
	{
		# Latest v2
		"digest": "sha256:abc",
		"tag": "v2",
		"effective_on": "2022-04-11T00:00:00Z",
	},
	{
		# Latest v3
		"digest": "sha256:ghi",
		"tag": "v3",
		"effective_on": "2022-04-11T00:00:00Z",
	},
	{
		# Older v2
		"digest": "sha256:bcd",
		"tag": "v2",
		"effective_on": "2022-03-11T00:00:00Z",
	},
	{
		# Latest v1
		"digest": "sha256:cde",
		"tag": "v1",
		"effective_on": "2022-02-01T00:00:00Z",
	},
	{
		# Older v1
		"digest": "sha256:def",
		"tag": "v1",
		"effective_on": "2021-01-01T00:00:00Z",
	},
]}
