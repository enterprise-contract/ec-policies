package lib.bundles_test

import rego.v1

import data.lib
import data.lib.bundles

test_disallowed_task_reference if {
	tasks := [
		{"name": "my-task-1", "taskRef": {}},
		{"name": "my-task-2", "ref": {}},
	]

	expected := lib.to_set(tasks)
	lib.assert_equal(bundles.disallowed_task_reference(tasks), expected)
}

test_empty_task_bundle_reference if {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": ""}},
		{"name": "my-task-2", "ref": {"bundle": ""}},
	]

	expected := lib.to_set(tasks)
	lib.assert_equal(bundles.empty_task_bundle_reference(tasks), expected)
}

test_unpinned_task_bundle if {
	tasks := [
		{
			"name": "my-task-1",
			"taskRef": {"bundle": "reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5"},
		},
		{
			"name": "my-task-2",
			"ref": {"bundle": "reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5"},
		},
	]

	expected := lib.to_set(tasks)
	lib.assert_equal(bundles.unpinned_task_bundle(tasks), expected) with data["task-bundles"] as []
}
