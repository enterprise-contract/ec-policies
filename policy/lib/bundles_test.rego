package lib.bundles

import data.lib

# used as reference bundle data in tests
bundle_data := {"registry.img/acceptable": [{
	"digest": "sha256:digest",
	"tag": "",
	"effective_on": "2000-01-01T00:00:00Z",
}]}

# used as reference bundle data in tests
acceptable_bundle_ref := "registry.img/acceptable@sha256:digest"

test_disallowed_task_reference {
	tasks := [
		{"name": "my-task-1", "taskRef": {}},
		{"name": "my-task-2", "ref": {}},
	]

	expected := {task | task := tasks[_]}
	lib.assert_equal(disallowed_task_reference(tasks), expected)
}

test_empty_task_bundle_reference {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": ""}},
		{"name": "my-task-2", "ref": {"bundle": ""}},
	]

	expected := {task | task := tasks[_]}
	lib.assert_equal(empty_task_bundle_reference(tasks), expected)
}

test_unpinned_task_bundle {
	tasks := [
		{
			"name": "my-task-1",
			"taskRef": {"bundle": "reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5-2"},
		},
		{
			"name": "my-task-2",
			"ref": {"bundle": "reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5-2"},
		},
	]

	expected := {task | task := tasks[_]}
	lib.assert_equal(unpinned_task_bundle(tasks), expected)
}

# All good when the most recent bundle is used.
test_acceptable_bundle {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": "reg.com/repo@sha256:abc"}},
		{"name": "my-task-2", "ref": {"bundle": "reg.com/repo@sha256:abc"}},
	]

	lib.assert_empty(disallowed_task_reference(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(empty_task_bundle_reference(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(unpinned_task_bundle(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(out_of_date_task_bundle(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(unacceptable_task_bundle(tasks)) with data["task-bundles"] as task_bundles
}

# All good when the most recent bundle is used when streams are used.
test_acceptable_bundle_up_to_date_with_streams {
	tasks := [
		{
			"name": "my-task-1",
			"taskRef": {"bundle": "reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5-2@sha256:abc"},
		},
		{
			"name": "my-task-2",
			"ref": {"bundle": "reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5-2@sha256:abc"},
		},
	]

	lib.assert_empty(disallowed_task_reference(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(empty_task_bundle_reference(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(unpinned_task_bundle(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(out_of_date_task_bundle(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(unacceptable_task_bundle(tasks)) with data["task-bundles"] as task_bundles
}

test_out_of_date_task_bundle {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": "reg.com/repo@sha256:bcd"}},
		{"name": "my-task-2", "taskRef": {"bundle": "reg.com/repo@sha256:cde"}},
		{"name": "my-task-3", "ref": {"bundle": "reg.com/repo@sha256:bcd"}},
		{"name": "my-task-4", "ref": {"bundle": "reg.com/repo@sha256:cde"}},
	]

	expected := {task | task := tasks[_]}
	lib.assert_equal(out_of_date_task_bundle(tasks), expected) with data["task-bundles"] as task_bundles
}

test_out_of_date_task_bundle_with_streams {
	# Verify streams are honored
	tasks := [
		{
			"name": "my-task-1",
			"taskRef": {"bundle": "reg.com/repo:b7d8f6ae908641f5f2309ee6a9d6b2b83a56e1af-2@sha256:bcd"},
		},
		{
			"name": "my-task-2",
			"taskRef": {"bundle": "reg.com/repo:120dda49a6cc3b89516b491e19fe1f3a07f1427f-2@sha256:cde"},
		},
		{
			"name": "my-task-3",
			"taskRef": {"bundle": "reg.com/repo:b7d8f6ae908641f5f2309ee6a9d6b2b83a56e1af-2@sha256:bcd"},
		},
		{
			"name": "my-task-4",
			"taskRef": {"bundle": "reg.com/repo:120dda49a6cc3b89516b491e19fe1f3a07f1427f-2@sha256:cde"},
		},
	]

	expected := {task | task := tasks[_]}
	lib.assert_equal(out_of_date_task_bundle(tasks), expected) with data["task-bundles"] as task_bundles
}

test_unacceptable_task_bundles {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": "reg.com/repo@sha256:def"}},
		{"name": "my-task-2", "ref": {"bundle": "reg.com/repo@sha256:def"}},
	]

	expected := {task | task := tasks[_]}
	lib.assert_equal(unacceptable_task_bundle(tasks), expected) with data["task-bundles"] as task_bundles
}

test_unacceptable_task_bundles_with_streams {
	tasks := [
		{
			"name": "my-task-1",
			"taskRef": {"bundle": "reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5-1@sha256:def"},
		},
		{
			"name": "my-task-2",
			"ref": {"bundle": "reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5-1@sha256:def"},
		},
	]

	expected := {task | task := tasks[_]}
	lib.assert_equal(unacceptable_task_bundle(tasks), expected) with data["task-bundles"] as task_bundles
}

test_is_equal {
	record := {"digest": "sha256:abc", "tag": "spam"}

	# Exact match
	lib.assert_equal(is_equal(record, {"digest": "sha256:abc", "tag": "spam"}), true)

	# Tag is ignored if digest matches
	lib.assert_equal(is_equal(record, {"digest": "sha256:abc", "tag": "not-spam"}), true)

	# Tag is not required
	lib.assert_equal(is_equal(record, {"digest": "sha256:abc", "tag": ""}), true)

	# When digest is missing on ref, compare tag
	lib.assert_equal(is_equal(record, {"digest": "", "tag": "spam"}), true)

	# If digest does not match, tag is still ignored
	lib.assert_equal(is_equal(record, {"digest": "sha256:bcd", "tag": "spam"}), false)

	# No match is honored when digest is missing
	lib.assert_equal(is_equal(record, {"digest": "", "tag": "not-spam"}), false)
}

test_stream {
	lib.assert_equal(_stream(""), "default")
	lib.assert_equal(_stream("spam"), "default")
	lib.assert_equal(_stream("903d49a833d22f359bce3d67b15b006e1197bae5"), "default")
	lib.assert_equal(_stream("903d49a833d22f359bce3d67b15b006e1197bae5-9-9"), "default")
	lib.assert_equal(_stream("spam-903d49a833d22f359bce3d67b15b006e1197bae5-2"), "default")

	lib.assert_equal(_stream("903d49a833d22f359bce3d67b15b006e1197bae5-2"), "2")
	lib.assert_equal(_stream("903d49a833d22f359bce3d67b15b006e1197bae5-999"), "999")
}

test_tag_by_digest {
	refs := [
		{
			"digest": "sha256:abc",
			"tag": "ignore-me",
		},
		{
			"digest": "sha256:bcd",
			"tag": "the-tag",
		},
		{
			"digest": "sha256:bcd",
			"tag": "repeat-digest",
		},
	]

	# The first match is found
	lib.assert_equal(_tag_by_digest(refs, {"digest": "sha256:bcd", "tag": ""}), "the-tag")

	# Skip search if tag is already provided
	lib.assert_equal(_tag_by_digest(refs, {"digest": "sha256:bcd", "tag": "tag-known"}), "tag-known")

	# No match found
	lib.assert_equal(_tag_by_digest(refs, {"digest": "sha256:cde", "tag": ""}), "")
}

task_bundles = {"reg.com/repo": [
	{
		"digest": "sha256:012", # Ignore
		"tag": "903d49a833d22f359bce3d67b15b006e1197bae5-1",
		"effective_on": "2262-04-11T00:00:00Z",
	},
	{
		"digest": "sha256:abc", # Allow
		"tag": "903d49a833d22f359bce3d67b15b006e1197bae5-2",
		"effective_on": "2262-04-11T00:00:00Z",
	},
	{
		"digest": "sha256:123", # Ignore
		"tag": "b7d8f6ae908641f5f2309ee6a9d6b2b83a56e1af-1",
		"effective_on": "2262-03-11T00:00:00Z",
	},
	{
		"digest": "sha256:bcd", # Warn
		"tag": "b7d8f6ae908641f5f2309ee6a9d6b2b83a56e1af-2",
		"effective_on": "2262-03-11T00:00:00Z",
	},
	{
		"digest": "sha256:234", # Ignore
		"tag": "120dda49a6cc3b89516b491e19fe1f3a07f1427f-1",
		"effective_on": "2022-02-01T00:00:00Z",
	},
	{
		"digest": "sha256:cde", # Warn
		"tag": "120dda49a6cc3b89516b491e19fe1f3a07f1427f-2",
		"effective_on": "2022-02-01T00:00:00Z",
	},
	{
		"digest": "sha256:345", # Ignore
		"tag": "903d49a833d22f359bce3d67b15b006e1197bae5-1",
		"effective_on": "2021-01-01T00:00:00Z",
	},
	{
		"digest": "sha256:def", # Warn
		"tag": "903d49a833d22f359bce3d67b15b006e1197bae5-2",
		"effective_on": "2021-01-01T00:00:00Z",
	},
]}

test_acceptable_bundle_is_acceptable {
	is_acceptable(acceptable_bundle_ref) with data["task-bundles"] as bundle_data
}

test_unacceptable_bundle_is_unacceptable {
	not is_acceptable("registry.img/unacceptable@sha256:digest") with data["task-bundles"] as bundle_data
}
