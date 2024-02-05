package lib.bundles_test

import rego.v1

import data.lib
import data.lib.bundles
import data.lib.image

# used as reference bundle data in tests
bundle_data := {"registry.img/acceptable": [{
	"digest": "sha256:digest",
	"tag": "",
	"effective_on": "2000-01-01T00:00:00Z",
}]}

# used as reference bundle data in tests
acceptable_bundle_ref := "registry.img/acceptable@sha256:digest"

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

# All good when the most recent bundle is used.
test_acceptable_bundle if {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": "reg.com/repo@sha256:abc"}},
		{"name": "my-task-2", "ref": {"bundle": "reg.com/repo@sha256:abc"}},
	]

	lib.assert_empty(bundles.disallowed_task_reference(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(bundles.empty_task_bundle_reference(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(bundles.unpinned_task_bundle(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(bundles.out_of_date_task_bundle(tasks)) with data["task-bundles"] as task_bundles
	lib.assert_empty(bundles.unacceptable_task_bundle(tasks)) with data["task-bundles"] as task_bundles
}

test_out_of_date_task_bundle if {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": "reg.com/repo@sha256:bcd"}},
		{"name": "my-task-3", "ref": {"bundle": "reg.com/repo@sha256:bcd"}},
	]
	lib.assert_empty(bundles.out_of_date_task_bundle(tasks))

	lib.assert_empty(bundles.out_of_date_task_bundle(tasks)) with data["task-bundles"] as task_bundles

	expected := lib.to_set(tasks)
	lib.assert_equal(bundles.out_of_date_task_bundle(tasks), expected) with data["task-bundles"] as task_bundles
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2022-03-12T00:00:00Z")
}

test_unacceptable_task_bundles if {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": "reg.com/repo@sha256:blah"}},
		{"name": "my-task-2", "ref": {"bundle": "reg.com/repo@sha256:blah"}},
		{"name": "my-task-3", "ref": {"bundle": "wat.com/repo@sha256:blah"}},
	]

	expected := lib.to_set(tasks)
	lib.assert_equal(bundles.unacceptable_task_bundle(tasks), expected) with data["task-bundles"] as task_bundles

	# By default, if a list of acceptable bundles is not provided, everything is is unacceptable.
	lib.assert_equal(bundles.unacceptable_task_bundle(tasks), expected)
}

task_bundles := {"reg.com/repo": [
	{
		"digest": "sha256:abc", # Allow
		"tag": "v1",
		"effective_on": "2022-04-11T00:00:00Z",
	},
	{
		"digest": "sha256:bcd", # Warn
		"tag": "v1",
		"effective_on": "2022-03-11T00:00:00Z",
	},
	{
		"digest": "sha256:cde", # Warn
		"tag": "v1",
		"effective_on": "2022-02-01T00:00:00Z",
	},
	{
		"digest": "sha256:def", # Warn
		"tag": "v1",
		"effective_on": "2021-01-01T00:00:00Z",
	},
]}

test_acceptable_bundle_record_exists if {
	bundles._record_exists(image.parse(acceptable_bundle_ref)) with data["task-bundles"] as bundle_data
}

test_unacceptable_bundle_is_unacceptable if {
	ref := "registry.img/unacceptable@sha256:digest"
	not bundles._record_exists(image.parse(ref)) with data["task-bundles"] as bundle_data
}

test_missing_required_data if {
	lib.assert_equal(bundles.missing_task_bundles_data, false) with data["task-bundles"] as task_bundles
	lib.assert_equal(bundles.missing_task_bundles_data, true) with data["task-bundles"] as []
	lib.assert_equal(bundles.missing_task_bundles_data, true)
}

test_newer_version_exists_not_using_tags_newest if {
	ref := image.parse("registry.io/repository/image:tag@sha256:digest")
	acceptable := {"registry.io/repository/image": [{
		"digest": "sha256:digest",
		"tag": "",
		"effective_on": "2262-04-11T00:00:00Z",
	}]}
	not bundles._newer_version_exists(ref) with data["task-bundles"] as acceptable
}

test_newer_version_exists_not_using_tags_older if {
	ref := image.parse("registry.io/repository/image:tag@sha256:digest")
	acceptable := {"registry.io/repository/image": [
		{
			"digest": "sha256:newer",
			"tag": "",
			"effective_on": "2262-04-11T00:00:00Z",
		},
		{
			"digest": "sha256:digest",
			"tag": "",
			"effective_on": "1962-04-11T00:00:00Z",
		},
	]}
	bundles._newer_version_exists(ref) with data["task-bundles"] as acceptable
}

test_newer_version_exists_tags_differ_newest if {
	ref := image.parse("registry.io/repository/image:tag@sha256:digest")
	acceptable := {"registry.io/repository/image": [{
		"digest": "sha256:digest",
		"tag": "different",
		"effective_on": "2262-04-11T00:00:00Z",
	}]}
	not bundles._newer_version_exists(ref) with data["task-bundles"] as acceptable
}

test_newer_version_exists_tags_differ_older if {
	ref := image.parse("registry.io/repository/image:tag@sha256:digest")
	acceptable := {"registry.io/repository/image": [
		{
			"digest": "sha256:newer",
			"tag": "newer",
			"effective_on": "2262-04-11T00:00:00Z",
		},
		{
			"digest": "sha256:digest",
			"tag": "different",
			"effective_on": "1962-04-11T00:00:00Z",
		},
	]}
	bundles._newer_version_exists(ref) with data["task-bundles"] as acceptable
}

test_newer_version_exists_tags_as_versions_newest if {
	ref := image.parse("registry.io/repository/image:v1@sha256:digest")
	acceptable := {"registry.io/repository/image": [
		{
			"digest": "sha256:digest",
			"tag": "v1",
			"effective_on": "2262-04-11T00:00:00Z",
		},
		{
			"digest": "sha256:different",
			"tag": "v1",
			"effective_on": "2162-04-11T00:00:00Z",
		},
	]}
	not bundles._newer_version_exists(ref) with data["task-bundles"] as acceptable
}

test_newer_version_exists_tags_as_versions_older if {
	ref := image.parse("registry.io/repository/image:v1@sha256:digest")
	acceptable := {"registry.io/repository/image": [
		{
			"digest": "sha256:newer",
			"tag": "v1",
			"effective_on": "2262-04-11T00:00:00Z",
		},
		{
			"digest": "sha256:digest",
			"tag": "v1",
			"effective_on": "1962-04-11T00:00:00Z",
		},
	]}
	bundles._newer_version_exists(ref) with data["task-bundles"] as acceptable
}

test_is_acceptable if {
	acceptable := {"registry.io/repository/image": [{
		"digest": "sha256:digest",
		"tag": "",
		"effective_on": "1962-04-11T00:00:00Z",
	}]}
	acceptable_task := {"name": "my-task", "taskRef": {"bundle": "registry.io/repository/image:tag@sha256:digest"}}
	bundles.is_acceptable_task(acceptable_task) with data["task-bundles"] as acceptable

	unacceptable_task := {"name": "my-task", "taskRef": {"bundle": "registry.io/other/image:tag@sha256:digest"}}
	not bundles.is_acceptable_task(unacceptable_task) with data["task-bundles"] as acceptable
}

test_stale_entries_ignored if {
	acceptable := {"registry.io/repository/image": [
		{
			"digest": "sha256:digest",
			"effective_on": "2023-02-01T00:00:00Z",
			"tag": "tag",
		},
		{
			"digest": "sha256:digest",
			"effective_on": "2023-01-01T00:00:00Z",
			"tag": "tag",
		},
	]}

	acceptable_task := {"name": "my-task", "taskRef": {"bundle": "registry.io/repository/image:tag@sha256:digest"}}
	lib.assert_empty(bundles.unacceptable_task_bundle([acceptable_task])) with data["task-bundles"] as acceptable
}
