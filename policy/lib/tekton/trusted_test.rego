package lib.tekton_test

import rego.v1

import data.lib
import data.lib.tekton

test_unpinned_task_references if {
	tasks := [
		trusted_bundle_task,
		unpinned_bundle_task,
		trusted_git_task,
		unpinned_git_task,
	]

	expected := {unpinned_bundle_task, unpinned_git_task}

	lib.assert_equal(expected, tekton.unpinned_task_references(tasks)) with data.trusted_tasks as trusted_tasks
}

test_missing_trusted_tasks_data if {
	lib.assert_equal(true, tekton.missing_trusted_tasks_data)

	lib.assert_equal(false, tekton.missing_trusted_tasks_data) with data.trusted_tasks as trusted_tasks
}

test_newer_tasks if {
	tasks := [
		same_date_trusted_bundle_task,
		newest_trusted_bundle_task,
		outdated_trusted_bundle_task,
		newest_trusted_git_task,
		outdated_trusted_git_task,
	]

	expected := {
		{
			"newer_effective_on": "2099-01-01T00:00:00Z",
			"task": outdated_trusted_bundle_task,
		},
		{
			"newer_effective_on": "2099-01-01T00:00:00Z",
			"task": outdated_trusted_git_task,
		},
	}

	lib.assert_equal(expected, tekton.newer_tasks_of(tasks)) with data.trusted_tasks as trusted_tasks
}

test_untrusted_task_refs if {
	tasks := [
		trusted_bundle_task,
		untrusted_bundle_task,
		expired_trusted_bundle_task,
		trusted_git_task,
		untrusted_git_task,
		expired_trusted_git_task,
	]

	expected := {untrusted_bundle_task, expired_trusted_bundle_task, untrusted_git_task, expired_trusted_git_task}

	lib.assert_equal(expected, tekton.untrusted_task_refs(tasks)) with data.trusted_tasks as trusted_tasks
}

test_is_trusted_task if {
	tekton.is_trusted_task(trusted_bundle_task) with data.trusted_tasks as trusted_tasks
	tekton.is_trusted_task(trusted_git_task) with data.trusted_tasks as trusted_tasks

	not tekton.is_trusted_task(untrusted_bundle_task) with data.trusted_tasks as trusted_tasks
	not tekton.is_trusted_task(untrusted_git_task) with data.trusted_tasks as trusted_tasks

	tekton.is_trusted_task(newest_trusted_bundle_task) with data.trusted_tasks as future_trusted_tasks
	tekton.is_trusted_task(newest_trusted_git_task) with data.trusted_tasks as future_trusted_tasks
}

test_rule_data_merging if {
	lib.assert_equal(tekton._trusted_tasks_data.foo, "baz") with data.trusted_tasks as {"foo": "baz"}

	lib.assert_equal(tekton._trusted_tasks_data.foo, "bar") with data.trusted_tasks as {"foo": "baz"}
		with data.rule_data.trusted_tasks as {"foo": "bar"}
}

test_data_errors if {
	tasks := {
		"not-an-array": 1,
		"empty-array": [],
		"missing-required-properties": [{}],
		"additional-properties": [{
			"effective_on": "2024-01-01T00:00:00Z",
			"expires_on": "2024-02-01T00:00:00Z",
			"ref": "abc",
			"spam": "maps",
		}],
		"bad-dates": [
			{"ref": "bad-effective-on", "effective_on": "not-a-date"},
			{"ref": "bad-effective-on", "effective_on": "2024-01-01T00:00:00Z", "expires_on": "not-a-date"},
		],
		# this is allowed
		"duplicated-entries": [
			{"ref": "sha256:digest", "effective_on": "2099-01-01T00:00:00Z"},
			{"ref": "sha256:digest", "effective_on": "2099-01-01T00:00:00Z"},
		],
	}

	expected := {
		{
			"message": "trusted_tasks data has unexpected format: not-an-array: Invalid type. Expected: array, given: integer",
			"severity": "failure",
		},
		{
			"message": "trusted_tasks data has unexpected format: empty-array: Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"message": "trusted_tasks data has unexpected format: missing-required-properties.0: effective_on is required",
			"severity": "failure",
		},
		{
			"message": "trusted_tasks data has unexpected format: missing-required-properties.0: ref is required",
			"severity": "failure",
		},
		{
			# regal ignore:line-length
			"message": "trusted_tasks data has unexpected format: additional-properties.0: Additional property spam is not allowed",
			"severity": "warning",
		},
		{
			"message": `trusted_tasks.bad-dates[0].effective_on is not valid RFC3339 format: "not-a-date"`,
			"severity": "failure",
		},
		{
			"message": `trusted_tasks.bad-dates[1].expires_on is not valid RFC3339 format: "not-a-date"`,
			"severity": "failure",
		},
	}

	lib.assert_equal(tekton.data_errors, expected) with data.trusted_tasks as tasks
}

trusted_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:digest"},
	{"name": "name", "value": "trusty"},
	{"name": "kind", "value": "task"},
]}}}

newest_trusted_bundle_task := trusted_bundle_task

same_date_trusted_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:same_date"},
	{"name": "name", "value": "trusty"},
	{"name": "kind", "value": "task"},
]}}}

outdated_trusted_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:outdated-digest"},
	{"name": "name", "value": "trusty"},
	{"name": "kind", "value": "task"},
]}}}

expired_trusted_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:expired-digest"},
	{"name": "name", "value": "trusty"},
	{"name": "kind", "value": "task"},
]}}}

unpinned_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	{"name": "bundle", "value": "registry.local/trusty:1.0"},
	{"name": "name", "value": "crook"},
	{"name": "kind", "value": "task"},
]}}}

untrusted_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	{"name": "bundle", "value": "registry.local/crook:1.0@sha256:digest"},
	{"name": "name", "value": "crook"},
	{"name": "kind", "value": "task"},
]}}}

trusted_git_task := {
	"metadata": {"labels": {"tekton.dev/task": "honest-abe"}},
	"spec": {"taskRef": {"resolver": "git", "params": [
		{"name": "revision", "value": "48df630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]}},
}

newest_trusted_git_task := trusted_git_task

outdated_trusted_git_task := {
	"metadata": {"labels": {"tekton.dev/task": "honest-abe"}},
	"spec": {"taskRef": {"resolver": "git", "params": [
		{"name": "revision", "value": "37ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]}},
}

expired_trusted_git_task := {
	"metadata": {"labels": {"tekton.dev/task": "honest-abe"}},
	"spec": {"taskRef": {"resolver": "git", "params": [
		{"name": "revision", "value": "26ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]}},
}

unpinned_git_task := {
	"metadata": {"labels": {"tekton.dev/task": "honest-abe"}},
	"spec": {"taskRef": {"resolver": "git", "params": [
		{"name": "revision", "value": "main"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]}},
}

untrusted_git_task := {
	"metadata": {"labels": {"tekton.dev/task": "lawless"}},
	"spec": {"taskRef": {"resolver": "git", "params": [
		{"name": "revision", "value": "37ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/lawless.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]}},
}

trusted_tasks := {
	"oci://registry.local/trusty:1.0": [
		{
			"ref": "sha256:digest",
			"effective_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "sha256:same_date",
			"effective_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "sha256:outdated-digest",
			"effective_on": "2024-01-01T00:00:00Z",
		},
		{
			"ref": "sha256:expired-digest",
			"effective_on": "2023-01-01T00:00:00Z",
		},
	],
	"git+git.local/repo.git//tasks/honest-abe.yaml": [
		{
			"ref": "48df630394794f28142224295851a45eea5c63ae",
			"effective_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "37ef630394794f28142224295851a45eea5c63ae",
			"effective_on": "2024-01-01T00:00:00Z",
		},
		{
			"ref": "26ef630394794f28142224295851a45eea5c63ae",
			"effective_on": "2023-01-01T00:00:00Z",
		},
	],
}

# Corner case where all entries are in the future.
future_trusted_tasks := {
	"oci://registry.local/trusty:1.0": [{
		"ref": "sha256:digest",
		"effective_on": "2099-01-01T00:00:00Z",
	}],
	"git+git.local/repo.git//tasks/honest-abe.yaml": [{
		"ref": "48df630394794f28142224295851a45eea5c63ae",
		"effective_on": "2099-01-01T00:00:00Z",
	}],
}
