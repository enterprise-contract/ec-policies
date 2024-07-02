package lib.tkn_test

import rego.v1

import data.lib
import data.lib.tkn

test_unpinned_task_references if {
	tasks := [
		trusted_bundle_task,
		unpinned_bundle_task,
		trusted_git_task,
		unpinned_git_task,
	]

	expected := {unpinned_bundle_task, unpinned_git_task}

	lib.assert_equal(expected, tkn.unpinned_task_references(tasks)) with data.trusted_tasks as trusted_tasks
}

test_missing_trusted_tasks_data if {
	lib.assert_equal(true, tkn.missing_trusted_tasks_data)

	lib.assert_equal(false, tkn.missing_trusted_tasks_data) with data.trusted_tasks as trusted_tasks
}

test_out_of_date_task_refs if {
	tasks := [
		same_date_trusted_bundle_task,
		newest_trusted_bundle_task,
		outdated_trusted_bundle_task,
		newest_trusted_git_task,
		outdated_trusted_git_task,
	]

	expected := {outdated_trusted_bundle_task, outdated_trusted_git_task}

	lib.assert_equal(expected, tkn.out_of_date_task_refs(tasks)) with data.trusted_tasks as trusted_tasks
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

	lib.assert_equal(expected, tkn.untrusted_task_refs(tasks)) with data.trusted_tasks as trusted_tasks
}

test_is_trusted_task if {
	tkn.is_trusted_task(trusted_bundle_task) with data.trusted_tasks as trusted_tasks
	tkn.is_trusted_task(trusted_git_task) with data.trusted_tasks as trusted_tasks

	not tkn.is_trusted_task(untrusted_bundle_task) with data.trusted_tasks as trusted_tasks
	not tkn.is_trusted_task(untrusted_git_task) with data.trusted_tasks as trusted_tasks

	tkn.is_trusted_task(newest_trusted_bundle_task) with data.trusted_tasks as future_trusted_tasks
	tkn.is_trusted_task(newest_trusted_git_task) with data.trusted_tasks as future_trusted_tasks
}

test_rule_data_merging if {
	lib.assert_equal(tkn._trusted_tasks_data.foo, "baz") with data.trusted_tasks as {"foo": "baz"}

	lib.assert_equal(tkn._trusted_tasks_data.foo, "bar") with data.trusted_tasks as {"foo": "baz"}
		with data.rule_data.trusted_tasks as {"foo": "bar"}
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
