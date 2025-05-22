package lib.tekton_test

import rego.v1

import data.lib
import data.lib.tekton
import data.lib.time as time_lib

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

test_task_expiry_warnings_after if {
	# default
	lib.assert_equal(0, tekton.task_expiry_warnings_after)

	# with rule data
	lib.assert_equal(
		time.add_date(
			time_lib.effective_current_time_ns, 0, 0,
			16,
		),
		tekton.task_expiry_warnings_after,
	) with data.rule_data.task_expiry_warning_days as 16
}

test_expiry_of if {
	# defaults
	# regal ignore:line-length
	lib.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(same_date_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
	not tekton.expiry_of(newest_trusted_bundle_task) with data.trusted_tasks as trusted_tasks

	# regal ignore:line-length
	lib.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
	not tekton.expiry_of(newest_trusted_git_task) with data.trusted_tasks as trusted_tasks

	# regal ignore:line-length
	lib.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_git_task))) with data.trusted_tasks as trusted_tasks

	# when running far in the future without the grace period
	# regal ignore:line-length
	lib.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(same_date_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
	not tekton.expiry_of(newest_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")

	# regal ignore:line-length
	lib.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
	not tekton.expiry_of(newest_trusted_git_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")

	# regal ignore:line-length
	lib.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_git_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")

	# when running far in the future within the grace period
	# regal ignore:line-length
	lib.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(same_date_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 6
	not tekton.expiry_of(newest_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 6

	# regal ignore:line-length
	lib.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 6
	not tekton.expiry_of(newest_trusted_git_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 6

	# regal ignore:line-length
	lib.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_git_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 6

	# when running far in the future outside the grace period
	not tekton.expiry_of(same_date_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 7
	not tekton.expiry_of(newest_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 7
	not tekton.expiry_of(outdated_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 7
	not tekton.expiry_of(newest_trusted_git_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 7
	not tekton.expiry_of(outdated_trusted_git_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 7
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
	not tekton.is_trusted_task(expired_trusted_git_task) with data.trusted_tasks as trusted_tasks
	not tekton.is_trusted_task(expired_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
}

test_trusted_task_records if {
	task_ref_expected_matches := {
		"oci://registry.local/trusty:1.0": 3,
		"oci://registry.local/trusty": 3,
		"git+git.local/repo.git//tasks/honest-abe.yaml": 2,
		"git+git.local/repo.git//tasks/untrusted.yaml": 0,
		"oci://reg": 0,
	}

	every ref, expected in task_ref_expected_matches {
		records := tekton.trusted_task_records(ref) with data.trusted_tasks as trusted_tasks
		lib.assert_equal(expected, count(records))
	}
}

test_unexpired_records if {
	expected_refs_by_index := {
		0: "sha256:latest",
		1: "sha256:digest-1",
		2: "sha256:digest-2",
		3: "sha256:oldest",
	}

	# regal ignore:line-length
	sorted_tasks := tekton.trusted_task_records("oci://registry.local/trusty:1.0") with data.trusted_tasks as unsorted_trusted_task
	every index, ref in expected_refs_by_index {
		lib.assert_equal(ref, sorted_tasks[index].ref)
	}
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
			{"ref": "sha256:digest", "expires_on": "2099-01-01T00:00:00Z"},
			{"ref": "sha256:digest", "expires_on": "2099-01-01T00:00:00Z"},
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

test_task_expiry_warning_days_data if {
	lib.assert_equal(tekton.data_errors, {{
		"message": "task_expiry_warning_days: Invalid type. Expected: integer, given: string",
		"severity": "failure",
	}}) with data.rule_data.task_expiry_warning_days as "14"

	lib.assert_equal(tekton.data_errors, {{
		"message": `task_expiry_warning_days: Invalid type. Expected: integer, given: number`,
		"severity": "failure",
	}}) with data.rule_data.task_expiry_warning_days as 5.5

	lib.assert_empty(tekton.data_errors) with data.rule_data.task_expiry_warning_days as 14
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
		{"ref": "sha256:digest"},
		{
			"ref": "sha256:same_date",
			"expires_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "sha256:outdated-digest",
			"expires_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "sha256:expired-digest",
			"expires_on": "2024-01-01T00:00:00Z",
		},
	],
	"git+git.local/repo.git//tasks/honest-abe.yaml": [
		{"ref": "48df630394794f28142224295851a45eea5c63ae"},
		{
			"ref": "37ef630394794f28142224295851a45eea5c63ae",
			"expires_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "26ef630394794f28142224295851a45eea5c63ae",
			"expires_on": "2024-01-01T00:00:00Z",
		},
	],
}

unsorted_trusted_task := {"oci://registry.local/trusty:1.0": [
	{
		"ref": "sha256:digest-1",
		"expires_on": "2100-01-01T00:00:00Z",
	},
	{
		"ref": "sha256:digest-2",
		"expires_on": "2075-01-01T00:00:00Z",
	},
	{"ref": "sha256:latest"},
	{
		"ref": "sha256:oldest",
		"expires_on": "2050-01-01T00:00:00Z",
	},
	{
		"ref": "sha256:expired",
		"expires_on": "2000-01-01T00:00:00Z",
	},
	{
		"ref": "sha256:invalid-expires-on",
		"expires_on": "bad-data",
	},
]}
