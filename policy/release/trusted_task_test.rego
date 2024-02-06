package policy.release.trusted_task_test

import rego.v1

import data.lib
import data.policy.release.trusted_task

test_success if {
	att := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [
			newest_bundle_pipeline_task,
			newest_git_pipeline_task,
		]},
	}}}

	lib.assert_empty(trusted_task.warn | trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as trusted_tasks_data
}

test_pinned_warning if {
	att := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [
			trusted_bundle_pipeline_task,
			unpinned_bundle_pipeline_task,
			trusted_git_pipeline_task,
			unpinned_git_pipeline_task,
		]},
	}}}

	expected := {
		{
			"code": "trusted_task.pinned",
			# regal ignore:line-length
			"msg": "Pipeline task \"unpinned-honest-abe-p\" uses an unpinned task reference, git+git.local/repo.git//tasks/honest-abe.yaml@", "term": "honest-abe",
		},
		{
			"code": "trusted_task.pinned",
			# regal ignore:line-length
			"msg": "Pipeline task \"unpinned-trusty-p\" uses an unpinned task reference, oci://registry.local/trusty:1.0@", "term": "trusty",
		},
	}

	lib.assert_equal_results(trusted_task.warn, expected) with input.attestations as [att]
		with data.trusted_tasks as trusted_tasks_data
}

test_outdated_warning if {
	att := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [
			trusted_bundle_pipeline_task,
			outdated_bundle_pipeline_task,
			trusted_git_pipeline_task,
			outdated_git_pipeline_task,
		]},
	}}}

	expected := {
		{
			"code": "trusted_task.current",
			# regal ignore:line-length
			"msg": "Pipeline task \"outadated-honest-abe-p\" uses an out of date task reference, git+git.local/repo.git//tasks/honest-abe.yaml@37ef630394794f28142224295851a45eea5c63ae",
			"term": "honest-abe",
		},
		{
			"code": "trusted_task.current",
			# regal ignore:line-length
			"msg": "Pipeline task \"outdated-trusty-p\" uses an out of date task reference, oci://registry.local/trusty:1.0@sha256:outdated-digest",
			"term": "trusty",
		},
	}

	lib.assert_equal_results(trusted_task.warn, expected) with input.attestations as [att]
		with data.trusted_tasks as trusted_tasks_data
}

test_trusted_violation if {
	att := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [
			trusted_bundle_pipeline_task,
			outdated_bundle_pipeline_task,
			unknown_bundle_pipeline_task,
			expired_bundle_pipeline_task,
			trusted_git_pipeline_task,
			outdated_git_pipeline_task,
			unknown_git_pipeline_task,
			expired_git_pipeline_task,
			inlined_pipeline_task,
		]},
	}}}

	expected := {
		{
			"code": "trusted_task.trusted",
			"msg": "Pipeline task \"crook-p\" uses an untrusted task reference, oci://registry.local/crook:1.0@sha256:digest",
			"term": "crook",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": "Pipeline task \"expired-honest-abe-p\" uses an untrusted task reference, git+git.local/repo.git//tasks/honest-abe.yaml@26ef630394794f28142224295851a45eea5c63ae",
			"term": "honest-abe",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": "Pipeline task \"expired-trusty-p\" uses an untrusted task reference, oci://registry.local/trusty:1.0@sha256:expired-digest",
			"term": "trusty",
		},
		{
			# regal ignore:line-length
			"code": "trusted_task.trusted", "msg": "Pipeline task \"inlined-p\" uses an untrusted task reference, <UNKNOWN>@<INLINED>",
			"term": "<NAMELESS>",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": "Pipeline task \"untrusted-lawless-p\" uses an untrusted task reference, git+git.local/repo.git//tasks/lawless.yaml@37ef630394794f28142224295851a45eea5c63ae",
			"term": "lawless",
		},
	}

	lib.assert_equal_results(trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as trusted_tasks_data
}

test_data_missing if {
	expected := {{"code": "trusted_task.data", "msg": "Missing required trusted_tasks data"}}
	lib.assert_equal_results(trusted_task.deny, expected) with data.trusted_tasks as []
}

#########################################
# Pipeline Tasks using bundles resolver #
#########################################

trusted_bundle_pipeline_task := {
	"name": "trusty-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:digest"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]},
}

newest_bundle_pipeline_task := trusted_bundle_pipeline_task

outdated_bundle_pipeline_task := {
	"name": "outdated-trusty-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:outdated-digest"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]},
}

expired_bundle_pipeline_task := {
	"name": "expired-trusty-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:expired-digest"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]},
}

unpinned_bundle_pipeline_task := {
	"name": "unpinned-trusty-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/trusty:1.0"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]},
}

unknown_bundle_pipeline_task := {
	"name": "crook-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/crook:1.0@sha256:digest"},
		{"name": "name", "value": "crook"},
		{"name": "kind", "value": "task"},
	]},
}

#####################################
# Pipeline Tasks using git resolver #
#####################################

trusted_git_pipeline_task := {
	"name": "honest-abe-p",
	"ref": {"resolver": "git", "params": [
		{"name": "revision", "value": "48df630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]},
	"invocation": {"environment": {"labels": {"tekton.dev/task": "honest-abe"}}},
}

newest_git_pipeline_task := trusted_git_pipeline_task

outdated_git_pipeline_task := {
	"name": "outadated-honest-abe-p",
	"ref": {"resolver": "git", "params": [
		{"name": "revision", "value": "37ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]},
	"invocation": {"environment": {"labels": {"tekton.dev/task": "honest-abe"}}},
}

expired_git_pipeline_task := {
	"name": "expired-honest-abe-p",
	"ref": {"resolver": "git", "params": [
		{"name": "revision", "value": "26ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]},
	"invocation": {"environment": {"labels": {"tekton.dev/task": "honest-abe"}}},
}

unpinned_git_pipeline_task := {
	"name": "unpinned-honest-abe-p",
	"ref": {"resolver": "git", "params": [
		{"name": "revision", "value": "main"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]},
	"invocation": {"environment": {"labels": {"tekton.dev/task": "honest-abe"}}},
}

unknown_git_pipeline_task := {
	"name": "untrusted-lawless-p",
	"ref": {"resolver": "git", "params": [
		{"name": "revision", "value": "37ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/lawless.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]},
	"invocation": {"environment": {"labels": {"tekton.dev/task": "lawless"}}},
}

##########################
# Inlined Pipeline Tasks #
##########################

inlined_pipeline_task := {
	"name": "inlined-p",
	"ref": {},
}

######################
# Trusted Tasks data #
######################

trusted_tasks_data := {
	"oci://registry.local/trusty:1.0": [
		{
			"ref": "sha256:digest",
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
