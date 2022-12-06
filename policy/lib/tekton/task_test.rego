package lib.tkn

import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.bundles

test_latest_required_tasks if {
	expected := {t | some t in _expected_latest.tasks}
	lib.assert_equal(expected, latest_required_tasks) with data["required-tasks"] as _time_based_required_tasks
}

test_current_required_tasks if {
	expected := {t | some t in _expected_current.tasks}
	lib.assert_equal(expected, current_required_tasks) with data["required-tasks"] as _time_based_required_tasks
}

test_tasks_from_attestation if {
	attestation := {"predicate": {"buildConfig": {"tasks": ["git-clone", "buildah"]}}}
	expected := ["git-clone", "buildah"]
	lib.assert_equal(expected, tasks(attestation))
}

test_tasks_from_pipeline if {
	pipeline := {
		"kind": "Pipeline",
		"spec": {
			"tasks": ["git-clone", "buildah"],
			"finally": ["summary"],
		},
	}
	expected := ["git-clone", "buildah", "summary"]
	lib.assert_equal(expected, tasks(pipeline))
}

test_tasks_from_partial_pipeline if {
	lib.assert_empty(tasks({"kind": "Pipeline"}))
	lib.assert_empty(tasks({"kind": "Pipeline", "spec": {}}))
	lib.assert_equal(["git-clone"], tasks({"kind": "Pipeline", "spec": {"tasks": ["git-clone"]}}))
	lib.assert_equal(["git-clone"], tasks({"kind": "Pipeline", "spec": {"finally": ["git-clone"]}}))
}

test_tasks_not_found if {
	lib.assert_empty(tasks({}))
}

test_trusted_tasks_from_attestation if {
	good_bundle := bundles.acceptable_bundle_ref
	bad_bundle := "registry.img/unacceptable@sha256:digest"

	attestation := {"predicate": {"buildConfig": {"tasks": [
		{"ref": {"name": "git-clone", "kind": "Task", "bundle": good_bundle}},
		{
			"ref": {"name": "buildah", "kind": "Task", "bundle": good_bundle},
			"invocation": {"parameters": {"NETWORK": "none"}},
		},
		{
			"ref": {"name": "weird[food=spam]", "kind": "Task", "bundle": good_bundle},
			"invocation": {"parameters": {"SPAM": "MAPS"}},
		},
		{"ref": {"name": "ignored-bad-bundle", "kind": "Task", "bundle": bad_bundle}},
		{"ref": {"name": "ignored-bad-kind", "kind": "NotTask", "bundle": good_bundle}},
		{"ref": {"name": "summary", "kind": "Task", "bundle": good_bundle}},
		{}, # Obviously, also ignored.
	]}}}

	expected := {"git-clone", "buildah", "buildah[NETWORK=none]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected, trusted_tasks(attestation)) with data["task-bundles"] as bundles.bundle_data
}

test_trusted_tasks_from_pipeline if {
	good_bundle := bundles.acceptable_bundle_ref
	bad_bundle := "registry.img/unacceptable@sha256:digest"

	pipeline := {
		"kind": "Pipeline",
		"spec": {
			"tasks": [
				{"taskRef": {"name": "git-clone", "kind": "Task", "bundle": good_bundle}},
				{
					"taskRef": {"name": "buildah", "kind": "Task", "bundle": good_bundle},
					"params": [{"name": "NETWORK", "value": "none"}],
				},
				{
					"taskRef": {"name": "weird[food=spam]", "kind": "Task", "bundle": good_bundle},
					"params": [{"name": "SPAM", "value": "MAPS"}],
				},
				{"taskRef": {"name": "ignored-bad-bundle", "kind": "Task", "bundle": bad_bundle}},
				{"taskRef": {"name": "ignored-bad-kind", "kind": "NotTask", "bundle": good_bundle}},
				{}, # Obviously, also ignored.
			],
			"finally": [{"taskRef": {"name": "summary", "kind": "Task", "bundle": good_bundle}}],
		},
	}

	expected := {"git-clone", "buildah", "buildah[NETWORK=none]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected, trusted_tasks(pipeline)) with data["task-bundles"] as bundles.bundle_data
}

_expected_latest := {
	"effective_on": "2099-01-02T00:00:00Z",
	"tasks": [
		"git-clone",
		"buildah",
		"conftest-clair",
		"sanity-label-check[POLICY_NAMESPACE=required_checks]",
		"sanity-label-check[POLICY_NAMESPACE=optional_checks]",
	],
}

_expected_current := {
	"effective_on": "2022-12-01T00:00:00Z",
	"tasks": [
		"git-clone",
		"buildah",
		"not-required-in-future",
		"sanity-label-check[POLICY_NAMESPACE=required_checks]",
		"sanity-label-check[POLICY_NAMESPACE=optional_checks]",
	],
}

_time_based_required_tasks := [
	_expected_latest,
	{
		"effective_on": "2099-01-01T00:00:00Z",
		"tasks": ["also-ignored"],
	},
	_expected_current,
	{
		"effective_on": "2022-01-01T00:00:00Z",
		"tasks": ["ignored"],
	},
]
