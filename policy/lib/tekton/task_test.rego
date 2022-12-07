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

test_task_param if {
	task := {"params": [{"name": "NETWORK", "value": "none"}]}
	lib.assert_equal("none", task_param(task, "NETWORK"))
	not task_param(task, "missing")
}

test_task_result if {
	task := {"results": [{"name": "SPAM", "value": "maps"}]}
	lib.assert_equal("maps", task_result(task, "SPAM"))
	not task_result(task, "missing")
}

test_trusted_tasks_from_attestation if {
	good_bundle := bundles.acceptable_bundle_ref
	bad_bundle := "registry.img/unacceptable@sha256:digest"

	attestation := {"predicate": {"buildConfig": {"tasks": [
		{"ref": {"name": "git-clone", "kind": "Task", "bundle": good_bundle}},
		_good_build_task,
		{
			"ref": {"name": "weird[food=spam]", "kind": "Task", "bundle": good_bundle},
			"invocation": {"parameters": {"SPAM": "MAPS"}},
		},
		{"ref": {"name": "ignored-bad-bundle", "kind": "Task", "bundle": bad_bundle}},
		{"ref": {"name": "ignored-bad-kind", "kind": "NotTask", "bundle": good_bundle}},
		{"ref": {"name": "summary", "kind": "Task", "bundle": good_bundle}},
		{}, # Obviously, also ignored.
	]}}}

	expected_tasks := {
		{"ref": {"name": "git-clone", "kind": "Task", "bundle": good_bundle}},
		_good_build_task,
		{
			"ref": {"name": "weird[food=spam]", "kind": "Task", "bundle": good_bundle},
			"invocation": {"parameters": {"SPAM": "MAPS"}},
		},
		{"ref": {"name": "summary", "kind": "Task", "bundle": good_bundle}},
	}
	lib.assert_equal(expected_tasks, trusted_tasks(attestation)) with data["task-bundles"] as bundles.bundle_data

	expected_names := {"git-clone", "buildah", "buildah[HERMETIC_BUILD=true]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected_names, trusted_tasks_names(attestation)) with data["task-bundles"] as bundles.bundle_data
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

	expected_tasks := {
		{"taskRef": {"name": "git-clone", "kind": "Task", "bundle": good_bundle}},
		{
			"taskRef": {"name": "buildah", "kind": "Task", "bundle": good_bundle},
			"params": [{"name": "NETWORK", "value": "none"}],
		},
		{
			"taskRef": {"name": "weird[food=spam]", "kind": "Task", "bundle": good_bundle},
			"params": [{"name": "SPAM", "value": "MAPS"}],
		},
		{"taskRef": {"name": "summary", "kind": "Task", "bundle": good_bundle}},
	}
	lib.assert_equal(expected_tasks, trusted_tasks(pipeline)) with data["task-bundles"] as bundles.bundle_data

	expected_names := {"git-clone", "buildah", "buildah[NETWORK=none]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected_names, trusted_tasks_names(pipeline)) with data["task-bundles"] as bundles.bundle_data
}

test_trusted_build_task if {
	expected := _good_build_task
	lib.assert_equal(expected, trusted_build_task(_good_attestation)) with data["task-bundles"] as bundles.bundle_data
}

test_trusted_build_task_not_found if {
	untrusted_bundle := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/predicate/buildConfig/tasks/0/ref/bundle",
		"value": "registry.img/unacceptable@sha256:digest",
	}])
	not trusted_build_task(untrusted_bundle) with data["task-bundles"] as bundles.bundle_data

	missing_image_url := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/predicate/buildConfig/tasks/0/results/0/name",
		"value": "IMAGE_URL_SKIP",
	}])
	not trusted_build_task(missing_image_url) with data["task-bundles"] as bundles.bundle_data

	missing_image_digest := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/predicate/buildConfig/tasks/0/results/1/name",
		"value": "IMAGE_DIGEST_SKIP",
	}])
	not trusted_build_task(missing_image_digest) with data["task-bundles"] as bundles.bundle_data

	missing_results := json.remove(_good_attestation, ["/predicate/buildConfig/tasks/0/results"])
	not trusted_build_task(missing_results) with data["task-bundles"] as bundles.bundle_data
}

test_task_data_bundle_ref if {
	lib.assert_equal(
		{
			"bundle": "bundle",
			"name": "ref-name",
		},
		task_data({
			"name": "name",
			"ref": {
				"name": "ref-name",
				"kind": "Task",
				"bundle": "bundle",
			},
		}),
	)
}

test_task_data_no_bundle_Ref if {
	lib.assert_equal({"name": "name"}, task_data({"name": "name"}))
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

_good_build_task := {
	"results": [
		{"name": "IMAGE_URL", "value": "registry/repo"},
		{"name": "IMAGE_DIGEST", "value": "digest"},
	],
	"ref": {"kind": "Task", "name": "buildah", "bundle": bundles.acceptable_bundle_ref},
	"invocation": {"parameters": {"HERMETIC_BUILD": "true"}},
}

_good_attestation := {"predicate": {
	"buildType": lib.pipelinerun_att_build_types[0],
	"buildConfig": {"tasks": [_good_build_task]},
}}
