package lib.tkn

import future.keywords.if
import future.keywords.in

import data.lib

test_latest_required_tasks if {
	expected := {t | some t in _expected_latest.tasks}
	lib.assert_equal(expected, latest_required_default_tasks) with data["required-tasks"] as _time_based_required_tasks
}

test_current_required_tasks if {
	expected := {t | some t in _expected_current.tasks}
	lib.assert_equal(expected, current_required_default_tasks) with data["required-tasks"] as _time_based_required_tasks
}

test_tasks_from_attestation if {
	git_clone := {"name": "ignored", "ref": {"name": "git-clone"}}
	buildah := {"name": "ignored", "ref": {"name": "buildah"}}

	attestation := {"predicate": {"buildConfig": {"tasks": [git_clone, buildah]}}}
	expected := {git_clone, buildah}
	lib.assert_equal(expected, tasks(attestation))
}

test_tasks_from_pipeline if {
	git_clone := {"taskRef": {"name": "git-clone"}}
	buildah := {"taskRef": {"name": "buildah"}}
	summary := {"taskRef": {"name": "summary"}}
	pipeline := {
		"kind": "Pipeline",
		"spec": {
			"tasks": [git_clone, buildah],
			"finally": [summary],
		},
	}
	expected := {git_clone, buildah, summary}
	lib.assert_equal(expected, tasks(pipeline))
}

test_tasks_from_partial_pipeline if {
	lib.assert_empty(tasks({"kind": "Pipeline"}))
	lib.assert_empty(tasks({"kind": "Pipeline", "spec": {}}))

	git_clone := {"taskRef": {"name": "git-clone"}}
	lib.assert_equal({git_clone}, tasks({"kind": "Pipeline", "spec": {"tasks": [git_clone]}}))
	lib.assert_equal({git_clone}, tasks({"kind": "Pipeline", "spec": {"finally": [git_clone]}}))
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

test_tasks_from_attestation if {
	expected_tasks := {
		{"ref": {"name": "git-clone", "kind": "Task", "bundle": _bundle}},
		_good_build_task,
		{
			"ref": {"name": "weird[food=spam]", "kind": "Task", "bundle": _bundle},
			"invocation": {"parameters": {"SPAM": "MAPS"}},
		},
		{"ref": {"name": "summary", "kind": "Task", "bundle": _bundle}},
	}

	attestation := {"predicate": {"buildConfig": {"tasks": expected_tasks}}}

	lib.assert_equal(expected_tasks, tasks(attestation))

	expected_names := {"git-clone", "buildah", "buildah[HERMETIC=true]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected_names, tasks_names(attestation))
}

test_tasks_from_pipeline if {
	pipeline := {
		"kind": "Pipeline",
		"spec": {
			"tasks": [
				{"taskRef": {"name": "git-clone", "kind": "Task", "bundle": _bundle}},
				{
					"taskRef": {"name": "buildah", "kind": "Task", "bundle": _bundle},
					"params": [{"name": "NETWORK", "value": "none"}],
				},
				{
					"taskRef": {"name": "weird[food=spam]", "kind": "Task", "bundle": _bundle},
					"params": [{"name": "SPAM", "value": "MAPS"}],
				},
				{"taskRef": {"name": "ignored-bad-kind", "kind": "NotTask", "bundle": _bundle}},
				{}, # Obviously, also ignored.
			],
			"finally": [{"taskRef": {"name": "summary", "kind": "Task", "bundle": _bundle}}],
		},
	}

	expected_tasks := {
		{"taskRef": {"name": "git-clone", "kind": "Task", "bundle": _bundle}},
		{
			"taskRef": {"name": "buildah", "kind": "Task", "bundle": _bundle},
			"params": [{"name": "NETWORK", "value": "none"}],
		},
		{
			"taskRef": {"name": "weird[food=spam]", "kind": "Task", "bundle": _bundle},
			"params": [{"name": "SPAM", "value": "MAPS"}],
		},
		{"taskRef": {"name": "summary", "kind": "Task", "bundle": _bundle}},
	}
	lib.assert_equal(expected_tasks, tasks(pipeline))

	expected_names := {"git-clone", "buildah", "buildah[NETWORK=none]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected_names, tasks_names(pipeline))
}

test_build_task if {
	expected := _good_build_task
	lib.assert_equal(expected, build_task(_good_attestation))
}

test_build_task_not_found if {
	missing_image_url := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/predicate/buildConfig/tasks/0/results/0/name",
		"value": "IMAGE_URL_SKIP",
	}])
	not build_task(missing_image_url)

	missing_image_digest := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/predicate/buildConfig/tasks/0/results/1/name",
		"value": "IMAGE_DIGEST_SKIP",
	}])
	not build_task(missing_image_digest)

	missing_results := json.remove(_good_attestation, ["/predicate/buildConfig/tasks/0/results"])
	not build_task(missing_results)
}

test_git_clone_task if {
	expected := _good_git_clone_task
	lib.assert_equal(expected, git_clone_task(_good_attestation))
}

test_git_clone_task_not_found if {
	missing_url := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/predicate/buildConfig/tasks/1/results/0/name",
		"value": "you-argh-el",
	}])
	not git_clone_task(missing_url)

	missing_commit := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/predicate/buildConfig/tasks/1/results/1/name",
		"value": "bachelor",
	}])
	not git_clone_task(missing_commit)

	missing_results := json.remove(_good_attestation, ["/predicate/buildConfig/tasks/1/results"])
	not git_clone_task(missing_results)
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

test_missing_required_tasks_data if {
	lib.assert_equal(missing_required_tasks_data, true) with data["required-tasks"] as []
	lib.assert_equal(missing_required_tasks_data, false) with data["required-tasks"] as _time_based_required_tasks
}

_expected_latest := {
	"effective_on": "2099-01-02T00:00:00Z",
	"tasks": [
		"git-clone",
		"buildah",
		"conftest-clair",
		"label-check[POLICY_NAMESPACE=required_checks]",
		"label-check[POLICY_NAMESPACE=optional_checks]",
	],
}

_expected_current := {
	"effective_on": "2022-12-01T00:00:00Z",
	"tasks": [
		"git-clone",
		"buildah",
		"not-required-in-future",
		"label-check[POLICY_NAMESPACE=required_checks]",
		"label-check[POLICY_NAMESPACE=optional_checks]",
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
	"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
	"invocation": {"parameters": {"HERMETIC": "true"}},
}

_good_git_clone_task := {
	"results": [
		{"name": "url", "value": "https://forge/repo"},
		{"name": "commit", "value": "250e77f12a5ab6972a0895d290c4792f0a326ea8"},
	],
	"ref": {"kind": "Task", "name": "git-clone", "bundle": _bundle},
}

_good_attestation := {"predicate": {
	"buildType": lib.pipelinerun_att_build_types[0],
	"buildConfig": {"tasks": [_good_build_task, _good_git_clone_task]},
}}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
