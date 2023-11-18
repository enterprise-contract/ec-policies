# regal ignore:file-length
package lib.tkn_test

import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.tkn

test_latest_required_tasks if {
	expected := {t | some t in _expected_latest.tasks}
	lib.assert_equal(
		expected,
		tkn.latest_required_default_tasks,
	) with data["required-tasks"] as _time_based_required_tasks
}

test_current_required_tasks if {
	expected := {t | some t in _expected_current.tasks}
	lib.assert_equal(
		expected,
		tkn.current_required_default_tasks,
	) with data["required-tasks"] as _time_based_required_tasks
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
	lib.assert_equal(expected, tkn.tasks(pipeline))
}

test_tasks_from_partial_pipeline if {
	lib.assert_empty(tkn.tasks({"kind": "Pipeline"}))
	lib.assert_empty(tkn.tasks({"kind": "Pipeline", "spec": {}}))

	git_clone := {"taskRef": {"name": "git-clone"}}
	lib.assert_equal({git_clone}, tkn.tasks({"kind": "Pipeline", "spec": {"tasks": [git_clone]}}))
	lib.assert_equal({git_clone}, tkn.tasks({"kind": "Pipeline", "spec": {"finally": [git_clone]}}))
}

test_tasks_not_found if {
	lib.assert_empty(tkn.tasks({}))
}

test_task_param if {
	task := {"params": [{"name": "NETWORK", "value": "none"}]}
	lib.assert_equal("none", tkn.task_param(task, "NETWORK"))
	not tkn.task_param(task, "missing")
}

test_task_slsav1_param if {
	task := {
		"kind": "TaskRun",
		"metadata": {"name": "buildah"},
		"spec": {"params": [{"name": "NETWORK", "value": "none"}]},
	}
	lib.assert_equal("none", tkn.task_param(task, "NETWORK"))
	not tkn.task_param(task, "missing")
}

test_task_result if {
	task := {"results": [{"name": "SPAM", "value": "maps"}]}
	lib.assert_equal("maps", tkn.task_result(task, "SPAM"))
	not tkn.task_result(task, "missing")

	slsav1_task := {"status": {"taskResults": [{"name": "SPAM", "value": "maps"}]}}
	lib.assert_equal("maps", tkn.task_result(slsav1_task, "SPAM"))
	not tkn.task_result(slsav1_task, "missing")
}

test_tasks_from_attestation_with_spam if {
	expected_tasks := {
		{"ref": {"name": "git-clone", "kind": "Task", "bundle": _bundle}},
		_good_build_task,
		{
			"ref": {"name": "weird[food=spam]", "kind": "Task", "bundle": _bundle},
			"invocation": {"parameters": {"SPAM": "MAPS"}},
		},
		{"ref": {"name": "summary", "kind": "Task", "bundle": _bundle}},
	}

	attestation := {"statement": {"predicate": {"buildConfig": {"tasks": expected_tasks}}}}

	lib.assert_equal(expected_tasks, tkn.tasks(attestation))

	expected_names := {"git-clone", "buildah", "buildah[HERMETIC=true]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected_names, tkn.tasks_names(attestation))
}

# regal ignore:rule-length
test_tasks_from_pipeline_with_spam if {
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
	lib.assert_equal(expected_tasks, tkn.tasks(pipeline))

	expected_names := {"git-clone", "buildah", "buildah[NETWORK=none]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected_names, tkn.tasks_names(pipeline))
}

test_build_task if {
	expected := _good_build_task
	lib.assert_equal(expected, tkn.build_task(_good_attestation))
}

test_build_task_not_found if {
	missing_image_url := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/0/results/0/name",
		"value": "IMAGE_URL_SKIP",
	}])
	not tkn.build_task(missing_image_url)

	missing_image_digest := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/0/results/1/name",
		"value": "IMAGE_DIGEST_SKIP",
	}])
	not tkn.build_task(missing_image_digest)

	missing_results := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/0/results"])
	not tkn.build_task(missing_results)
}

test_git_clone_task if {
	expected := _good_git_clone_task
	lib.assert_equal(expected, tkn.git_clone_task(_good_attestation))
}

test_git_clone_task_not_found if {
	missing_url := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/1/results/0/name",
		"value": "you-argh-el",
	}])
	not tkn.git_clone_task(missing_url)

	missing_commit := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/1/results/1/name",
		"value": "bachelor",
	}])
	not tkn.git_clone_task(missing_commit)

	missing_results := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/1/results"])
	not tkn.git_clone_task(missing_results)
}

test_task_data_bundle_ref if {
	lib.assert_equal(
		{
			"bundle": "bundle",
			"name": "ref-name",
		},
		tkn.task_data({
			"name": "name",
			"ref": {
				"name": "ref-name",
				"kind": "Task",
				"bundle": "bundle",
			},
		}),
	)
}

test_task_names_local if {
	lib.assert_equal(
		{
			"buildah",
			"buildah[DOCKERFILE=./image_with_labels/Dockerfile]",
			"buildah[IMAGE=quay.io/jstuart/hacbs-docker-build]",
		},
		tkn.task_names(slsav1_attestation_local_spec),
	)
}

test_task_data_no_bundle_ref if {
	lib.assert_equal({"name": "name"}, tkn.task_data({"ref": {"name": "name"}}))
}

test_missing_required_tasks_data if {
	lib.assert_equal(tkn.missing_required_tasks_data, true) with data["required-tasks"] as []
	lib.assert_equal(tkn.missing_required_tasks_data, false) with data["required-tasks"] as _time_based_required_tasks
}

test_task_step_image_ref if {
	lib.assert_equal(
		"redhat.io/openshift/rhel8@sha256:af7dd5b3b",
		tkn.task_step_image_ref({"name": "mystep", "imageID": "redhat.io/openshift/rhel8@sha256:af7dd5b3b"}),
	)
	lib.assert_equal(
		"redhat.io/openshift/rhel8@sha256:af7dd5b3b",
		tkn.task_step_image_ref({"environment": {"image": "redhat.io/openshift/rhel8@sha256:af7dd5b3b"}}),
	)
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

_good_attestation := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [_good_build_task, _good_git_clone_task]},
}}}

slsav1_attestation_local_spec := {
	"params": [
		{
			"name": "IMAGE",
			"value": "quay.io/jstuart/hacbs-docker-build",
		},
		{
			"name": "DOCKERFILE",
			"value": "./image_with_labels/Dockerfile",
		},
	],
	"serviceAccountName": "default",
	"taskRef": {
		"name": "buildah",
		"kind": "Task",
	},
	"timeout": "1h0m0s",
	"podTemplate": {
		"securityContext": {"fsGroup": 65532},
		"imagePullSecrets": [{"name": "docker-chains"}],
	},
	"workspaces": [
		{
			"name": "source",
			"persistentVolumeClaim": {"claimName": "pvc-bf2ed289ae"},
		},
		{
			"name": "dockerconfig",
			"secret": {"secretName": "docker-credentials"},
		},
	],
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

slsav1_task(name) := task if {
	parts := regex.split(`[\[\]=]`, name)
	not parts[1]
	pipeline_task_name := sprintf("%s-p", [name])
	unnamed_task := {
		"metadata": {"name": pipeline_task_name},
		"spec": slsav1_attestation_local_spec,
		"status": {"conditions": [{
			"type": "Succeeded",
			"status": "True",
		}]},
	}
	task := json.patch(unnamed_task, [{
		"op": "replace",
		"path": "/spec/taskRef/name",
		"value": name,
	}])
}

slsav1_task(name) := task if {
	parts := regex.split(`[\[\]=]`, name)
	parts[1]
	task_name := parts[0]
	pipeline_task_name := sprintf("%s-p", [task_name])
	unnamed_task := {
		"metadata": {"name": pipeline_task_name},
		"spec": slsav1_attestation_local_spec,
		"status": {"conditions": [{
			"type": "Succeeded",
			"status": "True",
		}]},
	}
	task := json.patch(unnamed_task, [
		{
			"op": "replace",
			"path": "/spec/taskRef/name",
			"value": task_name,
		},
		{
			"op": "replace",
			"path": "/spec/params",
			"value": [{"name": parts[1], "value": parts[2]}],
		},
	])
}

# create a task and add a bundle to it
slsav1_task_bundle(name, bundle) := task if {
	not name.spec
	task := json.patch(slsav1_task(name), [{
		"op": "add",
		"path": "/spec/taskRef/bundle",
		"value": bundle,
	}])
}

# add a bundle to an existing task
slsav1_task_bundle(name, bundle) := task if {
	name.spec
	task := json.patch(name, [{
		"op": "add",
		"path": "/spec/taskRef/bundle",
		"value": bundle,
	}])
}

slsav1_task_steps(name, steps) := json.patch(
	slsav1_task(name),
	[
		{
			"op": "add",
			"path": "/status/taskSpec",
			"value": {},
		},
		{
			"op": "add",
			"path": "/status/taskSpec/steps",
			"value": steps,
		},
	],
)

# results are an array of dictionaries with keys, "name", "type", "value"
slsav1_task_result(name, results) := json.patch(
	slsav1_task(name),
	[{
		"op": "add",
		"path": "/status/taskResults",
		"value": results,
	}],
)

# results are an array of dictionaries with keys, "name", "type", "value"
slsav1_task_result_ref(name, results) := json.patch(
	slsav1_task(name),
	[{
		"op": "add",
		"path": "/status/taskResults",
		"value": _marshal_slsav1_results(results),
	}],
)

_marshal_slsav1_results(results) := [r |
	some result in results
	r := {"name": result.name, "type": result.type, "value": json.marshal(result.value)}
]

resolved_dependencies(tasks) := [r |
	some task in tasks
	r := {
		"name": "pipelineTask",
		"content": base64.encode(json.marshal(task)),
	}
]
