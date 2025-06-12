# regal ignore:file-length
package lib.tekton_test

import rego.v1

import data.lib
import data.lib.tekton

test_latest_required_tasks if {
	expected := [t | some t in _expected_latest.tasks]
	lib.assert_equal(
		expected,
		tekton.latest_required_default_tasks.tasks,
	) with data["required-tasks"] as _time_based_required_tasks
}

test_current_required_tasks if {
	expected := [t | some t in _expected_current.tasks]
	lib.assert_equal(
		expected,
		tekton.current_required_default_tasks.tasks,
	) with data["required-tasks"] as _time_based_required_tasks
}

test_tasks_from_attestation if {
	git_clone := {"name": "ignored", "ref": {"name": "git-clone"}}
	buildah := {"name": "ignored", "ref": {"name": "buildah"}}

	attestation := {"statement": {"predicate": {"buildConfig": {"tasks": [git_clone, buildah]}}}}
	expected := {git_clone, buildah}
	lib.assert_equal(expected, tekton.tasks(attestation))
}

# regal ignore:rule-length
test_tasks_from_slsav1_tekton_attestation if {
	content := base64.encode(json.marshal(slsav1_attestation_local_spec))
	task := {
		"name": "pipelineTask",
		"uri": "oci://gcr.io/tekton-releases/github.com/tektoncd/pipeline/cmd/git-init",
		"digest": {"sha256": "28ff94e63e4058afc3f15b4c11c08cf3b54fa91faa646a4bbac90380cd7158df"},
		"content": content,
	}

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			"resolvedDependencies": [task],
		}},
	}}
	expected := {slsav1_attestation_local_spec}
	lib.assert_equal(expected, tekton.tasks(attestation))
}

# regal ignore:rule-length
test_tasks_from_slsav1_tekton_mixture_attestation if {
	task1 := json.patch(slsav1_attestation_local_spec, [{
		"op": "add",
		"path": "/taskRef/name",
		"value": "task1",
	}])
	task2 := json.patch(slsav1_attestation_local_spec, [{
		"op": "add",
		"path": "/taskRef/name",
		"value": "task2",
	}])
	task3 := json.patch(slsav1_attestation_local_spec, [{
		"op": "add",
		"path": "/taskRef/name",
		"value": "task3",
	}])

	git_init := {
		"name": "task",
		"uri": "oci://gcr.io/tekton-releases/github.com/tektoncd/pipeline/cmd/git-init",
		"digest": {"sha256": "28ff94e63e4058afc3f15b4c11c08cf3b54fa91faa646a4bbac90380cd7158df"},
		"content": base64.encode(json.marshal(task1)),
	}
	git_init_pipeline := {
		"name": "pipelineTask",
		"uri": "oci://gcr.io/tekton-releases/github.com/tektoncd/pipeline/cmd/git-init",
		"digest": {"sha256": "28ff94e63e4058afc3f15b4c11c08cf3b54fa91faa646a4bbac90380cd7158df"},
		"content": base64.encode(json.marshal(task2)),
	}
	git_init_bad := {
		"name": "pipeline",
		"uri": "oci://gcr.io/tekton-releases/github.com/tektoncd/pipeline/cmd/git-init",
		"digest": {"sha256": "28ff94e63e4058afc3f15b4c11c08cf3b54fa91faa646a4bbac90380cd7158df"},
		"content": base64.encode(json.marshal(task3)),
	}

	attestation := {"statement": {"predicate": {"buildDefinition": {
		"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
		"resolvedDependencies": [
			git_init,
			git_init_pipeline,
			git_init_bad,
		],
	}}}}
	expected := {
		task1,
		task2,
	}
	lib.assert_equal(expected, tekton.tasks(attestation))
}

test_tasks_from_slsav1_attestation if {
	git_init := {
		"name": "task/git-init",
		"uri": "oci://gcr.io/tekton-releases/github.com/tektoncd/pipeline/cmd/git-init",
		"digest": {"sha256": "28ff94e63e4058afc3f15b4c11c08cf3b54fa91faa646a4bbac90380cd7158df"},
	}
	attestation := {"statement": {"predicate": {"buildDefinition": {
		"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
		"resolvedDependencies": [git_init],
	}}}}
	lib.assert_equal(set(), tekton.tasks(attestation))
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
	lib.assert_equal(expected, tekton.tasks(pipeline))
}

test_tasks_from_partial_pipeline if {
	lib.assert_empty(tekton.tasks({"kind": "Pipeline"}))
	lib.assert_empty(tekton.tasks({"kind": "Pipeline", "spec": {}}))

	git_clone := {"taskRef": {"name": "git-clone"}}
	lib.assert_equal({git_clone}, tekton.tasks({"kind": "Pipeline", "spec": {"tasks": [git_clone]}}))
	lib.assert_equal({git_clone}, tekton.tasks({"kind": "Pipeline", "spec": {"finally": [git_clone]}}))
}

test_tasks_not_found if {
	lib.assert_empty(tekton.tasks({}))
}

test_task_param if {
	task := {"params": [{"name": "NETWORK", "value": "none"}]}
	lib.assert_equal("none", tekton.task_param(task, "NETWORK"))
	not tekton.task_param(task, "missing")
}

test_task_slsav1_param if {
	task := {
		"kind": "TaskRun",
		"metadata": {"name": "buildah"},
		"spec": {"params": [{"name": "NETWORK", "value": "none"}]},
	}
	lib.assert_equal("none", tekton.task_param(task, "NETWORK"))
	not tekton.task_param(task, "missing")
}

test_task_result if {
	task := {"results": [{"name": "SPAM", "value": "maps"}]}
	lib.assert_equal("maps", tekton.task_result(task, "SPAM"))
	not tekton.task_result(task, "missing")

	slsav1_task := {"status": {"taskResults": [{"name": "SPAM", "value": "maps"}]}}
	lib.assert_equal("maps", tekton.task_result(slsav1_task, "SPAM"))
	not tekton.task_result(slsav1_task, "missing")
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

	lib.assert_equal(expected_tasks, tekton.tasks(attestation))

	expected_names := {"git-clone", "buildah", "buildah[HERMETIC=true]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected_names, tekton.tasks_names(attestation))
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
	lib.assert_equal(expected_tasks, tekton.tasks(pipeline))

	expected_names := {"git-clone", "buildah", "buildah[NETWORK=none]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected_names, tekton.tasks_names(pipeline))
}

test_build_task if {
	expected := [_good_build_task, _good_source_build_task]
	lib.assert_equal(expected, tekton.build_tasks(_good_attestation))
}

test_build_task_with_artifact_uri if {
	artifact_uri_result := json.patch(_good_attestation, [
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/name",
			"value": "ARTIFACT_URI",
		},
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/1/name",
			"value": "ARTIFACT_DIGEST",
		},
	])
	count(tekton.build_tasks(artifact_uri_result)) == 2
}

test_build_task_with_artifact_output if {
	artifact_uri_result := json.patch(_good_attestation, [
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/name",
			"value": "ARTIFACT_OUTPUTS",
		},
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/value",
			"value": {"uri": "img1", "digest": "1234"},
		},
		{
			"op": "remove",
			"path": "/statement/predicate/buildConfig/tasks/0/results/1",
		},
	])
	count(tekton.build_tasks(artifact_uri_result)) == 2
}

test_build_task_with_images if {
	artifact_uri_result := json.patch(_good_attestation, [
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/name",
			"value": "IMAGES",
		},
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/value",
			"value": "img1@sha256:digest1, img2@sha256:digest2",
		},
		{
			"op": "remove",
			"path": "/statement/predicate/buildConfig/tasks/0/results/1",
		},
	])
	count(tekton.build_tasks(artifact_uri_result)) == 2
}

test_build_task_not_found if {
	missing_image_url := json.patch(_good_attestation, [
		{
			"op": "add",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/name",
			"value": "IMAGE_URL_SKIP",
		},
		{
			"op": "add",
			"path": "/statement/predicate/buildConfig/tasks/2/results/0/name",
			"value": "IMAGE_URL_SKIP",
		},
	])
	count(tekton.build_tasks(missing_image_url)) == 0

	missing_image_digest := json.patch(_good_attestation, [
		{
			"op": "add",
			"path": "/statement/predicate/buildConfig/tasks/0/results/1/name",
			"value": "IMAGE_DIGEST_SKIP",
		},
		{
			"op": "add",
			"path": "/statement/predicate/buildConfig/tasks/2/results/1/name",
			"value": "IMAGE_DIGEST_SKIP",
		},
	])
	count(tekton.build_tasks(missing_image_digest)) == 0

	missing_results := json.remove(_good_attestation, [
		"/statement/predicate/buildConfig/tasks/0/results",
		"/statement/predicate/buildConfig/tasks/2/results",
	])
	count(tekton.build_tasks(missing_results)) == 0
}

test_pre_build_tasks if {
	expected := [_pre_build_task]
	lib.assert_equal(expected, tekton.pre_build_tasks(_good_attestation))
}

test_multiple_build_tasks if {
	task1 := json.patch(_good_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "buildah-1",
	}])

	task2 := json.patch(_good_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "buildah-2",
	}])

	task3 := json.patch(_good_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "buildah-3",
	}])

	attestation3 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, task2, task3]},
	}}}

	count(tekton.build_tasks(attestation3)) == 3

	attestation2 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, _good_git_clone_task, task3]},
	}}}

	count(tekton.build_tasks(attestation2)) == 2
}

test_git_clone_task if {
	expected := _good_git_clone_task
	lib.assert_equal([expected], tekton.git_clone_tasks(_good_attestation))
}

test_git_clone_task_not_found if {
	missing_url := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/1/results/0/name",
		"value": "you-argh-el",
	}])
	count(tekton.git_clone_tasks(missing_url)) == 0

	missing_commit := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/1/results/1/name",
		"value": "bachelor",
	}])
	count(tekton.git_clone_tasks(missing_commit)) == 0

	missing_results := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/1/results"])
	count(tekton.git_clone_tasks(missing_results)) == 0
}

test_multiple_git_clone_tasks if {
	task1 := json.patch(_good_git_clone_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "git-clone-1",
	}])

	task2 := json.patch(_good_git_clone_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "git-clone-2",
	}])

	task3 := json.patch(_good_git_clone_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "git-clone-3",
	}])

	attestation3 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, task2, task3]},
	}}}

	count(tekton.git_clone_tasks(attestation3)) == 3

	attestation2 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, _good_build_task, task3]},
	}}}

	count(tekton.git_clone_tasks(attestation2)) == 2
}

test_source_build_task if {
	expected := _good_source_build_task
	lib.assert_equal([expected], tekton.source_build_tasks(_good_attestation))
}

test_source_build_task_not_found if {
	missing_image_url := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/2/results/0/name",
		"value": "ee-mah-gee-you-argh-el",
	}])
	count(tekton.source_build_tasks(missing_image_url)) == 0

	missing_image_digest := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/2/results/1/name",
		"value": "still-raw",
	}])
	count(tekton.source_build_tasks(missing_image_digest)) == 0

	missing_results := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/2/results"])
	count(tekton.source_build_tasks(missing_results)) == 0
}

test_multiple_source_build_tasks if {
	task1 := json.patch(_good_source_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "source-build-1",
	}])

	task2 := json.patch(_good_source_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "source-build-2",
	}])

	task3 := json.patch(_good_source_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "source-build-3",
	}])

	attestation_with_3 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, task2, task3]},
	}}}

	count(tekton.source_build_tasks(attestation_with_3)) == 3

	attestation_with_2 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, _good_build_task, task3]},
	}}}

	count(tekton.source_build_tasks(attestation_with_2)) == 2
}

test_task_data_bundle_ref if {
	lib.assert_equal(
		{
			"bundle": "bundle",
			"name": "ref-name",
		},
		tekton.task_data({
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
		tekton.task_names(slsav1_attestation_local_spec),
	)
}

test_task_data_no_bundle_ref if {
	lib.assert_equal({"name": "name"}, tekton.task_data({"ref": {"name": "name"}}))
}

test_missing_required_tasks_data if {
	lib.assert_equal(tekton.missing_required_tasks_data, true) with data["required-tasks"] as []
	lib.assert_equal(tekton.missing_required_tasks_data, false) with data["required-tasks"] as _time_based_required_tasks
}

test_task_step_image_ref if {
	lib.assert_equal(
		"redhat.io/openshift/rhel8@sha256:af7dd5b3b",
		tekton.task_step_image_ref({"name": "mystep", "imageID": "redhat.io/openshift/rhel8@sha256:af7dd5b3b"}),
	)
	lib.assert_equal(
		"redhat.io/openshift/rhel8@sha256:af7dd5b3b",
		tekton.task_step_image_ref({"environment": {"image": "redhat.io/openshift/rhel8@sha256:af7dd5b3b"}}),
	)
}

test_pipeline_task_slsav1 if {
	slsav1_task_spec := {"metadata": {
		"name": "clone-build-push-run-cb7ch-build-push",
		"labels": {
			"app.kubernetes.io/managed-by": "tekton-pipelines",
			"app.kubernetes.io/version": "0.5",
			"tekton.dev/memberOf": "tasks",
			"tekton.dev/pipeline": "clone-build-push-run-cb7ch",
			"tekton.dev/pipelineRun": "clone-build-push-run-cb7ch",
			"tekton.dev/pipelineTask": "build-push",
			"tekton.dev/task": "buildah",
		},
	}}
	lib.assert_equal(tekton.pipeline_task_name(slsav1_task_spec), "build-push")
	lib.assert_equal(tekton.pipeline_task_name(slsav1_task("my-pipeline")), "my-pipeline")
}

test_pipeline_task_slsav02 if {
	slsav02_inline_task_spec := {
		"name": "copy-settings",
		"after": ["clone-repository"],
		"ref": {},
	}
	lib.assert_equal(tekton.pipeline_task_name(slsav02_inline_task_spec), "copy-settings")

	task := {"name": "git-clone-p", "ref": {"name": "git-clone"}}
	lib.assert_equal(tekton.pipeline_task_name(task), "git-clone-p")
}

test_taskrun_labels_slsa02 if {
	task := {"invocation": {"environment": {"labels": {
		"l1": "v1",
		"l2": "v2",
	}}}}
	lib.assert_equal(tekton.task_labels(task), {"l1": "v1", "l2": "v2"})
}

test_taskrun_annotations_slsa02 if {
	task := {"invocation": {"environment": {"annotations": {
		"a1": "v1",
		"a2": "v2",
	}}}}
	lib.assert_equal(tekton.task_annotations(task), {"a1": "v1", "a2": "v2"})
}

test_taskrun_labels_slsa1 if {
	task := {"metadata": {"labels": {
		"l1": "v1",
		"l2": "v2",
	}}}
	lib.assert_equal(tekton.task_labels(task), {"l1": "v1", "l2": "v2"})
}

test_taskrun_annotations_slsa1 if {
	task := {"metadata": {"annotations": {
		"a1": "v1",
		"a2": "v2",
	}}}
	lib.assert_equal(tekton.task_annotations(task), {"a1": "v1", "a2": "v2"})
}

test_task_result_endswith if {
	results := [
		{
			"name": "ARTIFACT_URI",
			"value": "image1",
		},
		{
			"name": "ARTIFACT_DIGEST",
			"value": "1234",
		},
		{
			"name": "1234_ARTIFACT_URI",
			"value": "1234-image1",
		},
		{
			"name": "1234_ARTIFACT_DIGEST",
			"value": "1234-digest",
		},
	]
	task1 := slsav1_task_result("task1", results)
	lib.assert_equal(["1234-image1", "image1"], tekton.task_result_endswith(task1, "ARTIFACT_URI"))
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

_pre_build_task := {
	"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": _bundle},
	"invocation": {"parameters": {"HERMETIC": "true"}},
}

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

_good_source_build_task := {
	"results": [
		{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo"},
		{"name": "SOURCE_IMAGE_DIGEST", "value": "250e77f12a5ab6972a0895d290c4792f0a326ea8"},
	],
	"ref": {"kind": "Task", "name": "source-build", "bundle": _bundle},
}

_good_attestation := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [_good_build_task, _good_git_clone_task, _good_source_build_task, _pre_build_task]},
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
	"results": [
		{
			"name": "IMAGE_DIGEST",
			"type": "string",
			"value": "sha256:hash",
		},
		{
			"name": "IMAGE_URL",
			"type": "string",
			"value": "quay.io/jstuart/hacbs-docker-build:tag@sha256:hash",
		},
	],
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
	pipeline_task_name := sprintf("%s", [name])
	unnamed_task := {
		"metadata": {
			"name": pipeline_task_name,
			"labels": {"tekton.dev/pipelineTask": pipeline_task_name},
		},
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

	# regal ignore:redundant-existence-check
	parts[1]
	task_name := parts[0]
	pipeline_task_name := sprintf("%s", [task_name])
	unnamed_task := {
		"metadata": {
			"name": pipeline_task_name,
			"labels": {"tekton.dev/pipelineTask": pipeline_task_name},
		},
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
