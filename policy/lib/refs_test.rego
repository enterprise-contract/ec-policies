package lib.refs_test

import data.lib
import data.lib.refs
import future.keywords.if

test_bundle_in_pipelinerun if {
	image := "registry.img/test@sha256:digest"
	ref := {"ref": {"bundle": image, "kind": "Task", "name": "test"}}
	info := {"bundle": image, "kind": "task", "name": "test"}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_bundle_resolver_in_pipelinerun if {
	image := "registry.img/test@sha256:digest"
	ref := {"ref": {
		"resolver": "bundles",
		"params": [
			{"name": "bundle", "value": image},
			{"name": "name", "value": "test"},
			{"name": "kind", "value": "task"},
		],
	}}

	info := {"bundle": image, "kind": "task", "name": "test"}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_bundle_in_pipeline if {
	image := "registry.img/test@sha256:digest"
	ref := {"taskRef": {"bundle": image, "name": "test", "kind": "Task"}}
	info := {"bundle": image, "kind": "task", "name": "test"}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_bundle_resolver_in_pipeline if {
	image := "registry.img/test@sha256:digest"
	ref := {"taskRef": {
		"resolver": "bundles",
		"params": [
			{"name": "bundle", "value": image},
			{"name": "name", "value": "test"},
			{"name": "kind", "value": "task"},
		],
	}}

	info := {"bundle": image, "kind": "task", "name": "test"}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_bundle_in_pipelinerun_with_defaults if {
	image := "registry.img/test@sha256:digest"
	ref := {"ref": {"bundle": image}}
	info := {"bundle": image, "kind": "task", "name": refs._no_task_name}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_bundle_resolver_in_pipelinerun_with_defaults if {
	image := "registry.img/test@sha256:digest"
	ref := {"ref": {
		"resolver": "bundles",
		"params": [{"name": "bundle", "value": image}],
	}}

	info := {"bundle": image, "kind": "task", "name": refs._no_task_name}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_slsav1_local_ref if {
	ref := {"spec": {"taskRef": {"name": "task-name", "kind": "Task"}}}
	info := {"kind": "task", "name": "task-name"}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_git_resolver_in_slsav1_pipelinerun if {
	ref := {"spec": {"taskRef": {
		"name": "git-clone",
		"kind": "Task",
		"resolver": "git",
		"params": [
			{
				"name": "url",
				"value": "https://github.com/enterprise-contract/hacbs-docker-build.git",
			},
			{
				"name": "revision",
				"value": "main",
			},
			{
				"name": "pathInRepo",
				"value": "pipelines/git-clone.yaml",
			},
		],
	}}}
	info := {
		"url": "https://github.com/enterprise-contract/hacbs-docker-build.git",
		"revision": "main", "pathInRepo": "pipelines/git-clone.yaml",
		"name": "git-clone",
		"kind": "task",
	}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_ref_name_slsa_v0_2 if {
	# Local reference
	lib.assert_equal(
		refs.task_ref({
			"name": "my-pipeline-task",
			"status": "Succeeded",
			"ref": {"name": "my-task", "kind": "Task"},
		}).name,
		"my-task",
	)

	# Git resolver
	lib.assert_equal(
		refs.task_ref({
			"name": "my-pipeline-task",
			"status": "Succeeded",
			"ref": {
				"kind": "Task",
				"resolver": "git",
				"params": [{"name": "revision", "value": "main"}],
			},
			"invocation": {"environment": {"labels": {"tekton.dev/task": "my-task"}}},
		}).name,
		"my-task",
	)

	# Bundles resolver
	lib.assert_equal(
		refs.task_ref({
			"name": "my-pipeline-task",
			"status": "Succeeded",
			"ref": {
				"kind": "Task",
				"resolver": "bundles",
				"params": [
					{"name": "bundle", "value": "registry.local/test:latest"},
					{"name": "name", "value": "my-task"},
				],
			},
		}).name,
		"my-task",
	)

	# Inlined definition
	lib.assert_equal(
		refs.task_ref({
			"name": "pipeline-task-06",
			"status": "Succeeded",
			"ref": {},
		}).name,
		refs._no_task_name,
	)
}

test_ref_name_slsa_v1_0 if {
	# Local reference
	lib.assert_equal(
		refs.task_ref({"spec": {"taskRef": {
			"name": "my-task",
			"kind": "Task",
		}}}).name,
		"my-task",
	)

	# Git resolver
	lib.assert_equal(
		refs.task_ref({
			"metadata": {"labels": {"tekton.dev/task": "my-task"}},
			"spec": {"taskRef": {
				"kind": "Task",
				"resolver": "git",
				"params": [{"name": "revision", "value": "main"}],
			}},
		}).name,
		"my-task",
	)

	# Bundles resolver
	lib.assert_equal(
		refs.task_ref({"spec": {"taskRef": {
			"kind": "Task",
			"resolver": "bundles",
			"params": [
				{"name": "bundle", "value": "registry.local/test:latest"},
				{"name": "name", "value": "my-task"},
			],
		}}}).name,
		"my-task",
	)

	# Inlined definition
	lib.assert_equal(
		refs.task_ref({"spec": {"taskSpec": {"steps": [], "params": []}}}).name,
		refs._no_task_name,
	)
}
