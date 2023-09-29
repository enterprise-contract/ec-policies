package lib.refs_test

import data.lib
import data.lib.refs

test_bundle_in_pipelinerun {
	image := "registry.img/test@sha256:digest"
	ref := {"ref": {"bundle": image, "kind": "Task", "name": "test"}}
	info := {"bundle": image, "kind": "task", "name": "test"}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_bundle_resolver_in_pipelinerun {
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

test_bundle_in_pipeline {
	image := "registry.img/test@sha256:digest"
	ref := {"taskRef": {"bundle": image, "name": "test", "kind": "Task"}}
	info := {"bundle": image, "kind": "task", "name": "test"}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_bundle_resolver_in_pipeline {
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

test_bundle_in_pipelinerun_with_defaults {
	image := "registry.img/test@sha256:digest"
	ref := {"ref": {"bundle": image}}
	info := {"bundle": image, "kind": "task", "name": ""}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_bundle_resolver_in_pipelinerun_with_defaults {
	image := "registry.img/test@sha256:digest"
	ref := {"ref": {
		"resolver": "bundles",
		"params": [{"name": "bundle", "value": image}],
	}}

	info := {"bundle": image, "kind": "task", "name": ""}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_slsav1_local_ref {
	ref := {"spec": {"taskRef": {"name": "task-name", "kind": "Task"}}}
	info := {"kind": "task", "name": "task-name"}
	lib.assert_equal(refs.task_ref(ref), info)
}

test_git_resolver_in_slsav1_pipelinerun {
	ref := {"spec": {"taskRef": {
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
		"name": "pipelines/git-clone.yaml",
		"kind": "task",
	}
	lib.assert_equal(refs.task_ref(ref), info)
}
