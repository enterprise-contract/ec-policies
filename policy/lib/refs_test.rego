package lib.refs

import data.lib

test_bundle_in_pipelinerun {
	image := "registry.img/test@sha256:digest"
	ref := {"ref": {"bundle": image, "kind": "Task", "name": "test"}}
	info := {"bundle": image, "kind": "task", "name": "test"}
	lib.assert_equal(task_ref(ref), info)
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
	lib.assert_equal(task_ref(ref), info)
}

test_bundle_in_pipeline {
	image := "registry.img/test@sha256:digest"
	ref := {"taskRef": {"bundle": image, "name": "test", "kind": "Task"}}
	info := {"bundle": image, "kind": "task", "name": "test"}
	lib.assert_equal(task_ref(ref), info)
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
	lib.assert_equal(task_ref(ref), info)
}

test_bundle_in_pipelinerun_with_defaults {
	image := "registry.img/test@sha256:digest"
	ref := {"ref": {"bundle": image}}
	info := {"bundle": image, "kind": "task", "name": ""}
	lib.assert_equal(task_ref(ref), info)
}

test_bundle_resolver_in_pipelinerun_with_defaults {
	image := "registry.img/test@sha256:digest"
	ref := {"ref": {
		"resolver": "bundles",
		"params": [{"name": "bundle", "value": image}],
	}}

	info := {"bundle": image, "kind": "task", "name": ""}
	lib.assert_equal(task_ref(ref), info)
}
