package policy.task.build

import data.lib

test_build_label_found {
	lib.assert_empty(deny) with input as {"metadata": {"labels": {"build.appstudio.redhat.com/build_type": "docker"}}}
}

test_build_label_not_found {
	lib.assert_equal(deny, {{
		"code": "build.build_task_label_missing",
		"msg": "The required build label 'build.appstudio.redhat.com/build_type' is missing",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input as {"metadata": {"labels": {"bad": "docker"}}}
}

test_no_labels {
	lib.assert_equal(deny, {{
		"code": "build.build_task_no_labels",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "The task does not contain labels",
	}}) with input as {"metadata": {"name": "no_labels"}}
}
