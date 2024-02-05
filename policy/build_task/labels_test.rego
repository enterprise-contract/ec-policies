package policy.build_task.labels_test

import rego.v1

import data.lib
import data.policy.build_task.labels

test_build_label_found if {
	# regal ignore:line-length
	lib.assert_empty(labels.deny) with input as {"metadata": {"labels": {"build.appstudio.redhat.com/build_type": "docker"}}}
}

test_build_label_not_found if {
	lib.assert_equal_results(labels.deny, {{
		"code": "labels.build_type_label_set",
		"msg": "The required build label 'build.appstudio.redhat.com/build_type' is missing",
	}}) with input as {"metadata": {"labels": {"bad": "docker"}}}
}

test_no_labels if {
	lib.assert_equal_results(labels.deny, {{
		"code": "labels.build_task_has_label",
		"msg": "The task definition does not include any labels",
	}}) with input as {"metadata": {"name": "no_labels"}}
}
