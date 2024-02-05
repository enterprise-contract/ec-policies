package policy.task.step_image_registries_test

import rego.v1

import data.lib
import data.policy.task.step_image_registries

good_image := "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b"

bad_image := "hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b"

test_step_images_permitted_success if {
	task := {
		"kind": "Task",
		"spec": {"steps": [{"image": good_image}, {"image": good_image}]},
	}

	lib.assert_empty(step_image_registries.deny) with input as task
}

test_step_images_permitted_failure if {
	task := {
		"kind": "Task",
		"spec": {"steps": [{"image": bad_image}, {"image": good_image}, {"image": bad_image}]},
	}

	expected := {
		{
			"code": "step_image_registries.step_images_permitted",
			"msg": "Step 0 uses disallowed image ref 'hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b'",
		},
		{
			"code": "step_image_registries.step_images_permitted",
			"msg": "Step 2 uses disallowed image ref 'hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b'",
		},
	}

	lib.assert_equal_results(step_image_registries.deny, expected) with input as task
}

test_step_images_permitted_skipped if {
	not_a_task := {
		"kind": "Taskinha",
		"spec": {"steps": [{"image": bad_image}]},
	}

	lib.assert_empty(step_image_registries.deny) with input as not_a_task
}

test_step_images_permitted_prefix_list_empty if {
	task := {
		"kind": "Task",
		"spec": {"steps": [{"image": good_image}]},
	}

	expected := {
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
		},
		{
			"code": "step_image_registries.step_images_permitted",
			# regal ignore:line-length
			"msg": "Step 0 uses disallowed image ref 'registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b'",
		},
	}

	lib.assert_equal_results(step_image_registries.deny, expected) with input as task
		with data.rule_data as {}
}

test_step_image_registry_prefix_list_format if {
	d := {"allowed_step_image_registry_prefixes": [
		# Wrong type
		1,
		# Duplicated items
		"registry.local/",
		"registry.local/",
	]}

	expected := {
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
		},
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): array items[1,2] must be unique",
		},
	}

	lib.assert_equal_results(expected, step_image_registries.deny) with data.rule_data as d
}
