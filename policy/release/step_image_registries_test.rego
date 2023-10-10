package policy.release.step_image_registries_test

import future.keywords.if

import data.lib
import data.lib.tkn_test
import data.lib_test
import data.policy.release.step_image_registries

good_image := "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b"

good_oci_image := sprintf("oci://%s", [good_image])

bad_image := "hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b"

bad_oci_image := sprintf("oci://%s", [bad_image])

unexpected_image := sprintf("spam://%s", [good_image])

mock_data(image_ref) := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [{
		"name": "mytask",
		"ref": {"kind": "task", "name": "mytask"},
		"steps": [{"environment": {"image": image_ref}}],
	}]},
}}}

mock_slsav1_data(image_ref) := lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_steps("mytask", [{
	"name": "mystep",
	"image": image_ref,
}])])

test_image_registry_valid if {
	attestations := [
		mock_data(good_image),
		mock_data(good_oci_image),
		mock_slsav1_data(good_image),
		mock_slsav1_data(good_oci_image),
	]
	lib.assert_empty(step_image_registries.deny) with input.attestations as attestations
	lib.assert_empty(step_image_registries.deny) with input.attestations as attestations
}

test_attestation_type_invalid if {
	bad_attestations := [
		mock_data(bad_image),
		mock_slsav1_data(bad_image),
	]
	lib.assert_equal_results(step_image_registries.deny, {{
		"code": "step_image_registries.task_step_images_permitted",
		"msg": sprintf("Step 0 in task 'mytask' has disallowed image ref '%s'", [bad_image]),
	}}) with input.attestations as bad_attestations

	bad_oci_attestations := [
		mock_data(bad_oci_image),
		mock_slsav1_data(bad_oci_image),
	]
	lib.assert_equal_results(step_image_registries.deny, {{
		"code": "step_image_registries.task_step_images_permitted",
		"msg": sprintf("Step 0 in task 'mytask' has disallowed image ref '%s'", [bad_oci_image]),
	}}) with input.attestations as bad_oci_attestations
}

test_unexpected_image_ref if {
	lib.assert_equal_results(step_image_registries.deny, {{
		"code": "step_image_registries.task_step_images_permitted",
		"msg": sprintf("Step 0 in task 'mytask' has disallowed image ref '%s'", [unexpected_image]),
	}}) with input.attestations as mock_data(unexpected_image)
}

test_step_image_registry_prefix_list_found if {
	expected := {{
		"code": "step_image_registries.step_image_registry_prefix_list_provided",
		"msg": "Missing required allowed_step_image_registry_prefixes rule data",
	}}
	lib.assert_equal_results(expected, step_image_registries.deny) with data.rule_data as {}
}
