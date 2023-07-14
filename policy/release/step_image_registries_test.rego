package policy.release.step_image_registries

import data.lib

good_image := "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b"

bad_image := "hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b"

mock_data(image_ref) = d {
	d := [{"predicate": {
		"buildType": lib.pipelinerun_att_build_types[0],
		"buildConfig": {"tasks": [{"name": "mytask", "steps": [{"environment": {"image": image_ref}}]}]},
	}}]
}

test_image_registry_valid {
	lib.assert_empty(deny) with input.attestations as mock_data(good_image)
}

test_attestation_type_invalid {
	expected_msg := sprintf("Step 0 in task 'mytask' has disallowed image ref '%s'", [bad_image])
	lib.assert_equal_results(deny, {{
		"code": "step_image_registries.task_step_images_permitted",
		"msg": expected_msg,
	}}) with input.attestations as mock_data(bad_image)
}

test_step_image_registry_prefix_list_found {
	expected := {{
		"code": "step_image_registries.step_image_registry_prefix_list_provided",
		"msg": "Missing required allowed_step_image_registry_prefixes rule data",
	}}
	lib.assert_equal_results(expected, deny) with data.rule_data as {}
}
