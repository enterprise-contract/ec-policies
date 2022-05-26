package policies.step_image_registries

import data.lib

good_image := "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b"

bad_image := "hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b"

mock_data(image_ref) = d {
	d := [{"predicate": {
		"buildType": lib.pipelinerun_att_build_type,
		"buildConfig": {"tasks": [{"name": "mytask", "steps": [{"environment": {"image": image_ref}}]}]},
	}}]
}

test_image_registry_valid {
	lib.assert_empty(deny) with input.attestations as mock_data(good_image)
}

test_attestation_type_invalid {
	expected_msg := sprintf("Step 0 in task 'mytask' has disallowed image ref '%s'", [bad_image])
	lib.assert_equal(deny, {{"code": "disallowed_task_step_image", "msg": expected_msg}}) with input.attestations as mock_data(bad_image)
}
