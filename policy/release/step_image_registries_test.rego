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
	lib.assert_equal(deny, {{
		"code": "step_image_registries.disallowed_task_step_image",
		"collections": ["minimal"],
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as mock_data(bad_image)
}

test_missing_rule_data {
	expected := {{
		"code": "step_image_registries.missing_rule_data",
		"collections": ["minimal"],
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Missing required allowed_step_image_registry_prefixes rule data",
	}}
	lib.assert_equal(expected, deny) with data.rule_data as {}
}
