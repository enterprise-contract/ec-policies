package hacbs.contract.step_image_registries

good_image := "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b"

bad_image := "hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b"

prepare_mock_rekor_data(image_specifier) = result {
	result := {"example.com": {"index": {"123": {"entry": {"Attestation": base64.encode(json.marshal({"predicate": {"buildConfig": {"steps": [{"environment": {"image": image_specifier}}]}}}))}}}}}
}

# A valid image registry
test_image_registry_valid {
	deny_set := deny with data.rekor as prepare_mock_rekor_data(good_image)
	count(deny_set) == 0
}

# A invalid image registry
test_attestation_type_invalid {
	deny_set := deny with data.rekor as prepare_mock_rekor_data(bad_image)
	count(deny_set) == 1
	expected_msg := "Step 0 has disallowed registry 'hackz.io/openshift-pipelines' for transparency log entry 123 on example.com."
	deny_set == {{"msg": expected_msg}}
}
