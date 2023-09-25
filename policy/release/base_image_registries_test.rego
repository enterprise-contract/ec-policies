package policy.release.base_image_registries_test

import data.lib
import data.lib_test
import data.policy.release.base_image_registries

mock_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

test_acceptable_base_images {
	attestations := [lib_test.att_mock_helper_ref_plain_result(
		lib.build_base_images_digests_result_name,
		concat("\n", [
			"registry.redhat.io/ubi7:latest@sha256:abc",
			"registry.access.redhat.com/ubi8:8.9@sha256:bcd",
			"", # Verify trailing new line is ignored
		]),
		"buildah-task-1",
		mock_bundle,
	)]
	lib.assert_empty(base_image_registries.deny) with input.attestations as attestations
}

test_empty_base_images {
	attestations := [lib_test.att_mock_helper_ref_plain_result(
		lib.build_base_images_digests_result_name,
		"",
		"buildah-task-1",
		mock_bundle,
	)]
	lib.assert_empty(base_image_registries.deny) with input.attestations as attestations
}

test_unacceptable_base_images {
	attestations := [lib_test.att_mock_helper_ref_plain_result(
		lib.build_base_images_digests_result_name,
		concat("\n", [
			"registry.redhat.io/ubi7:latest@sha256:abc",
			"docker.io/busybox:latest@sha256:bcd",
			"registry.access.redhat.com/ubi8:8.9@sha256:cde",
			"registry.redhat.ioo/spam:latest@sha256:def",
		]),
		"buildah-task-1",
		mock_bundle,
	)]
	expected := {
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"docker.io/busybox:latest@sha256:bcd\" is from a disallowed registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.ioo/spam:latest@sha256:def\" is from a disallowed registry",
		},
	}
	lib.assert_equal_results(base_image_registries.deny, expected) with input.attestations as attestations
}

test_missing_result {
	attestations := [lib_test.att_mock_helper_ref_plain_result(
		"SPAM_SPAM_SPAM",
		"registry.redhat.io/ubi7:latest@sha256:abc",
		"buildah-task-1",
		"registry.img/unacceptable@sha256:012",
	)]
	expected := {{
		"code": "base_image_registries.base_image_info_found",
		"msg": "Base images result is missing",
	}}
	lib.assert_equal_results(base_image_registries.deny, expected) with input.attestations as attestations
}

test_allowed_registries_provided {
	expected := {{
		"code": "base_image_registries.allowed_registries_provided",
		"msg": "Missing required allowed_registry_prefixes rule data",
	}}
	lib.assert_equal_results(expected, base_image_registries.deny) with data.rule_data as {}
}
