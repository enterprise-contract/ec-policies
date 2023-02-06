package policy.release.base_image_registries

import data.lib

mock_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

test_acceptable_base_images {
	attestations := [lib.att_mock_helper_ref_plain_result(
		lib.build_base_images_digests_result_name,
		concat("\n", [
			"registry.redhat.io/ubi7:latest@sha256:abc",
			"registry.access.redhat.com/ubi8:8.9@sha256:bcd",
			"", # Verify trailing new line is ignored
		]),
		"buildah-task-1",
		mock_bundle,
	)]
	lib.assert_empty(deny) with input.attestations as attestations
}

test_empty_base_images {
	attestations := [lib.att_mock_helper_ref_plain_result(
		lib.build_base_images_digests_result_name,
		"",
		"buildah-task-1",
		mock_bundle,
	)]
	lib.assert_empty(deny) with input.attestations as attestations
}

test_unacceptable_base_images {
	attestations := [lib.att_mock_helper_ref_plain_result(
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
			"code": "base_image_registries.disallowed_base_image",
			"collections": ["minimal"],
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Base image \"docker.io/busybox:latest@sha256:bcd\" is from a disallowed registry",
		},
		{
			"code": "base_image_registries.disallowed_base_image",
			"collections": ["minimal"],
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Base image \"registry.redhat.ioo/spam:latest@sha256:def\" is from a disallowed registry",
		},
	}
	lib.assert_equal(deny, expected) with input.attestations as attestations
}

test_missing_result {
	attestations := [lib.att_mock_helper_ref_plain_result(
		"SPAM_SPAM_SPAM",
		"registry.redhat.io/ubi7:latest@sha256:abc",
		"buildah-task-1",
		"registry.img/unacceptable@sha256:012",
	)]
	expected := {{
		"code": "base_image_registries.base_images_missing",
		"collections": ["minimal"],
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Base images result is missing",
	}}
	lib.assert_equal(deny, expected) with input.attestations as attestations
}

test_missing_rule_data {
	expected := {{
		"code": "base_image_registries.missing_rule_data",
		"collections": ["minimal"],
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Missing required allowed_registry_prefixes rule data",
	}}
	lib.assert_equal(expected, deny) with data.rule_data as {}
}
