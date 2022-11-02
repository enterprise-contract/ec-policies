package policy.release.base_image_registries

import data.lib
import data.lib.bundles

test_acceptable_base_images {
	attestations := [lib.att_mock_helper_ref_plain_result(
		lib.build_base_images_digests_result_name,
		concat("\n", [
			"registry.redhat.io/ubi7:latest@sha256:abc",
			"registry.access.redhat.com/ubi8:8.9@sha256:bcd",
			"", # Verify trailing new line is ignored
		]),
		"buildah-task-1",
		bundles.acceptable_bundle_ref,
	)]
	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as attestations
}

test_empty_base_images {
	attestations := [lib.att_mock_helper_ref_plain_result(
		lib.build_base_images_digests_result_name,
		"",
		"buildah-task-1",
		bundles.acceptable_bundle_ref,
	)]
	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as attestations
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
		bundles.acceptable_bundle_ref,
	)]
	expected := {
		{
			"code": "disallowed_base_image",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Base image \"docker.io/busybox:latest@sha256:bcd\" is from a disallowed registry",
		},
		{
			"code": "disallowed_base_image",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Base image \"registry.redhat.ioo/spam:latest@sha256:def\" is from a disallowed registry",
		},
	}
	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as attestations
}

test_unacceptable_bundle {
	attestations := [lib.att_mock_helper_ref_plain_result(
		lib.build_base_images_digests_result_name,
		"registry.redhat.io/ubi7:latest@sha256:abc",
		"buildah-task-1",
		"registry.img/unacceptable@sha256:012",
	)]
	expected := {{
		"code": "base_images_missing",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Base images result is missing",
	}}
	lib.assert_equal(deny, expected) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as attestations
}
