package policy.release.base_image_registries_test

import rego.v1

import data.lib
import data.lib.tkn_test
import data.lib_test
import data.policy.release.base_image_registries

mock_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

test_allowed_base_images if {
	slsav1_task_with_result := tkn_test.slsav1_task_result(
		"buildah-task-1",
		[{
			"name": lib.build_base_images_digests_result_name,
			"type": "string",
			"value": concat("\n", [
				"registry.redhat.io/ubi7:latest@sha256:abc",
				"docker.io/library/registry:latest@sha256:bcd",
				"", # Verify trailing new line is ignored
			]),
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref_plain_result(
			lib.build_base_images_digests_result_name,
			concat("\n", [
				"registry.redhat.io/ubi7:latest@sha256:abc",
				"docker.io/library/registry:latest@sha256:bcd",
				"", # Verify trailing new line is ignored
			]),
			"buildah-task-1",
			mock_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, mock_bundle)]),
	]

	sboms := [{"formulation": [
		{"components": [{
			"name": "registry.redhat.io/ubi7:latest@sha256:abc",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "true",
			}],
		}]},
		{"components": [{
			"name": "docker.io/library/registry:latest@sha256:bcd",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
		}]},
	]}]

	lib.assert_empty(base_image_registries.deny) with input.attestations as attestations
		with lib.sbom.cyclonedx_sboms as sboms
}

test_allowed_base_images_from_snapshot if {
	sboms := [{"formulation": [
		{"components": [{
			"name": "registry.redhat.io/ubi7:latest@sha256:abc",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "true",
			}],
		}]},
		{"components": [{
			"name": "docker.io/library/registry:latest@sha256:bcd",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
		}]},
	]}]

	snapshot := {"components": [
		{"containerImage": "ignored.io/ignore@sha256:abc"},
		{"containerImage": "ignored.dev/ignore:ignore@sha256:bcd"},
	]}

	lib.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
		with data.rule_data.allowed_registry_prefixes as ["another.registry.io"]
		with input.snapshot as snapshot
}

test_empty_base_images_result if {
	slsav1_task_with_result := tkn_test.slsav1_task_result(
		"buildah-task-1",
		[{
			"name": lib.build_base_images_digests_result_name,
			"type": "string",
			"value": "",
		}],
	)

	attestations := [
		lib_test.att_mock_helper_ref_plain_result(
			lib.build_base_images_digests_result_name,
			"",
			"buildah-task-1",
			mock_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, mock_bundle)]),
	]
	lib.assert_empty(base_image_registries.deny) with input.attestations as attestations
}

test_disallowed_base_images if {
	slsav1_task_with_result := tkn_test.slsav1_task_result(
		"buildah-task-1",
		[{
			"name": lib.build_base_images_digests_result_name,
			"type": "string",
			"value": concat("\n", [
				"registry.redhat.io/ubi7:latest@sha256:abc1",
				"dockery.io/busybox:latest@sha256:bcd1",
				"registry.redhat.ioo/spam:latest@sha256:def1",
			]),
		}],
	)
	attestations := [
		lib_test.att_mock_helper_ref_plain_result(
			lib.build_base_images_digests_result_name,
			concat("\n", [
				"registry.redhat.io/ubi7:latest@sha256:abc2",
				"dockery.io/busybox:latest@sha256:bcd2",
				"registry.redhat.ioo/spam:latest@sha256:def2",
			]),
			"buildah-task-1",
			mock_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(slsav1_task_with_result, mock_bundle)]),
	]

	sboms := [{"formulation": [
		{"components": [{
			"name": "registry.redhat.yo/ubi7/3",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "true",
			}],
		}]},
		{"components": [{
			"name": "dockery.io/busybox/3",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
		}]},
		{"components": [{
			"name": "registry.redhat.ioo/spam/3",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "1",
			}],
		}]},
	]}]

	expected := {
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"dockery.io/busybox:latest@sha256:bcd1\" is from a disallowed registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.ioo/spam:latest@sha256:def1\" is from a disallowed registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"dockery.io/busybox:latest@sha256:bcd2\" is from a disallowed registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.ioo/spam:latest@sha256:def2\" is from a disallowed registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.yo/ubi7/3\" is from a disallowed registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.ioo/spam/3\" is from a disallowed registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"dockery.io/busybox/3\" is from a disallowed registry",
		},
	}
	lib.assert_equal_results(base_image_registries.deny, expected) with input.attestations as attestations
		with lib.sbom.cyclonedx_sboms as sboms
}

test_disallowed_base_images_with_snapshot if {
	sboms := [{"formulation": [
		{"components": [{
			"name": "registry.redhat.io/ubi7:latest@sha256:abc",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "true",
			}],
		}]},
		{"components": [{
			"name": "docker.io/library/registry:latest@sha256:bcd",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
		}]},
	]}]

	snapshot := {"components": [
		{"containerImage": "ignored.io/ignore@sha256:cba"},
		{"containerImage": "ignored.dev/ignore:ignore@sha256:dcb"},
	]}

	expected := {
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"docker.io/library/registry:latest@sha256:bcd\" is from a disallowed registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.io/ubi7:latest@sha256:abc\" is from a disallowed registry",
		},
	}

	lib.assert_equal_results(base_image_registries.deny, expected) with lib.sbom.cyclonedx_sboms as sboms
		with data.rule_data.allowed_registry_prefixes as ["another.registry.io"]
		with input.snapshot as snapshot
}

test_sbom_base_image_selection if {
	sboms := [{"formulation": [
		{"components": [{
			"name": "registry.ignore.me/no-properties",
			"type": "container",
		}]},
		{"components": [{
			"name": "registry.ignore.me/is_base_image/false/value",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "false",
			}],
		}]},
		{"components": [{
			"name": "registry.ignore.me/is_base_image/0/value",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "0",
			}],
		}]},
		{"components": [{
			"name": "registry.ignore.me/is_base_image/non-marshaled-json/value",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": true,
			}],
		}]},
		{"components": [{
			"name": "registry.ignore.me/is_base_image/missing/value",
			"type": "container",
			"properties": [{"name": "konflux:container:is_base_image"}],
		}]},
		{"components": [{
			"name": "registry.ignore.me/for_stage/false/value",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "false",
			}],
		}]},
		{"components": [{
			"name": "registry.ignore.me/for_stage/non-marshaled-json/value",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": 1,
			}],
		}]},
		{"components": [{
			"name": "registry.ignore.me/for_stage/missing/value",
			"type": "container",
			"properties": [{"name": "konflux:container:is_builder_image:for_stage"}],
		}]},
	]}]

	lib.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
}

test_missing_result if {
	slsav1_task_with_result := tkn_test.slsav1_task_bundle(
		tkn_test.slsav1_task_result(
			"buildah-task-1",
			[{
				"name": "SPAM_SPAM_SPAM",
				"type": "string",
				"value": "registry.redhat.io/ubi7:latest@sha256:abc",
			}],
		),
		"registry.img/unacceptable@sha256:012",
	)

	attestations := [
		lib_test.att_mock_helper_ref_plain_result(
			"SPAM_SPAM_SPAM",
			"registry.redhat.io/ubi7:latest@sha256:abc",
			"buildah-task-1",
			"registry.img/unacceptable@sha256:012",
		),
		lib_test.mock_slsav1_attestation_with_tasks([slsav1_task_with_result]),
	]
	expected := {{
		"code": "base_image_registries.base_image_info_found",
		"msg": "Base images information is missing",
	}}
	lib.assert_equal_results(base_image_registries.deny, expected) with input.attestations as attestations
}

test_allowed_registries_provided if {
	expected := {{
		"code": "base_image_registries.allowed_registries_provided",
		"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
	}}
	lib.assert_equal_results(expected, base_image_registries.deny) with data.rule_data as {}
		with lib.sbom.cyclonedx_sboms as [{}]
}

test_rule_data_validation if {
	d := {"allowed_registry_prefixes": [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]}

	expected := {
		{
			"code": "base_image_registries.allowed_registries_provided",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): array items[1,2] must be unique",
		},
		{
			"code": "base_image_registries.allowed_registries_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
		},
	}

	lib.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as d
		with lib.sbom.cyclonedx_sboms as [{}]
}
