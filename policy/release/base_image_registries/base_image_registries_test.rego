package base_image_registries_test

import rego.v1

import data.base_image_registries
import data.lib

test_allowed_base_images if {
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

	lib.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as _spdx_sbom
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
		with lib.sbom.spdx_sboms as _spdx_sbom
		with data.rule_data.allowed_registry_prefixes as ["another.registry.io"]
		with input.snapshot as snapshot
}

test_empty_base_images_result if {
	lib.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as [{}] with lib.sbom.spdx_sboms as [{}]
}

test_disallowed_base_images if {
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

	bad_spdx_sbom := json.patch(_spdx_sbom, [
		{"op": "replace", "path": "/0/packages/0/name", "value": "registry.redhat.blah/ubi7/3"},
		{"op": "replace", "path": "/0/packages/1/name", "value": "registry.redhat.whatever/ubi7/3"},
	])

	expected := {
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.yo/ubi7/3\" is from a disallowed registry",
			"term": "registry.redhat.yo/ubi7/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.ioo/spam/3\" is from a disallowed registry",
			"term": "registry.redhat.ioo/spam/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"dockery.io/busybox/3\" is from a disallowed registry",
			"term": "dockery.io/busybox/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.blah/ubi7/3\" is from a disallowed registry",
			"term": "registry.redhat.blah/ubi7/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.whatever/ubi7/3\" is from a disallowed registry",
			"term": "registry.redhat.whatever/ubi7/3",
		},
	}
	lib.assert_equal_results(base_image_registries.deny, expected) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as bad_spdx_sbom
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

	bad_spdx_sbom := json.patch(_spdx_sbom, [
		{"op": "replace", "path": "/0/packages/0/name", "value": "registry.redhat.blah/ubi7/3@sha256:ccc"},
		{"op": "replace", "path": "/0/packages/1/name", "value": "registry.redhat.whatever/ubi7/3@sha256:ccc"},
	])

	snapshot := {"components": [
		{"containerImage": "ignored.io/ignore@sha256:cba"},
		{"containerImage": "ignored.dev/ignore:ignore@sha256:dcb"},
	]}

	expected := {
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"docker.io/library/registry:latest@sha256:bcd\" is from a disallowed registry",
			"term": "docker.io/library/registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.io/ubi7:latest@sha256:abc\" is from a disallowed registry",
			"term": "registry.redhat.io/ubi7",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.blah/ubi7/3@sha256:ccc\" is from a disallowed registry",
			"term": "registry.redhat.blah/ubi7/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.whatever/ubi7/3@sha256:ccc\" is from a disallowed registry",
			"term": "registry.redhat.whatever/ubi7/3",
		},
	}

	lib.assert_equal_results(base_image_registries.deny, expected) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as bad_spdx_sbom
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
		with lib.sbom.spdx_sboms as []
}

test_base_image_not_found if {
	expected := {{
		"code": "base_image_registries.base_image_info_found",
		"msg": "Base images information is missing",
	}}
	lib.assert_equal_results(base_image_registries.deny, expected)
}

test_base_image_not_found_image_index if {
	att := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{"results": [
			{
				"name": "IMAGES",
				"type": "string",
				"value": "registry.local/spam@sha256:abc, registry.local/bacon@sha256:bcd",
			},
			{
				"name": "IMAGE_URL",
				"type": "string",
				"value": "registry.local/eggs:latest",
			},
			{
				"name": "IMAGE_DIGEST",
				"type": "string",
				"value": "sha256:fff",
			},
		]}]},
	}}}

	lib.assert_empty(base_image_registries.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/ham@sha256:fff"

	expected := {{
		"code": "base_image_registries.base_image_info_found",
		"msg": "Base images information is missing",
	}}
	lib.assert_equal_results(base_image_registries.deny, expected) with input.attestations as [att]
		with input.image.ref as "registry.local/ham@sha256:aaa"
}

test_allowed_registries_provided if {
	expected := {{
		"code": "base_image_registries.allowed_registries_provided",
		"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
		"severity": "failure",
	}}
	lib.assert_equal_results(expected, base_image_registries.deny) with data.rule_data as {}
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
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
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as d
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

_spdx_sbom := [{"packages": [
	{
		# regal ignore:line-length
		"SPDXID": "SPDXRef-image-registry.redhat.io/single-container-app-9520a72cbb69edfca5cac88ea2a9e0e09142ec934952b9420d686e77765f002c",
		"name": "registry.redhat.io/single-container-app:latest@sha256:abc",
		"downloadLocation": "NOASSERTION",
		"externalRefs": [{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceType": "purl",
			# regal ignore:line-length
			"referenceLocator": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app",
		}],
		"annotations": [{
			"annotator": "Tool: konflux:jsonencoded",
			"comment": "{\"name\":\"konflux:container:is_base_image\",\"value\":\"true\"}",
			"annotationDate": "2024-12-09T12:00:00Z",
			"annotationType": "OTHER",
		}],
	},
	{
		# regal ignore:line-length
		"SPDXID": "SPDXRef-image-docker.io/single-container-app-9520a72cbb69edfca5cac88ea2a9e0e09142ec934952b9420d686e77765f002c",
		"name": "docker.io/single-container-app:latest@sha256:bcd",
		"downloadLocation": "NOASSERTION",
		"externalRefs": [{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceType": "purl",
			# regal ignore:line-length
			"referenceLocator": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app",
		}],
		"annotations": [{
			"annotator": "Tool: konflux:jsonencoded",
			"comment": "{\"name\":\"konflux:container:is_builder_image:for_stage\",\"value\":\"0\"}",
			"annotationDate": "2024-12-09T12:00:00Z",
			"annotationType": "OTHER",
		}],
	},
]}]
