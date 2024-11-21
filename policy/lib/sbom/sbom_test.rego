package lib.sbom_test

import rego.v1

import data.lib
import data.lib.sbom

test_all_sboms if {
	expected := ["hurricane", "tornado", "spandex", "latex"]
	lib.assert_equal(sbom.all_sboms, expected) with sbom.cyclonedx_sboms as ["hurricane", "tornado"]
		with sbom.spdx_sboms as ["spandex", "latex"]
}

# test from attestation and fallback to oci image
test_cyclonedx_sboms if {
	attestations := [
		{"statement": {
			"predicateType": "https://cyclonedx.org/bom",
			"predicate": "sbom from attestation",
		}},
		{"statement": {
			"predicateType": "https://example.org/boom",
			"predicate": "not an sbom",
		}},
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{"results": [
				{
					"name": "IMAGE_DIGEST",
					"type": "string",
					"value": "sha256:284e3029",
				},
				{
					"name": "IMAGE_URL",
					"type": "string",
					"value": "registry.io/repository/image:latest",
				},
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": "registry.io/repository/image@sha256:f0cacc1a",
				},
			]}]},
		}}},
	]
	expected := ["sbom from attestation", {"sbom": "from oci blob", "bomFormat": "CycloneDX"}]
	lib.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as attestations
		with input.image as _cyclonedx_image
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
}

# test from attestation and fallback to oci image
test_spdx_sboms if {
	attestations := [
		{"statement": {
			"predicateType": "https://spdx.dev/Document",
			"predicate": "sbom from attestation",
		}},
		{"statement": {
			"predicateType": "https://example.org/boom",
			"predicate": "not an sbom",
		}},
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{"results": [
				{
					"name": "IMAGE_DIGEST",
					"type": "string",
					"value": "sha256:284e3029",
				},
				{
					"name": "IMAGE_URL",
					"type": "string",
					"value": "registry.io/repository/image:latest",
				},
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": "registry.io/repository/image@sha256:f0cacc1a",
				},
			]}]},
		}}},
	]
	expected := ["sbom from attestation", {"sbom": "from oci blob", "SPDXID": "SPDXRef-DOCUMENT"}]
	lib.assert_equal(sbom.spdx_sboms, expected) with input.attestations as attestations
		with input.image as _spdx_image
		with ec.oci.blob as mock_ec_oci_spdx_blob
}

test_ignore_unrelated_sboms if {
	attestations := [
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{"results": [
				{
					"name": "IMAGE_DIGEST",
					"type": "string",
					"value": "sha256:0000000",
				},
				{
					"name": "IMAGE_URL",
					"type": "string",
					"value": "registry.io/repository/image:latest",
				},
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": "registry.io/repository/image@sha256:f0cacc1a",
				},
			]}]},
		}}},
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{"results": [
				{
					"name": "IMAGE_DIGEST",
					"type": "string",
					"value": "sha256:1111111",
				},
				{
					"name": "IMAGE_URL",
					"type": "string",
					"value": "registry.io/repository/image:latest",
				},
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": "registry.io/repository/image@sha256:f0cacc1b",
				},
			]}]},
		}}},
	]

	lib.assert_equal(sbom.all_sboms, []) with input.attestations as attestations
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}
		with ec.oci.blob as ""
}

mock_ec_oci_cyclonedx_blob := `{"sbom": "from oci blob", "bomFormat": "CycloneDX"}`

mock_ec_oci_spdx_blob := `{"sbom": "from oci blob", "SPDXID": "SPDXRef-DOCUMENT"}`

_cyclonedx_image := {
	"ref": "registry.io/repository/image@sha256:284e3029",
	"config": {"Labels": {"vendor": "Red Hat, Inc."}},
}

_spdx_image := {
	"ref": "registry.io/repository/image@sha256:284e3029",
	"config": {"Labels": {"vendor": "Red Hat, Inc."}},
}
