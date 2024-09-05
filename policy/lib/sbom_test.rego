package lib.sbom_test

import rego.v1

import data.lib
import data.lib.sbom

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
					"value": "sha256:f0cacc1a",
				},
				{
					"name": "IMAGE_URL",
					"type": "string",
					"value": "registry.io/repository/image@sha256:baadf00d",
				},
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": "registry.io/repository/image@sha256:f0cacc1a",
				},
			]}]},
		}}},
	]
	expected := ["sbom from attestation", {"sbom": "from oci blob"}]
	lib.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as attestations
		with input.image as _image
		with ec.oci.blob as mock_ec_oci_blob
}

test_cyclonedx_sboms_fallback_prefetched if {
	attestations := [{"statement": {
		"predicateType": "https://example.org/boom",
		"predicate": "not an sbom",
	}}]
	expected := ["sbom from image"]
	lib.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as attestations
		with input.image as _image
		with ec.oci.blob as mock_ec_oci_blob
}

test_cyclonedx_sboms_fallback_live_fetch if {
	image := json.remove(_image, ["files"])
	expected := [{"sbom": "from live image"}]
	lib.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as []
		with input.image as image
		with ec.oci.blob as mock_ec_oci_blob
		with ec.oci.image_files as mock_ec_oci_image_files
}

mock_ec_oci_blob("registry.io/repository/image@sha256:f0cacc1a") := `{"sbom": "from oci blob"}`

mock_ec_oci_image_files(
	"registry.io/repository/image@sha256:284e3029",
	["root/buildinfo/content_manifests/sbom-cyclonedx.json"],
) := {sbom._sbom_image_path: {"sbom": "from live image"}}

_image := {
	"ref": "registry.io/repository/image@sha256:284e3029",
	"files": {
		"root/buildinfo/content_manifests/sbom-cyclonedx.json": "sbom from image",
		"root/foo": "not an sbom",
	},
	"config": {"Labels": {"vendor": "Red Hat, Inc."}},
}
