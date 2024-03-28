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
	image := {"files": {
		"root/buildinfo/content_manifests/sbom-cyclonedx.json": "sbom from image",
		"root/foo": "not an sbom",
	}}
	expected := ["sbom from image", "sbom from attestation", {"sbom": "from oci blob"}]
	lib.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as attestations
		with input.image as image
		with ec.oci.blob as mock_ec_oci_blob
}

mock_ec_oci_blob("registry.io/repository/image@sha256:f0cacc1a") := `{"sbom": "from oci blob"}`
