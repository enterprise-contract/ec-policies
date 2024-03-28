package lib.sbom_oci_test

import rego.v1

import data.lib
import data.lib.sbom

test_fetch_sbom_from_oci_blob if {
	sbom_ref := sprintf("%s%s", [
		"quay.io/redhat-user-workloads-stage/zregvart-tenant/",
		"golden-container/golden-container@sha256:c8aefe2e6a76aaf6569ea7aec4d2e0d2c7e38ea1ee2549ee18be30941bf43ad4",
	])
	lib.assert_equal(count(sbom.cyclonedx_sboms), 2) with input as {
		"image": {"files": {"root/buildinfo/content_manifests/sbom-cyclonedx.json": "from_file"}},
		"attestations": [{"statement": {"predicate": {
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
					"value": "registry.io/repository/image@sha256:f0cacc1a",
				},
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": sbom_ref,
				},
			]}]},
		}}}],
	}
}
