package lib.sbom_test

import future.keywords.if
import future.keywords.in

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
	]
	image := {"files": {
		"root/buildinfo/content_manifests/sbom-cyclonedx.json": "sbom from image",
		"root/foo": "not an sbom",
	}}
	expected := ["sbom from image", "sbom from attestation"]
	lib.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as attestations
		with input.image as image
}
