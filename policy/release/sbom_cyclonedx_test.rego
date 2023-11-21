package policy.release.sbom_cyclonedx_test

import future.keywords.if
import future.keywords.in

import data.lib
import data.policy.release.sbom_cyclonedx

test_all_good_from_attestation if {
	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_all_good_from_image if {
	files := {"root/buildinfo/content_manifests/sbom-cyclonedx.json": _sbom_attestation.statement.predicate}
	lib.assert_empty(sbom_cyclonedx.deny) with input.image.files as files
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_not_found if {
	expected := {{"code": "sbom_cyclonedx.found", "msg": "No CycloneDX SBOM found"}}
	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as []
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_not_valid if {
	expected := {{
		"code": "sbom_cyclonedx.valid",
		"msg": "CycloneDX SBOM at index 0 is not valid: components: Invalid type. Expected: array, given: string",
	}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/components",
		"value": "spam",
	}])
	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_empty_components if {
	expected := {{
		"code": "sbom_cyclonedx.contains_components",
		"msg": "The list of components is empty",
	}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/components",
		"value": [],
	}])
	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_missing_components if {
	expected := {{
		"code": "sbom_cyclonedx.contains_components",
		"msg": "The list of components is empty",
	}}
	att := json.remove(_sbom_attestation, ["/statement/predicate/components"])
	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

_sbom_attestation := {"statement": {
	"predicateType": "https://cyclonedx.org/bom",
	"predicate": {
		"$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"serialNumber": "urn:uuid:cf1a2c3d-bcf8-45c4-9d0f-b2b59a0753f0",
		"version": 1,
		"metadata": {
			"timestamp": "2023-11-20T17:32:41Z",
			"tools": [{
				"vendor": "anchore",
				"name": "syft",
				"version": "0.96.0",
			}],
			"component": {
				"bom-ref": "158c8a990fbd4038",
				"type": "file",
				"name": "/var/lib/containers/storage/vfs/dir/dfd74fe178f4ea0472b5569bff38a4df69d05e7a81b538c98d731566aec15a69",
			},
		},
		"components": [{
			# regal ignore:line-length
			"bom-ref": "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3&package-id=f4f4e3cc2a6d9c37",
			"type": "library",
			"publisher": "Red Hat, Inc.",
			"name": "coreutils-single",
			"version": "8.32-34.el9",
			"licenses": [{"license": {"name": "GPLv3+"}}],
			"cpe": "cpe:2.3:a:coreutils-single:coreutils-single:8.32-34.el9:*:*:*:*:*:*:*",
			# regal ignore:line-length
			"purl": "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3",
		}],
	},
}}
