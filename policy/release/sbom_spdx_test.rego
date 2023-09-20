package policy.release.sbom_spdx_test

import future.keywords.if
import future.keywords.in

import data.lib
import data.policy.release.sbom_spdx

test_all_good if {
	lib.assert_empty(sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_all_good_marshaled if {
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate",
		"value": json.marshal(_sbom_attestation.statement.predicate),
	}])
	lib.assert_empty(sbom_spdx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_not_found if {
	expected := {{"code": "sbom_spdx.found", "msg": "No SPDX SBOM attestations found"}}
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as []
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_not_valid if {
	attestations := [
		# bad name
		json.patch(_sbom_attestation, [{
			"op": "add",
			"path": "/statement/predicate/name",
			"value": "spam",
		}]),
		# missing name
		json.remove(_sbom_attestation, ["/statement/predicate/name"]),
		# bad packages
		json.patch(_sbom_attestation, [{
			"op": "add",
			"path": "/statement/predicate/packages",
			"value": "spam",
		}]),
		# missing packages
		json.remove(_sbom_attestation, ["/statement/predicate/packages"]),
		# bad files
		json.patch(_sbom_attestation, [{
			"op": "add",
			"path": "/statement/predicate/files",
			"value": "spam",
		}]),
		# missing files
		json.remove(_sbom_attestation, ["/statement/predicate/files"]),
	]

	expected := {violation |
		some i in numbers.range(0, count(attestations) - 1)
		violation := {
			"code": "sbom_spdx.valid",
			"msg": sprintf("SPDX SBOM at index %d is not valid", [i]),
		}
	}

	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as attestations
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_missing_packages if {
	expected := {{"code": "sbom_spdx.contains_packages", "msg": "The list of packages is empty"}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/packages",
		"value": [],
	}])
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_missing_files if {
	expected := {{"code": "sbom_spdx.contains_files", "msg": "The list of files is empty"}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/files",
		"value": [],
	}])
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_digest_mismatch if {
	expected := {{
		"code": "sbom_spdx.matches_image",
		"msg": "Image digest in the SBOM, \"sha256:123\", is not as expected, \"sha256:abc\"",
	}}
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:abc"
}

_sbom_attestation := {"statement": {
	"predicateType": "https://spdx.dev/Document",
	"predicate": {
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "registry.local/bacon@sha256:123",
		"packages": [{"name": "spam"}],
		"files": [{
			"fileName": "/usr/bin/spam",
			"SPDXID": "SPDXRef-File-usr-bin-spam-0e18b4ee77321ba5",
		}],
	},
}}
