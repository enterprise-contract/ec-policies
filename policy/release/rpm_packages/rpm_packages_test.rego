package policy.release.rpm_packages_test

import rego.v1

import data.lib
import data.lib.tekton_test
import data.lib_test
import data.policy.release.rpm_packages

test_success_cyclonedx if {
	att := _attestation_with_sboms([_cyclonedx_url_1, _cyclonedx_url_1])

	lib.assert_empty(rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_success_spdx if {
	att := _attestation_with_sboms([_spdx_url_1, _spdx_url_1])

	lib.assert_empty(rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_failure_cyclonedx if {
	att := _attestation_with_sboms([_cyclonedx_url_1, _cyclonedx_url_2])

	expected := {{
		"code": "policy.release.rpm_packages.unique_version",
		"msg": "Multiple versions of the \"spam\" RPM were found: 1.0.0-1, 1.0.0-2",
		"term": "spam",
	}}

	lib.assert_equal_results(expected, rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_failure_spdx if {
	att := _attestation_with_sboms([_spdx_url_1, _spdx_url_2])

	expected := {{
		"code": "policy.release.rpm_packages.unique_version",
		"msg": "Multiple versions of the \"spam\" RPM were found: 1.0.0-1, 1.0.0-2",
		"term": "spam",
	}}

	lib.assert_equal_results(expected, rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image-index-digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_non_image_index if {
	att := _attestation_with_sboms([_spdx_url_1, _spdx_url_2])

	lib.assert_empty(rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-manifest@sha256:image-manifest-digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_ignore_names if {
	att := _attestation_with_sboms([_spdx_url_1, _spdx_url_2])

	lib.assert_empty(rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image-index-digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
		with data.rule_data.non_unique_rpm_names as ["spam"]
}

_mock_blob(`"registry.local/cyclonedx-1@sha256:cyclonedx-1-digest"`) := json.marshal({"components": [
	{"purl": "pkg:rpm/redhat/spam@1.0.0-1"},
	{"purl": "pkg:rpm/redhat/bacon@1.0.0-2"},
	{"purl": "pkg:rpm/redhat/ham@4.2.0-0"},
]})

_mock_blob(`"registry.local/cyclonedx-2@sha256:cyclonedx-2-digest"`) := json.marshal({"components": [
	{"purl": "pkg:rpm/redhat/spam@1.0.0-2"},
	{"purl": "pkg:rpm/redhat/bacon@1.0.0-2"},
	{"purl": "pkg:rpm/redhat/eggs@4.2.0-0"},
]})

_mock_blob(`"registry.local/spdx-1@sha256:spdx-1-digest"`) := json.marshal({"packages": [
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-1",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceLocator": "pkg:rpm/redhat/bacon@1.0.0-2",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceLocator": "pkg:rpm/redhat/ham@4.2.0-0",
	}]},
]})

_mock_blob(`"registry.local/spdx-2@sha256:spdx-2-digest"`) := json.marshal({"packages": [
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-2",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceLocator": "pkg:rpm/redhat/bacon@1.0.0-2",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceLocator": "pkg:rpm/redhat/eggs@4.2.0-0",
	}]},
]})

_cyclonedx_url_1 := "registry.local/cyclonedx-1@sha256:cyclonedx-1-digest"

_cyclonedx_url_2 := "registry.local/cyclonedx-2@sha256:cyclonedx-2-digest"

_spdx_url_1 := "registry.local/spdx-1@sha256:spdx-1-digest"

_spdx_url_2 := "registry.local/spdx-2@sha256:spdx-2-digest"

_attestation_with_sboms(sbom_urls) := attestation if {
	tasks := [task |
		some i, url in sbom_urls
		task_with_result := tekton_test.slsav1_task_result_ref(
			sprintf("some-build-%d", [i]),
			[
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": url,
				},
				{
					"name": "IMAGES",
					"type": "string",
					"value": "registry.local/image@sha256:abc",
				},
			],
		)
		task := tekton_test.slsav1_task_bundle(task_with_result, _bundle)
	]

	attestation := lib_test.mock_slsav1_attestation_with_tasks(tasks)
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
