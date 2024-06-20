package policy.release.sbom_cyclonedx_test

import rego.v1

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

test_attributes_not_allowed_all_good if {
	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"

	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom_cyclonedx._rule_data_attributes_key: [{"name": "attrX", "value": "valueX"}]}
}

test_attributes_not_allowed_pair if {
	expected := {{
		"code": "sbom_cyclonedx.disallowed_package_attributes",
		# regal ignore:line-length
		"msg": `Package pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3 has the attribute "attr1" set`,
	}}

	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom_cyclonedx._rule_data_attributes_key: [{"name": "attr1"}]}
}

test_attributes_not_allowed_value if {
	expected := {{
		"code": "sbom_cyclonedx.disallowed_package_attributes",
		# regal ignore:line-length
		"msg": `Package pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3 has the attribute "attr2" set to "value2"`,
	}}

	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom_cyclonedx._rule_data_attributes_key: [{"name": "attr2", "value": "value2"}]}
}

test_attributes_not_allowed_no_properties if {
	att := json.patch(_sbom_attestation, [{
		"op": "remove",
		"path": "/statement/predicate/components/0/properties",
	}])

	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom_cyclonedx._rule_data_attributes_key: [{"name": "attr", "value": "value"}]}
}

test_allowed_by_default if {
	assert_allowed("pkg:golang/k8s.io/client-go@v0.28.3", [])
}

test_not_allowed_with_min if {
	disallowed_packages := [{
		"purl": "pkg:golang/k8s.io/client-go",
		"format": "semverv",
		"min": "v50.28.3",
	}]

	# Much lower than min version
	assert_allowed("pkg:golang/k8s.io/client-go@v0.29.4", disallowed_packages)

	# Lower than min version
	assert_allowed("pkg:golang/k8s.io/client-go@v50.28.2", disallowed_packages)

	# Exact match to min version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.28.3", disallowed_packages)

	# Higher than min version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.28.4", disallowed_packages)

	# Much higher than min version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v99.99.99", disallowed_packages)
}

test_not_allowed_with_max if {
	disallowed_packages := [{
		"purl": "pkg:golang/k8s.io/client-go",
		"format": "semverv",
		"max": "v50.28.3",
	}]

	# Much lower than max version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v0.29.4", disallowed_packages)

	# Lower than max version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.28.2", disallowed_packages)

	# Exact match to max version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.28.3", disallowed_packages)

	# Higher than max version
	assert_allowed("pkg:golang/k8s.io/client-go@v50.28.4", disallowed_packages)

	# Much higher than max version
	assert_allowed("pkg:golang/k8s.io/client-go@v99.99.99", disallowed_packages)
}

test_not_allowed_with_min_max if {
	disallowed_packages := [{
		"purl": "pkg:golang/k8s.io/client-go",
		"format": "semverv",
		"min": "v50.20.2",
		"max": "v50.28.3",
	}]

	# Much lower than min version
	assert_allowed("pkg:golang/k8s.io/client-go@v0.29.4", disallowed_packages)

	# Lower than min version
	assert_allowed("pkg:golang/k8s.io/client-go@v50.20.1", disallowed_packages)

	# Exact match to min version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.20.2", disallowed_packages)

	# Mid-range
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.24.9", disallowed_packages)

	# Exact match to max version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.28.3", disallowed_packages)

	# Higher than max version
	assert_allowed("pkg:golang/k8s.io/client-go@v50.28.4", disallowed_packages)

	# Much higher than max version
	assert_allowed("pkg:golang/k8s.io/client-go@v99.99.99", disallowed_packages)
}

assert_allowed(purl, disallowed_packages) if {
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/components/0/purl",
		"value": purl,
	}])

	# regal ignore:with-outside-test-context
	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [att]
		with data.rule_data.disallowed_packages as disallowed_packages
}

assert_not_allowed(purl, disallowed_packages) if {
	expected := {{
		"code": "sbom_cyclonedx.allowed",
		"msg": sprintf("Package is not allowed: %s", [purl]),
	}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/components/0/purl",
		"value": purl,
	}])

	# regal ignore:with-outside-test-context
	lib.assert_equal_results(sbom_cyclonedx.deny, expected) with input.attestations as [att]
		with data.rule_data.disallowed_packages as disallowed_packages
}

test_rule_data_validation if {
	d := {
		"disallowed_packages": [
			# Missing required attributes
			{},
			# Additional properties not allowed
			{"purl": "pkg:golang/k8s.io/client-go", "format": "semverv", "min": "v0.1.0", "blah": "foo"},
			# Bad types everywhere
			{"purl": 1, "format": 2, "min": 3, "max": 4},
			# Duplicated items
			{"purl": "pkg:golang/k8s.io/client-go", "format": "semverv", "min": "v0.1.0"},
			{"purl": "pkg:golang/k8s.io/client-go", "format": "semverv", "min": "v0.1.0"},
			# Bad semver values
			{"purl": "pkg:golang/k8s.io/client-go", "format": "semverv", "min": "v0.1"},
			{"purl": "pkg:golang/k8s.io/client-go", "format": "semver", "max": "v0.1"},
		],
		sbom_cyclonedx._rule_data_attributes_key: [
			# ok
			{"name": "some_attr", "value": "some_val"},
			{"name": "no_val_attr"},
			# Missing required attributes
			{},
			# Additional properties not allowed
			{"name": "_name_", "value": "_value_", "something": "else"},
			# Bad types everywhere
			{"name": 1, "value": 2},
			# Duplicated items
			{"name": "_name_", "value": "_value_"},
			{"name": "_name_", "value": "_value_"},
		],
	}

	expected := {
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: Must validate at least one schema (anyOf)",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: format is required",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: min is required",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: purl is required",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 1: Additional property blah is not allowed",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_packages has unexpected format: 2.format: 2.format must be one of the following: \"semver\", \"semverv\"",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 2.max: Invalid type. Expected: string, given: integer",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 2.min: Invalid type. Expected: string, given: integer",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 2.purl: Invalid type. Expected: string, given: integer",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Item at index 2 in disallowed_packages does not have a valid PURL: '\\x01'",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: (Root): array items[3,4] must be unique",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Item at index 5 in disallowed_packages does not have a valid min semver value: \"0.1\"",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Item at index 6 in disallowed_packages does not have a valid max semver value: \"0.1\"",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_attributes has unexpected format: 2: name is required",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_attributes has unexpected format: 3: Additional property something is not allowed",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_attributes has unexpected format: 4.name: Invalid type. Expected: string, given: integer",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_attributes has unexpected format: 4.value: Invalid type. Expected: string, given: integer",
		},
		{
			"code": "sbom_cyclonedx.disallowed_packages_provided",
			"msg": "Rule data disallowed_attributes has unexpected format: (Root): array items[5,6] must be unique",
		},
	}

	lib.assert_equal_results(sbom_cyclonedx.deny, expected) with input.attestations as [_sbom_attestation]
		with data.rule_data as d

	# rule data keys are optional
	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with data.rule_data as {}
	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with data.rule_data as {
			sbom_cyclonedx._rule_data_packages_key: [],
			sbom_cyclonedx._rule_data_attributes_key: [],
		}
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
			"properties": [
				{"name": "attr1"},
				{
					"name": "attr2",
					"value": "value2",
				},
			],
		}],
	},
}}
