package policy.beta.packages_test

import future.keywords.if
import future.keywords.in

import data.lib
import data.policy.beta.packages

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
	lib.assert_empty(packages.deny) with input.attestations as [att]
		with data.rule_data.disallowed_packages as disallowed_packages
}

assert_not_allowed(purl, disallowed_packages) if {
	expected := {{
		"code": "packages.allowed",
		"msg": sprintf("Package is not allowed: %s", [purl]),
	}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/components/0/purl",
		"value": purl,
	}])
	lib.assert_equal_results(packages.deny, expected) with input.attestations as [att]
		with data.rule_data.disallowed_packages as disallowed_packages
}

test_rule_data_validation if {
	d := {"disallowed_packages": [
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
	]}

	expected := {
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: Must validate at least one schema (anyOf)",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: format is required",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: min is required",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: purl is required",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 1: Additional property blah is not allowed",
		},
		{
			"code": "packages.disallowed_packages_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_packages has unexpected format: 2.format: 2.format must be one of the following: \"semver\", \"semverv\"",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 2.max: Invalid type. Expected: string, given: integer",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 2.min: Invalid type. Expected: string, given: integer",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 2.purl: Invalid type. Expected: string, given: integer",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Item at index 2 in disallowed_packages does not have a valid PURL: '\\x01'",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: (Root): array items[3,4] must be unique",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Item at index 5 in disallowed_packages does not have a valid min semver value: \"0.1\"",
		},
		{
			"code": "packages.disallowed_packages_provided",
			"msg": "Item at index 6 in disallowed_packages does not have a valid max semver value: \"0.1\"",
		},
	}

	lib.assert_equal_results(packages.deny, expected) with data.rule_data as d
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
