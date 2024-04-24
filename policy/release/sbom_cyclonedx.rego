#
# METADATA
# title: SBOM CycloneDX
# description: >-
#   Checks different properties of the CycloneDX SBOMs associated with the image being validated.
#   The SBOMs are read from multiple locations: a file within the image, and a CycloneDX SBOM
#   attestation.
#
package policy.release.sbom_cyclonedx

import rego.v1

import data.lib
import data.lib.sbom

# METADATA
# title: Found
# description: Confirm a CycloneDX SBOM exists.
# custom:
#   short_name: found
#   failure_msg: No CycloneDX SBOM found
#   solution: >-
#     Make sure the build process produces a CycloneDX SBOM.
#   collections:
#   - minimal
#   - redhat
#
deny contains result if {
	count(sbom.cyclonedx_sboms) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Valid
# description: >-
#   Check the CycloneDX SBOM has the expected format. It verifies the CycloneDX SBOM matches the 1.5
#   version of the schema.
# custom:
#   short_name: valid
#   failure_msg: 'CycloneDX SBOM at index %d is not valid: %s'
#   solution: Make sure the build process produces a valid CycloneDX SBOM.
#   collections:
#   - minimal
#   - redhat
#
deny contains result if {
	some index, s in sbom.cyclonedx_sboms
	some violation in json.match_schema(s, schema_1_5)[1]
	error := violation.error
	result := lib.result_helper(rego.metadata.chain(), [index, error])
}

# METADATA
# title: Contains components
# description: Check the list of components in the CycloneDX SBOM is not empty.
# custom:
#   short_name: contains_components
#   failure_msg: The list of components is empty
#   solution: >-
#     Verify the SBOM is correctly identifying the components in the image.
#   collections:
#   - minimal
#   - redhat
#
deny contains result if {
	some s in sbom.cyclonedx_sboms
	count(object.get(s, "components", [])) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Allowed
# description: >-
#   Confirm the CycloneDX SBOM contains only allowed packages. By default all packages are allowed.
#   Use the "disallowed_packages" rule data key to provide a list of disallowed packages.
# custom:
#   short_name: allowed
#   failure_msg: "Package is not allowed: %s"
#   solution: >-
#     Update the image to not use a disallowed package.
#   collections:
#   - redhat
#
deny contains result if {
	some s in sbom.cyclonedx_sboms
	some component in s.components
	_contains(component.purl, lib.rule_data(_rule_data_key))
	result := lib.result_helper(rego.metadata.chain(), [component.purl])
}

# METADATA
# title: Disallowed packages list is provided
# description: >-
#   Confirm the `disallowed_packages` rule data was provided, since it is required by the policy
#   rules in this package.
# custom:
#   short_name: disallowed_packages_provided
#   failure_msg: "%s"
#   solution: Provide a list of disallowed packages in the expected format.
#   collections:
#   - redhat
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

_contains(needle, haystack) if {
	needle_purl := ec.purl.parse(needle)

	some hay in haystack
	hay_purl := ec.purl.parse(hay.purl)

	needle_purl.type == hay_purl.type
	needle_purl.namespace == hay_purl.namespace
	needle_purl.name == hay_purl.name
	_matches_version(needle_purl.version, hay)
} else := false

_matches_version(version, matcher) if {
	matcher.format in {"semverv", "semver"}
	matcher.min != ""
	matcher.max != ""
	semver.compare(_to_semver(version), _to_semver(matcher.min)) != -1
	semver.compare(_to_semver(version), _to_semver(matcher.max)) != 1
} else if {
	matcher.format in {"semverv", "semver"}
	matcher.min != ""
	object.get(matcher, "max", "") == ""
	semver.compare(_to_semver(version), _to_semver(matcher.min)) != -1
} else if {
	matcher.format in {"semverv", "semver"}
	matcher.max != ""
	object.get(matcher, "min", "") == ""
	semver.compare(_to_semver(version), _to_semver(matcher.max)) != 1
} else := false

_to_semver(v) := trim_prefix(v, "v")

# Verify disallowed_packages is an array of objects
_rule_data_errors contains msg if {
	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(_rule_data_key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"uniqueItems": true,
			"items": {
				"type": "object",
				"properties": {
					"purl": {"type": "string"},
					"format": {"enum": ["semver", "semverv"]},
					"min": {"type": "string"},
					"max": {"type": "string"},
				},
				"additionalProperties": false,
				"anyOf": [
					{"required": ["purl", "format", "min"]},
					{"required": ["purl", "format", "max"]},
				],
			},
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, violation.error])
}

# Verify each item in disallowed_packages has a parseable PURL
_rule_data_errors contains msg if {
	some index, pkg in lib.rule_data(_rule_data_key)
	purl := pkg.purl
	not ec.purl.is_valid(purl)
	msg := sprintf("Item at index %d in %s does not have a valid PURL: %q", [index, _rule_data_key, purl])
}

# Verify each item in disallowed_packages has a parseable min/max semver
_rule_data_errors contains msg if {
	some index, pkg in lib.rule_data(_rule_data_key)
	pkg.format in {"semver", "semverv"}
	some attr in ["min", "max"]

	version := _to_semver(object.get(pkg, attr, ""))
	version != ""

	not semver.is_valid(version)

	msg := sprintf(
		"Item at index %d in %s does not have a valid %s semver value: %q",
		[index, _rule_data_key, attr, version],
	)
}

_rule_data_key := "disallowed_packages"
