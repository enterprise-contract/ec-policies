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
	_contains(component.purl, lib.rule_data(_rule_data_packages_key))
	result := lib.result_helper(rego.metadata.chain(), [component.purl])
}

# METADATA
# title: Disallowed packages list is provided
# description: >-
#   Confirm the `disallowed_packages` and `disallowed_attributes` rule data were
#   provided, since they are required by the policy rules in this package.
# custom:
#   short_name: disallowed_packages_provided
#   failure_msg: "%s"
#   solution: >-
#     Provide a list of disallowed packages or package attributes in the
#     expected format.
#   collections:
#   - redhat
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

# METADATA
# title: Disallowed package attributes
# description: >-
#   Confirm the CycloneDX SBOM contains only packages without disallowed
#   attributes. By default all attributes are allowed. Use the
#   "disallowed_attributes" rule data key to provide a list of key-value pairs
#   that forbid the use of an attribute set to the given value.
# custom:
#   short_name: disallowed_package_attributes
#   failure_msg: Package %s has the attribute %q set%s
#   solution: Update the image to not use a disallowed package attributes.
#   collections:
#   - redhat
#   - policy_data
#   effective_on: 2024-07-31T00:00:00Z
deny contains result if {
	some s in sbom.cyclonedx_sboms
	some component in s.components
	some property in component.properties
	some disallowed in lib.rule_data(_rule_data_attributes_key)

	property.name == disallowed.name
	object.get(property, "value", "") == object.get(disallowed, "value", "")

	msg := regex.replace(object.get(property, "value", ""), `(.+)`, ` to "$1"`)

	id := object.get(component, "purl", component.name)
	result := _with_effective_on(
		lib.result_helper(rego.metadata.chain(), [id, property.name, msg]),
		disallowed,
	)
}

# METADATA
# title: Allowed package external references
# description: >-
#   Confirm the CycloneDX SBOM contains only packages with explicitly allowed
#   external references. By default all external references are allowed unless the
#   "allowed_external_references" rule data key provides a list of type-pattern pairs
#   that forbid the use of any other external reference of the given type where the
#   reference url matches the given pattern.
# custom:
#   short_name: allowed_package_external_references
#   failure_msg: Package %s has reference %q of type %q which is not explicitly allowed%s
#   solution: Update the image to use only packages with explicitly allowed external references.
#   collections:
#   - redhat
#   - policy_data
#
deny contains result if {
	some s in sbom.cyclonedx_sboms
	some component in s.components
	some reference in component.externalReferences
	some allowed in lib.rule_data(_rule_data_allowed_external_references_key)

	reference.type == allowed.type
	not regex.match(object.get(allowed, "url", ""), object.get(reference, "url", ""))

	msg := regex.replace(object.get(allowed, "url", ""), `(.+)`, ` by pattern "$1"`)

	id := object.get(component, "purl", component.name)
	result := lib.result_helper(rego.metadata.chain(), [id, reference.url, reference.type, msg])
}

# METADATA
# title: Disallowed package external references
# description: >-
#   Confirm the CycloneDX SBOM contains only packages without disallowed
#   external references. By default all external references are allowed. Use the
#   "disallowed_external_references" rule data key to provide a list of type-pattern pairs
#   that forbid the use of an external reference of the given type where the reference url
#   matches the given pattern.
# custom:
#   short_name: disallowed_package_external_references
#   failure_msg: Package %s has reference %q of type %q which is disallowed%s
#   solution: Update the image to not use a package with a disallowed external reference.
#   collections:
#   - redhat
#   - policy_data
#   effective_on: 2024-07-31T00:00:00Z
deny contains result if {
	some s in sbom.cyclonedx_sboms
	some component in s.components
	some reference in component.externalReferences
	some disallowed in lib.rule_data(_rule_data_disallowed_external_references_key)

	reference.type == disallowed.type
	regex.match(object.get(disallowed, "url", ""), object.get(reference, "url", ""))

	msg := regex.replace(object.get(disallowed, "url", ""), `(.+)`, ` by pattern "$1"`)

	id := object.get(component, "purl", component.name)
	result := lib.result_helper(rego.metadata.chain(), [id, reference.url, reference.type, msg])
}

_contains(needle, haystack) if {
	needle_purl := ec.purl.parse(needle)

	some hay in haystack
	hay_purl := ec.purl.parse(hay.purl)

	needle_purl.type == hay_purl.type
	needle_purl.namespace == hay_purl.namespace
	needle_purl.name == hay_purl.name
	_matches_version(needle_purl.version, hay)

	not _excluded(needle_purl, object.get(hay, "exceptions", []))
} else := false

_excluded(purl, exceptions) if {
	matches := [exception |
		some exception in exceptions
		exception.subpath == purl.subpath
	]
	count(matches) > 0
}

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
	value := json.marshal(lib.rule_data(_rule_data_packages_key))
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
					"exceptions": {
						"type": "array",
						"uniqueItems": true,
						"items": {
							"type": "object",
							"properties": {"subpath": {"type": "string"}},
						},
					},
				},
				"additionalProperties": false,
				"anyOf": [
					{"required": ["purl", "format", "min"]},
					{"required": ["purl", "format", "max"]},
				],
			},
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [_rule_data_packages_key, violation.error])
}

# Verify each item in disallowed_packages has a parseable PURL
_rule_data_errors contains msg if {
	some index, pkg in lib.rule_data(_rule_data_packages_key)
	purl := pkg.purl
	not ec.purl.is_valid(purl)
	msg := sprintf("Item at index %d in %s does not have a valid PURL: %q", [index, _rule_data_packages_key, purl])
}

# Verify each item in disallowed_packages has a parseable min/max semver
_rule_data_errors contains msg if {
	some index, pkg in lib.rule_data(_rule_data_packages_key)
	pkg.format in {"semver", "semverv"}
	some attr in ["min", "max"]

	version := _to_semver(object.get(pkg, attr, ""))
	version != ""

	not semver.is_valid(version)

	msg := sprintf(
		"Item at index %d in %s does not have a valid %s semver value: %q",
		[index, _rule_data_packages_key, attr, version],
	)
}

# Verify disallowed_attributes is an array of name value pairs
_rule_data_errors contains msg if {
	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(_rule_data_attributes_key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"uniqueItems": true,
			"items": {
				"type": "object",
				"properties": {
					"name": {"type": "string"},
					"value": {"type": "string"},
					"effective_on": {"type": "string", "format": "date-time"},
				},
				"additionalProperties": false,
				"required": ["name"],
			},
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [_rule_data_attributes_key, violation.error])
}

# Verify allowed_external_references is an array of type/url pairs
_rule_data_errors contains msg if {
	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(_rule_data_allowed_external_references_key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"uniqueItems": true,
			"items": {
				"type": "object",
				"properties": {
					"type": {"type": "string"},
					"url": {"type": "string"},
				},
				"additionalProperties": false,
				"required": ["type", "url"],
			},
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [_rule_data_allowed_external_references_key, violation.error])
}

# Verify disallowed_external_references is an array of type/url pairs
_rule_data_errors contains msg if {
	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(_rule_data_disallowed_external_references_key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"uniqueItems": true,
			"items": {
				"type": "object",
				"properties": {
					"type": {"type": "string"},
					"url": {"type": "string"},
				},
				"additionalProperties": false,
				"required": ["type", "url"],
			},
		},
	)[1]

	# regal ignore:line-length
	msg := sprintf("Rule data %s has unexpected format: %s", [_rule_data_disallowed_external_references_key, violation.error])
}

# _with_effective_on annotates the result with the item's effective_on attribute. If the item does
# not have the attribute, result is returned unmodified.
_with_effective_on(result, item) := new_result if {
	new_result := object.union(result, {"effective_on": item.effective_on})
} else := result

_rule_data_packages_key := "disallowed_packages"

_rule_data_attributes_key := "disallowed_attributes"

_rule_data_allowed_external_references_key := "allowed_external_references"

_rule_data_disallowed_external_references_key := "disallowed_external_references"
