#
# METADATA
# title: SPDX SBOM
# description: >-
#   Checks different properties of the CycloneDX SBOMs associated with the image being validated.
#   The SBOMs are read from multiple locations: a file within the image, and a CycloneDX SBOM
#   attestation.
package sbom_spdx

import rego.v1

import data.lib
import data.lib.image
import data.lib.sbom

# METADATA
# title: Valid
# description: >-
#   Check the SPDX SBOM has the expected format. It verifies the SPDX SBOM matches the 2.3
#   version of the schema.
# custom:
#   short_name: valid
#   failure_msg: 'SPDX SBOM at index %d is not valid: %s'
#   solution: Make sure the build process produces a valid SPDX SBOM.
#   collections:
#   - minimal
#   - redhat
#
deny contains result if {
	some index, s in sbom.spdx_sboms
	some violation in json.match_schema(s, schema_2_3)[1]
	error := violation.error
	result := lib.result_helper(rego.metadata.chain(), [index, error])
}

# METADATA
# title: Contains packages
# description: Check the list of packages in the SPDX SBOM is not empty.
# custom:
#   short_name: contains_packages
#   failure_msg: The list of packages is empty
#   solution: >-
#     Verify the SBOM is correctly identifying the package in the image.
#
deny contains result if {
	some s in sbom.spdx_sboms
	count(s.packages) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Allowed
# description: >-
#   Confirm the SPDX SBOM contains only allowed packages. By default all packages are allowed.
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
	some s in sbom.spdx_sboms
	some pkg in s.packages
	some ref in pkg.externalRefs
	ref.referenceType == "purl"
	sbom.has_item(ref.referenceLocator, lib.rule_data(sbom.rule_data_packages_key))
	result := lib.result_helper(rego.metadata.chain(), [ref.referenceLocator])
}

# METADATA
# title: Allowed package external references
# description: >-
#   Confirm the SPDX SBOM contains only packages with explicitly allowed
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
	some s in sbom.spdx_sboms
	some pkg in s.packages
	some reference in pkg.externalRefs
	some allowed in lib.rule_data(sbom.rule_data_allowed_external_references_key)
	reference.referenceType == allowed.type
	not regex.match(object.get(allowed, "url", ""), object.get(reference, "referenceLocator", ""))

	msg := regex.replace(object.get(allowed, "url", ""), `(.+)`, ` by pattern "$1"`)

	# regal ignore:line-length
	result := lib.result_helper(rego.metadata.chain(), [pkg.name, reference.referenceLocator, reference.referenceType, msg])
}

# METADATA
# title: Disallowed package external references
# description: >-
#   Confirm the SPDX SBOM contains only packages without disallowed
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
	some s in sbom.spdx_sboms
	some pkg in s.packages
	some reference in pkg.externalRefs
	some disallowed in lib.rule_data(sbom.rule_data_disallowed_external_references_key)

	reference.referenceType == disallowed.type
	regex.match(object.get(disallowed, "url", ""), object.get(reference, "referenceLocator", ""))

	msg := regex.replace(object.get(disallowed, "url", ""), `(.+)`, ` by pattern "$1"`)

	# regal ignore:line-length
	result := lib.result_helper(rego.metadata.chain(), [pkg.name, reference.referenceLocator, reference.referenceType, msg])
}

# METADATA
# title: Contains files
# description: Check the list of files in the SPDX SBOM is not empty.
# custom:
#   short_name: contains_files
#   failure_msg: The list of files is empty
#   solution: >-
#     Verify the SBOM is correctly identifying the files in the image.
#
deny contains result if {
	some s in sbom.spdx_sboms
	count(s.files) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Matches image
# description: Check the SPDX SBOM targets the image being validated.
# custom:
#   short_name: matches_image
#   failure_msg: Image digest in the SBOM, %q, is not as expected, %q
#   solution: >-
#     The SPDX SBOM associated with the image describes a different image.
#     Verify the integrity of the build system.
#
deny contains result if {
	some s in sbom.spdx_sboms
	sbom_image := image.parse(s.name)
	expected_image := image.parse(input.image.ref)
	sbom_image.digest != expected_image.digest
	result := lib.result_helper(rego.metadata.chain(), [sbom_image.digest, expected_image.digest])
}
