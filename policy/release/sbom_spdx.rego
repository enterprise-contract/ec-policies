#
# METADATA
# description: >-
#   Checks different properties of the SPDX SBOM attestation.
#
package policy.release.sbom_spdx

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.image

# METADATA
# title: Found
# description: Confirm an SPDX SBOM attestation exists.
# custom:
#   short_name: found
#   failure_msg: No SPDX SBOM attestations found
#   solution: >-
#     Make sure the build process produces an SPDX SBOM attestation.
#
deny contains result if {
	count(_sboms) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Valid
# description: Check the SPDX SBOM has the expected format.
# custom:
#   short_name: valid
#   failure_msg: SPDX SBOM at index %d is not valid
#   solution: Make sure the build process produces a valid SPDX SBOM.
#
deny contains result if {
	some index, sbom in _sboms
	not _is_valid(sbom)

	# TODO: Consider adding an iteration index to the failuer message?
	result := lib.result_helper(rego.metadata.chain(), [index])
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
	some sbom in _sboms
	count(sbom.packages) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
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
	some sbom in _sboms
	count(sbom.files) == 0
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
	some sbom in _sboms
	sbom_image := image.parse(sbom.name)
	expected_image := image.parse(input.image.ref)
	sbom_image.digest != expected_image.digest
	result := lib.result_helper(rego.metadata.chain(), [sbom_image.digest, expected_image.digest])
}

_sboms := [sbom |
	some att in input.attestations
	att.statement.predicateType == "https://spdx.dev/Document"
	sbom := _predicate(att)
]

# _is_valid is true if the given SPDX SBOM has certain fields. This is
# not an exhaustive schema check. It mostly ensures the fields used
# by the policy rules in this package have been set.
_is_valid(sbom) if {
	sbom.name
	name_ref := image.parse(sbom.name)
	count(name_ref.digest) > 0
	is_array(sbom.files)
	is_array(sbom.packages)
}

# _predicate returns the predicate from the given attestation. If the
# predicate is JSON marshaled, it is unmarshaled.
_predicate(att) := predicate if {
	json.is_valid(att.statement.predicate)
	predicate := json.unmarshal(att.statement.predicate)
} else := att.statement.predicate
