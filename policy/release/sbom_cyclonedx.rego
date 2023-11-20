#
# METADATA
# description: >-
#   Checks different properties of the CycloneDX SBOMs associated with the image being validated.
#   The SBOMs are read from multiple locations: a file within the image, and a CycloneDX SBOM
#   attestation.
#
package policy.release.sbom_cyclonedx

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Found
# description: Confirm a CycloneDX SBOM exists.
# custom:
#   short_name: found
#   failure_msg: No CycloneDX SBOM found
#   solution: >-
#     Make sure the build process produces a CycloneDX SBOM.
#
deny contains result if {
	count(_sboms) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Valid
# description: Check the CycloneDX SBOM has the expected format.
# custom:
#   short_name: valid
#   failure_msg: CycloneDX SBOM at index %d is not valid
#   solution: Make sure the build process produces a valid CycloneDX SBOM.
#
deny contains result if {
	some index, sbom in _sboms
	not _is_valid(sbom)
	result := lib.result_helper(rego.metadata.chain(), [index])
}

# METADATA
# title: Contains components
# description: Check the list of components in the CycloneDX SBOM is not empty.
# custom:
#   short_name: contains_components
#   failure_msg: The list of components is empty
#   solution: >-
#     Verify the SBOM is correctly identifying the components in the image.
#
deny contains result if {
	some sbom in _sboms
	count(sbom.components) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

_sboms := array.concat(_sboms_from_image, _sboms_from_attestations)

_sboms_from_image := [sbom |
	some path in ["root/buildinfo/content_manifests/sbom-cyclonedx.json"]
	sbom := input.image.files[path]
]

_sboms_from_attestations := [sbom |
	some att in input.attestations
	statement := att.statement

	# https://cyclonedx.org/specification/overview/#recognized-predicate-type
	statement.predicateType == "https://cyclonedx.org/bom"
	sbom := statement.predicate
]

# _is_valid is true if the given CycloneDX SBOM has certain fields. This is not an exhaustive schema
# check. It mostly ensures the fields used by the policy rules in this package have been set.
_is_valid(sbom) if {
	is_array(sbom.components)
}
